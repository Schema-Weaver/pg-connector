import * as crypto from 'crypto';
import * as fs from 'fs';
import * as readline from 'readline';

import {
  AUDIT_FLOOR_SUFFIX,
  AUDIT_HEAD_FILENAME,
  ChainVerifier,
  GENESIS_HASH,
  loadAuditKey,
  makeHead,
  readHead,
  readHeadFloor,
  requireKeyBytes,
  resolveAnchor,
  type ChainVerifyResult,
} from './chain';
import { getAuditFilesChronological } from './files';
import type { AuditEvent, AuditHead } from './types';

/**
 * Incremental whole-log verification (audit finding M-06).
 *
 * `verifyAuditLog` already streams the log in O(1) memory and early-exits on the
 * first bad record, but it re-reads and re-verifies every rotated archive on
 * every call. This module adds the missing half: a per-file cache of the chain
 * head each file left behind, so a file that has not changed since a previous
 * successful verification is not read again, and the chain resumes from the
 * cached head of the last unchanged file.
 *
 * The record-level rules live in `chain.ts` (`ChainVerifier`) and are not
 * reimplemented here: this is a file-walk policy around the single
 * implementation, which is exactly the split that keeps the two from drifting.
 *
 * The cache is per process, in memory, and is never written next to the log. A
 * cache file in the audit directory would live wherever the log-writer can
 * reach, so a poisoned entry would turn "not re-verified" into "verified"; a
 * skip is therefore only ever a skip, and the result always says which files
 * were read and which were not.
 *
 * ## When a skipped file's verdict may be reused
 *
 * A cache hit is only allowed to stand in for a re-read when *all* of these
 * hold, and every one of them is checked on the path that uses the entry:
 *
 *  1. **The file is the same file.** `dev`/`ino`/`size` plus `mtime_ns` *and*
 *     `ctime_ns`. `size`+`mtime` alone was the original key and it is not
 *     enough: `utimensat` can put `mtime` back after a rewrite, so a same-size
 *     edit with a restored `mtime` reused a stale "intact" verdict and masked
 *     the tamper. `ctime` cannot be set from userspace, and the nanosecond
 *     fields come from a `bigint` stat, so a write that keeps the file's
 *     identity has to preserve all five values. A file whose timestamps the
 *     filesystem only records to the second is never cached at all: two writes
 *     inside one second cannot be told apart there, which is precisely the
 *     window such a tamper would aim for.
 *  2. **The chain state the file was verified from is the chain state we are
 *     resuming into.** The entry records the `seq` and `prev_hash` its *first*
 *     record had to chain from; a hit is refused unless those equal the
 *     verifier's current `expectedSeq`/`prev`. Without this, a modified earlier
 *     file followed by a cached later file would "verify": the cached head would
 *     paper over the gap instead of exposing it.
 *  3. **The signing key is the key the entry was verified with.** A fingerprint
 *     of the key bytes is part of every entry, so a rotated/replaced key file
 *     invalidates the whole cache even when no anchor names the chain.
 *  4. **The entry belongs to the chain the caller is verifying.** A constrained
 *     lookup never reuses an entry from another `chain_id`.
 *  5. **A reused tail is re-anchored to the bytes on disk.** When the last file
 *     walked came from the cache, the final record of the log is re-read (a
 *     bounded tail peek, never a whole file) and must still be the record the
 *     cache says was verified. Truncating the log and rewriting both anchors to
 *     match is otherwise invisible to a remembered verdict.
 *  6. **The anchors are read fresh on every call** and the cached end head is
 *     compared against them (`compareWithAnchor`), exactly as
 *     `ChainVerifier.result` compares the freshly observed head.
 *
 * Anything else fails closed: a file that cannot be stat'ed is reported as
 * unreadable *and* disables every later skip in the same run, a file that could
 * not be read to its end is never cached, and a run that skipped nothing still
 * has to produce a real verdict from the verifier.
 *
 * What this cannot do: it does not protect against an attacker who can write the
 * audit files *and* forge inode metadata (root/`CAP_FOWNER`) or land on a
 * filesystem with coarse timestamps. Such an attacker can also rewrite both
 * anchors, which the uncached verifier already cannot defend against. The
 * interactive `sw-agent audit verify` therefore never consults this cache at
 * all — see `src/cli/commands/audit-verify.ts`.
 */

/** Bytes read from the end of the newest non-empty file to re-anchor a skip. */
const TAIL_PEEK_BYTES = 64 * 1024;

/**
 * Stat identity of one log file.
 *
 * The timestamps are decimal nanoseconds (`bigint` stat) rather than millisecond
 * floats: a float cannot hold `1.7e18` ns without rounding, and the rounding
 * window is exactly where a "same second, same size" tamper would hide.
 */
export interface AuditFileIdentity {
  size: number;
  mtime_ns: string;
  ctime_ns: string;
  ino: string;
  dev: string;
}

/** Reads a file's identity, or null when it cannot be stat'ed. */
export async function statAuditFileIdentity(file: string): Promise<AuditFileIdentity | null> {
  try {
    const st = await fs.promises.stat(file, { bigint: true });
    return {
      size: Number(st.size),
      mtime_ns: st.mtimeNs.toString(),
      ctime_ns: st.ctimeNs.toString(),
      ino: st.ino.toString(),
      dev: st.dev.toString(),
    };
  } catch {
    return null;
  }
}

function sameIdentity(a: AuditFileIdentity, b: AuditFileIdentity): boolean {
  return (
    a.size === b.size &&
    a.mtime_ns === b.mtime_ns &&
    a.ctime_ns === b.ctime_ns &&
    a.ino === b.ino &&
    a.dev === b.dev
  );
}

const NS_PER_SECOND = 1_000_000_000n;

/**
 * True when both timestamps carry a sub-second component, i.e. the filesystem
 * that produced them records times finer than a second.
 */
function hasSubSecondResolution(identity: AuditFileIdentity): boolean {
  try {
    return (
      BigInt(identity.mtime_ns) % NS_PER_SECOND !== 0n &&
      BigInt(identity.ctime_ns) % NS_PER_SECOND !== 0n
    );
  } catch {
    return false;
  }
}

/** What a completed verification of one file leaves behind. */
export interface CachedAuditFile {
  /** The file's stat identity at verification time. */
  identity: AuditFileIdentity;
  /** Records in the file, and how many of them were not parseable. */
  records: number;
  malformed_lines: number;
  /** Sequence number the file's *first* record must carry. */
  first_seq: number;
  /** Hash the file's *first* record must chain from (genesis when it starts at 1). */
  first_prev_hash: string;
  /** Chain head after the last record of the file. */
  seq: number;
  last_hash: string;
  chain_id: string;
  /** Fingerprint of the signing key the entry was verified with. */
  key_fingerprint: string;
  verified_at: string;
}

/**
 * The chain state an entry may be reused for. An entry is only ever equivalent
 * to having read the file when it was verified from exactly this state.
 */
export interface CacheResumption {
  /** Chain the caller requires, or null when it is not constrained yet. */
  chainId: string | null;
  /** Sequence number the file's first record must carry. */
  seq: number;
  /** Hash the file's first record must chain from. */
  prevHash: string;
  /** Fingerprint of the signing key in use now. */
  keyFingerprint: string;
}

export class AuditVerifyCache {
  private readonly entries = new Map<string, CachedAuditFile>();

  /**
   * A usable entry for this exact file revision and this exact resumption point,
   * or null. Every field is load-bearing: see the trust model at the top of this
   * module.
   */
  get(file: string, identity: AuditFileIdentity, expect: CacheResumption): CachedAuditFile | null {
    const hit = this.entries.get(file);
    if (!hit) return null;
    if (hit.records <= 0) return null;
    if (!sameIdentity(hit.identity, identity)) return null;
    if (hit.key_fingerprint !== expect.keyFingerprint) return null;
    if (expect.chainId !== null && hit.chain_id !== expect.chainId) return null;
    if (hit.first_seq !== expect.seq) return null;
    if (hit.first_prev_hash !== expect.prevHash) return null;
    return hit;
  }

  set(file: string, entry: CachedAuditFile): void {
    // A file whose timestamps are stored at whole-second resolution cannot be
    // reused: two writes inside one second are indistinguishable there, which is
    // exactly the window a tamper aims for (same size, mtime put back). Losing
    // the skip is the cheap outcome; trusting it would not be.
    if (entry.records <= 0) return;
    if (!hasSubSecondResolution(entry.identity)) return;
    this.entries.set(file, entry);
  }

  /**
   * Copy of the stored entries. Read-only: nothing can be invalidated through
   * it, so a caller reporting on the cache cannot weaken it by accident.
   */
  snapshot(): ReadonlyMap<string, CachedAuditFile> {
    return new Map(this.entries);
  }

  /** Drops entries for files that no longer exist (rotated out of retention). */
  prune(liveFiles: Iterable<string>): void {
    const live = new Set(liveFiles);
    for (const file of [...this.entries.keys()]) {
      if (!live.has(file)) this.entries.delete(file);
    }
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }
}

const sharedCache = new AuditVerifyCache();

/**
 * The process-wide cache. Exposed so a caller that verifies the same directory
 * repeatedly (an interactive shell running `doctor` over and over) shares one
 * set of entries, and so a test can observe that production code used it.
 */
export function getSharedAuditVerifyCache(): AuditVerifyCache {
  return sharedCache;
}

export interface CachedVerifyOptions {
  /** Signing key. Defaults to `SW_AGENT_AUDIT_KEY` / `audit.key`. */
  key?: Buffer | string;
  /** Directory holding `audit.key`. Defaults to `dir`, then the agent home. */
  keyDir?: string;
  /** Expected head. Defaults to `head.json` in `dir`; pass `null` to skip. */
  head?: AuditHead | null;
  /** Stop after this many records read in this run. */
  maxRecords?: number;
  /** First sequence number the log must carry. Defaults to the anchored floor. */
  expectedSeq?: number;
  /** Cache to use. Defaults to the process-wide cache. */
  cache?: AuditVerifyCache;
  /** Set false to ignore and not populate the cache. Default true. */
  useCache?: boolean;
}

export interface CachedVerifyResult extends ChainVerifyResult {
  files: string[];
  malformed_lines: number;
  unreadable_files: string[];
  head_present: boolean;
  chain_id: string | null;
  coverage?: { from_seq: number; to_seq: number; records: number };
  /** Every anchor that was consulted, in the order given. */
  anchor_sources?: string[];
  /** Which of them decided the verdict. */
  anchor_source?: string | null;
  /** Files skipped because they match a previous successful verification. */
  cached_files: string[];
  /** Files actually read in this run. */
  verified_files: string[];
  skipped_bytes: number;
  verified_bytes: number;
  /** True when nothing had to be read at all. */
  cache_hit: boolean;
  /** Newest verified-at stamp among the entries this run reused. */
  cached_since?: string;
}

/**
 * Verifies the log chronologically across rotated files, reusing verified files
 * that have not changed. Fails closed: no key, no verdict.
 *
 * The verdict is identical to {@link verifyAuditLog}'s for any input the cache
 * did not serve; `verify-streaming.test.ts` pins both against the same logs.
 */
export async function verifyAuditDirCached(
  dir: string,
  opts: CachedVerifyOptions = {},
): Promise<CachedVerifyResult> {
  const files = await getAuditFilesChronological(dir);
  const head = opts.head === undefined ? readHead(dir) : opts.head;
  const { anchor, anchorSource, conflict, sources } = resolveAnchor([
    { head, source: opts.head === undefined ? AUDIT_HEAD_FILENAME : 'supplied head anchor' },
    { head: readHeadFloor(dir), source: `head${AUDIT_FLOOR_SUFFIX}` },
  ]);
  const cache = opts.useCache === false ? null : (opts.cache ?? sharedCache);
  cache?.prune(files);

  const base = {
    files,
    malformed_lines: 0,
    unreadable_files: [] as string[],
    head_present: head !== null,
    anchor_sources: sources,
    anchor_source: anchorSource,
    cached_files: [] as string[],
    verified_files: [] as string[],
    skipped_bytes: 0,
    verified_bytes: 0,
    cache_hit: false,
  };

  if (files.length === 0) {
    // Same shape as `verifyAuditLog`: a directory that used to hold an anchored
    // chain and no longer holds a log file has had the log *deleted*, which is a
    // different failure from "no records have ever been written".
    const state = await auditDirState(dir);
    const deleted = state === 'missing' || (anchor !== null && anchor.seq > 0);
    return {
      ...base,
      intact: false,
      events: 0,
      reason: deleted ? 'log_missing' : 'empty',
      detail: deleted
        ? `no audit log files in ${dir}` +
          (anchor && anchor.seq > 0
            ? `, but an anchor claims seq ${anchor.seq} — the log was deleted`
            : '')
        : `no audit records in ${dir} — an empty log is never verified`,
      chain_id: anchor?.chain_id ?? head?.chain_id ?? null,
    };
  }

  let key: Buffer;
  try {
    key =
      opts.key !== undefined
        ? requireKeyBytes(opts.key)
        : loadAuditKey({ dir: opts.keyDir ?? dir, create: false }).key;
  } catch (err: unknown) {
    return {
      ...base,
      intact: false,
      events: 0,
      reason: 'key_unavailable',
      detail: err instanceof Error ? err.message : String(err),
      chain_id: anchor?.chain_id ?? head?.chain_id ?? null,
    };
  }

  if (conflict) {
    return {
      ...base,
      intact: false,
      events: 0,
      reason: 'head_mismatch',
      detail: conflict,
      chain_id: anchor?.chain_id ?? head?.chain_id ?? null,
    };
  }

  const keyFingerprint = crypto.createHash('sha256').update(key).digest('hex').slice(0, 32);

  // The chain state the next file must resume from. Tracked here rather than
  // read back off the verifier, because a cache hit replaces the verifier and
  // the state has to survive that.
  let resumeChainId = anchor?.chain_id ?? head?.chain_id ?? null;
  let resumeSeq = opts.expectedSeq ?? anchor?.retained_from_seq ?? 1;
  /** null means "adopt the first record's prev_hash" (a retention window). */
  let resumePrev: string | null = resumeSeq > 1 ? null : GENESIS_HASH;

  let verifier = new ChainVerifier(key, {
    chainId: resumeChainId ?? undefined,
    expectedSeq: resumeSeq,
    expectedPrevHash: resumePrev ?? undefined,
  });
  /** Records already examined when the current verifier was built. */
  let verifierBase = 0;
  let chainId = resumeChainId;
  let records = 0;
  let malformed = 0;
  let fromSeq: number | null = null;
  let toSeq: number | null = null;
  let lastCachedHead: AuditHead | null = null;
  /** Newest verified-at among reused entries. */
  let cachedSince: string | undefined;
  /** Head of the log's last file, when that file came from the cache. */
  let reusedTail: { seq: number; last_hash: string; chain_id: string } | null = null;
  /** Set once a file is skipped over rather than read; blocks every later skip. */
  let cacheBlocked = false;

  for (const file of files) {
    if (verifier.failed) break;

    const identity = await statAuditFileIdentity(file);
    if (!identity) {
      base.unreadable_files.push(file);
      // A file the walk could not even stat is a hole in the sequence. Letting a
      // later cache hit bridge it would report "intact" for a chain with a
      // missing link, so no further skip is allowed in this run.
      cacheBlocked = true;
      continue;
    }

    const hit = cacheBlocked
      ? null
      : (cache?.get(file, identity, {
          chainId: resumeChainId,
          seq: resumeSeq,
          prevHash: resumePrev ?? GENESIS_HASH,
          keyFingerprint,
        }) ?? null);

    if (hit) {
      // Resuming is exact: the cached head *is* the state the verifier would be
      // in after reading this file, and the entry's `first_seq`/`first_prev_hash`
      // proved it was reached from the state we are in now.
      resumeChainId = hit.chain_id;
      resumeSeq = hit.seq + 1;
      resumePrev = hit.last_hash;
      verifier = new ChainVerifier(key, {
        chainId: hit.chain_id,
        expectedSeq: resumeSeq,
        expectedPrevHash: hit.last_hash,
      });
      verifierBase = records;
      chainId = hit.chain_id;
      records += hit.records;
      malformed += hit.malformed_lines;
      if (fromSeq === null) fromSeq = hit.first_seq;
      toSeq = hit.seq;
      base.cached_files.push(file);
      base.skipped_bytes += identity.size;
      lastCachedHead = makeHead(hit.seq, hit.last_hash, hit.chain_id);
      reusedTail = { seq: hit.seq, last_hash: hit.last_hash, chain_id: hit.chain_id };
      if (cachedSince === undefined || hit.verified_at > cachedSince) {
        cachedSince = hit.verified_at;
      }
      continue;
    }

    base.verified_files.push(file);
    base.verified_bytes += identity.size;

    const startSeq = resumeSeq;
    const startPrev = resumePrev ?? GENESIS_HASH;
    verifierBase = records;
    verifier = new ChainVerifier(key, {
      chainId: resumeChainId ?? undefined,
      expectedSeq: startSeq,
      expectedPrevHash: resumePrev ?? undefined,
    });

    let fileRecords = 0;
    let fileMalformed = 0;
    let fileFailed = false;
    /** False when the file was not read to its end (a `maxRecords` cut-off). */
    let readToEnd = true;
    try {
      for await (const line of readLines(file)) {
        const event = parseLine(line);
        if (!event) {
          // A line that is not a record is corruption, not a gap to skip past.
          fileMalformed++;
          verifier.push(null);
          fileFailed = true;
          break;
        }
        verifier.push(event);
        fileRecords++;
        if (verifier.failed) {
          fileFailed = true;
          break;
        }
        if (opts.maxRecords !== undefined && records + fileRecords >= opts.maxRecords) {
          readToEnd = false;
          break;
        }
      }
    } catch {
      base.unreadable_files.push(file);
      cacheBlocked = true;
      readToEnd = false;
    }

    records += fileRecords;
    malformed += fileMalformed;
    const observed = fileRecords > 0 ? verifier.observedHead() : null;
    if (fileRecords > 0) {
      // This file, not an earlier reused one, now holds the end of the log. An
      // empty file (a fresh active file right after a rotation) does not, so a
      // reused tail behind it still needs re-anchoring.
      reusedTail = null;
      if (fromSeq === null) fromSeq = startSeq;
      if (observed) {
        toSeq = observed.seq;
        chainId = chainId ?? observed.chain_id;
        resumeChainId = observed.chain_id;
        resumeSeq = observed.seq + 1;
        resumePrev = observed.last_hash;
      }
    }

    // Only a file that was read to its end and verified end to end may be
    // remembered: a partial read (maxRecords) or a mid-file failure would cache
    // a truncated head and the next run would resume from the wrong place.
    if (!fileFailed && readToEnd && observed) {
      cache?.set(file, {
        identity,
        records: fileRecords,
        malformed_lines: fileMalformed,
        first_seq: startSeq,
        first_prev_hash: startPrev,
        seq: observed.seq,
        last_hash: observed.last_hash,
        chain_id: observed.chain_id,
        key_fingerprint: keyFingerprint,
        verified_at: new Date().toISOString(),
      });
    }
  }

  const coverage =
    fromSeq !== null && toSeq !== null ? { from_seq: fromSeq, to_seq: toSeq, records } : undefined;
  const tail = reusedTail === null ? null : await reanchorTail(files, reusedTail);
  const tailMismatch = tail === null ? null : tail.error;

  if (tailMismatch !== null || cacheBlocked) {
    const detail =
      tailMismatch ??
      `a log file could not be read, so the chain has an unverified gap; ${base.cached_files.length} file(s) were skipped and the result is not a verdict`;
    return {
      ...base,
      intact: false,
      events: records,
      reason: tailMismatch === null ? 'unreadable' : 'head_mismatch',
      detail,
      chain_id: chainId ?? anchor?.chain_id ?? head?.chain_id ?? null,
      observed: lastCachedHead ?? undefined,
      verified_from_seq: coverage && coverage.from_seq > 1 ? coverage.from_seq : undefined,
      coverage,
      cached_since: cachedSince,
    };
  }

  if (base.verified_files.length === 0 && base.cached_files.length > 0) {
    // Every file was skipped, so the verifier has read nothing and cannot
    // produce a verdict (an empty window is never "verified"). The cached heads
    // are the log's own verified heads, so the verdict is: unchanged since the
    // verification that produced them, still consistent with the tail record
    // just re-read, and still consistent with the anchor that was just read from
    // disk.
    const observed = lastCachedHead;
    const mismatch: string | undefined = observed
      ? (compareWithAnchor(observed, anchor) ?? undefined)
      : 'no cached head to compare';
    if (observed && !mismatch) {
      return {
        intact: true,
        events: records,
        observed,
        files: base.files,
        malformed_lines: malformed,
        unreadable_files: base.unreadable_files,
        head_present: head !== null,
        chain_id: observed.chain_id,
        verified_from_seq: coverage && coverage.from_seq > 1 ? coverage.from_seq : undefined,
        coverage,
        cached_files: base.cached_files,
        verified_files: base.verified_files,
        skipped_bytes: base.skipped_bytes,
        verified_bytes: base.verified_bytes,
        cache_hit: true,
        cached_since: cachedSince,
      };
    }
    return {
      intact: false,
      events: records,
      reason: 'head_mismatch',
      detail: mismatch,
      files: base.files,
      malformed_lines: malformed,
      unreadable_files: base.unreadable_files,
      head_present: head !== null,
      chain_id: observed?.chain_id ?? anchor?.chain_id ?? head?.chain_id ?? null,
      coverage,
      cached_files: base.cached_files,
      verified_files: base.verified_files,
      skipped_bytes: base.skipped_bytes,
      verified_bytes: base.verified_bytes,
      cache_hit: true,
      cached_since: cachedSince,
    };
  }

  const result = verifier.result(anchor);
  const brokenAt = result.brokenAt === undefined ? undefined : result.brokenAt + verifierBase;

  return {
    ...result,
    ...base,
    brokenAt,
    malformed_lines: malformed,
    events: records,
    chain_id: result.observed?.chain_id ?? chainId ?? anchor?.chain_id ?? head?.chain_id ?? null,
    coverage,
    cached_since: cachedSince,
  };
}

/**
 * Anchor comparison for the fully-cached path. Mirrors the anchor rules in
 * `ChainVerifier.result`, which cannot be reused here because it only knows the
 * records it was actually handed. `head` is re-read from disk on every call, so
 * it is never stale.
 */
function compareWithAnchor(observed: AuditHead, head: AuditHead | null): string | null {
  if (!head) return null;
  if (head.chain_id !== observed.chain_id) {
    return `head belongs to chain ${head.chain_id}, the verified log is chain ${observed.chain_id}`;
  }
  if (head.seq > observed.seq) {
    return `head expects at least seq ${head.seq} but the verified log ends at seq ${observed.seq}`;
  }
  if (head.seq < observed.seq) {
    return `log ends at seq ${observed.seq}, ahead of the anchored head at ${head.seq}`;
  }
  if (head.last_hash !== observed.last_hash) {
    return `record at seq ${observed.seq} does not match the anchored head`;
  }
  return null;
}

/**
 * Re-anchors a remembered tail head to the bytes that are on disk right now.
 *
 * Bounded by construction: only the last {@link TAIL_PEEK_BYTES} of the newest
 * non-empty file are read, whatever the size of the log. `null` means the tail
 * still is the record that was verified.
 */
async function reanchorTail(
  files: string[],
  expected: { seq: number; last_hash: string; chain_id: string },
): Promise<{ error: string } | null> {
  for (let i = files.length - 1; i >= 0; i--) {
    const file = files[i];
    const event = await readTailRecord(file);
    if (event === 'empty') continue;
    if (event === 'unreadable') {
      return {
        error: `the tail of ${file} is not a readable record, so its cached verdict cannot be trusted`,
      };
    }
    if (
      event.seq !== expected.seq ||
      event.mac !== expected.last_hash ||
      event.chain_id !== expected.chain_id
    ) {
      return {
        error:
          `the last record on disk is ${describeEvent(event)}, not the ${describeEvent(expected)} ` +
          'that was verified earlier; the log changed while the cached head still claimed otherwise',
      };
    }
    return null;
  }
  return {
    error: 'no log file holds a readable record, so the cached tail head cannot be trusted',
  };
}

function describeEvent(event: { seq: number; chain_id: string }): string {
  return `seq ${event.seq} of chain ${event.chain_id}`;
}

type TailRecord = AuditEvent | 'empty' | 'unreadable';

/** Last complete non-empty line of a file, read from its tail. */
async function readTailRecord(file: string): Promise<TailRecord> {
  let handle: fs.promises.FileHandle | null = null;
  try {
    handle = await fs.promises.open(file, 'r');
    const st = await handle.stat();
    if (st.size === 0) return 'empty';
    const length = Math.min(TAIL_PEEK_BYTES, st.size);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, st.size - length);
    let text = buffer.subarray(0, bytesRead).toString('utf8');
    // The first fragment may be a partial record; the last line is never one.
    if (st.size > length) {
      const newlineAt = text.indexOf('\n');
      if (newlineAt < 0) return 'empty';
      text = text.slice(newlineAt + 1);
    }
    const lines = text.split('\n');
    while (lines.length > 0 && lines[lines.length - 1].trim().length === 0) lines.pop();
    const last = lines[lines.length - 1];
    if (last === undefined) return 'empty';
    return parseLine(last) ?? 'unreadable';
  } catch {
    return 'unreadable';
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

function parseLine(line: string): AuditEvent | null {
  const trimmed = line.trim();
  if (trimmed.length === 0) return null;
  const raw = trimmed.charCodeAt(0) === 0xfeff ? trimmed.slice(1) : trimmed;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as AuditEvent;
  } catch {
    return null;
  }
}

/**
 * Yields non-empty lines with bounded memory. Mirrors the reader in
 * `local-writer.ts`; kept local so this module does not widen that file's API.
 */
async function* readLines(file: string): AsyncGenerator<string, void, void> {
  const stream = fs.createReadStream(file, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (line.trim().length > 0) yield line;
    }
  } finally {
    rl.close();
    stream.destroy();
  }
}

type AuditDirState = 'missing' | 'empty' | 'present';

async function auditDirState(dir: string): Promise<AuditDirState> {
  let entries: string[];
  try {
    entries = await fs.promises.readdir(dir);
  } catch {
    return 'missing';
  }
  return entries.some((e) => e === 'audit.jsonl' || /^audit-\d+\.jsonl$/.test(e))
    ? 'present'
    : 'empty';
}
