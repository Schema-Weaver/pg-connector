import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import {
  AUDIT_FLOOR_SUFFIX,
  AUDIT_HEAD_FILENAME,
  ChainVerifier,
  loadAuditKey,
  readHead,
  readHeadFloor,
  resolveAnchor,
  type ChainVerifyResult,
} from './chain';
import { getAuditFilesChronological, getAuditFilesReverse } from './files';
import { AuditEvent, AuditHead, AuditWriterHealth } from './types';

export interface LocalWriterOptions {
  dir: string;
  /** Rotate the active log past this size. Default 10 MiB. */
  maxFileSize?: number;
  /** Number of rotated archives to keep. Default 10. */
  maxArchiveFiles?: number;
  /** Mode for the log files themselves. Default 0o600. */
  fileMode?: number;
  /**
   * Mode for the audit **directory**. Default 0o700.
   *
   * This must be a directory mode. A directory at 0o600 has no execute bit, is
   * therefore untraversable, and every write into it fails EACCES — which is how
   * a clean install ended up with no audit trail at all (finding C-06).
   */
  dirMode?: number;
  /** Group-commit interval for non-durable appends. Default 50ms. */
  flushIntervalMs?: number;
  /** Appends buffered before a group commit is forced. Default 256. */
  batchSize?: number;
  /**
   * Not settable here — use `setCommitListener()`. Called after every fsync
   * that made records durable, with the newest record that became durable. This
   * is where the chain head is anchored: the anchor must land *after* the data,
   * never before, or a crash in between looks like a truncation.
   */
}

export interface AppendOptions {
  /**
   * When true (the default) the record is written and `fsync`'d before the
   * returned promise resolves. `logSync()` depends on this; `log()` does not.
   */
  durable?: boolean;
}

const DEFAULT_FILE_MODE = 0o600;
const DEFAULT_DIR_MODE = 0o700;
const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVE_FILES = 10;
const DEFAULT_FLUSH_INTERVAL_MS = 50;
const DEFAULT_BATCH_SIZE = 256;
/** Bytes read from the head of a file to find its first record. */
const READ_HEAD_BYTES = 16 * 1024;

export const ACTIVE_AUDIT_FILE = 'audit.jsonl';
const ARCHIVE_NAME = /^audit-(\d+)\.jsonl$/;

/** Notified after a successful fsync with the newest durable record. */
export type CommitListener = (last: AuditEvent | null, retainedFromSeq: number | null) => void;

/**
 * Append-only local audit writer with group commit.
 *
 * Durability contract:
 *   - `append(event, { durable: true })` resolves only after the record has been
 *     written and `fsync`'d. This is what `AuditSink.logSync()` relies on.
 *   - `append(event, { durable: false })` resolves once the record has been
 *     handed to the kernel; a group commit `fsync`s it within `flushIntervalMs`,
 *     or immediately once `batchSize` records are buffered. This is what
 *     `AuditSink.log()` uses.
 *   - `flush()` forces the outstanding `fsync`; `close()` flushes, `fsync`s and
 *     releases the handle. Both are safe to call more than once and safe to race
 *     with `append()`: every mutating operation is serialised on one chain, so a
 *     concurrent append either lands before the close or reopens afterwards. A
 *     failure in either is reported through `getHealth()` and rethrown — never
 *     swallowed into a "flushed OK".
 *
 * One long-lived handle replaces the previous open/fsync/close per event, and
 * the `mkdir` + `stat` per event are gone from the hot path (finding M-05).
 */
export class LocalAuditWriter {
  private readonly opts: Required<LocalWriterOptions>;
  private readonly activePath: string;
  private lastKnownSize: number | null = null;

  /** Serialises mutating operations so fd/size/rotation state stays coherent. */
  private opChain: Promise<unknown> = Promise.resolve();
  private handle: fs.promises.FileHandle | null = null;
  private unflushedBytes = 0;
  private pendingRecords = 0;
  private flushTimer: NodeJS.Timeout | null = null;
  private lastError: string | null = null;
  private lastErrorAt: string | null = null;
  private lastWriteAt: string | null = null;
  private dirMode: number | null = null;
  private fileMode: number | null = null;
  private ready = false;
  private reportedError: string | null = null;
  private rotations = 0;
  private eventsWritten = 0;
  private eventsFailed = 0;
  private bytesWritten = 0;
  private commitListener: CommitListener | null = null;
  private lastAppended: AuditEvent | null = null;
  private retainedFromSeq: number | null = null;

  constructor(opts: LocalWriterOptions) {
    this.opts = {
      dir: opts.dir,
      maxFileSize: opts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
      maxArchiveFiles: opts.maxArchiveFiles ?? DEFAULT_MAX_ARCHIVE_FILES,
      fileMode: opts.fileMode ?? DEFAULT_FILE_MODE,
      dirMode: opts.dirMode ?? DEFAULT_DIR_MODE,
      flushIntervalMs: opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS,
      batchSize: opts.batchSize ?? DEFAULT_BATCH_SIZE,
    };
    this.activePath = path.join(this.opts.dir, ACTIVE_AUDIT_FILE);
  }

  get dir(): string {
    return this.opts.dir;
  }

  get activeFilePath(): string {
    return this.activePath;
  }

  /**
   * Registers the durable-commit hook. `AuditSink` uses it to anchor the chain
   * head at exactly the point where records became durable.
   */
  setCommitListener(fn: CommitListener | null): void {
    this.commitListener = fn;
  }

  /**
   * Oldest sequence number still on disk, or null when no record is retained.
   *
   * Rotation keeps a bounded number of archives, so the oldest records are
   * eventually evicted on purpose. Whole-log verification therefore starts at
   * this sequence number rather than at the genesis hash (finding M-06/H-13
   * interaction: an evicted archive used to make every later verify report a
   * phantom `seq_gap`).
   */
  getRetentionFloor(): number | null {
    return this.retainedFromSeq;
  }

  async append(event: AuditEvent, opts: AppendOptions = {}): Promise<void> {
    const durable = opts.durable !== false;
    const line = JSON.stringify(event) + '\n';
    const lineBytes = Buffer.byteLength(line, 'utf8');

    let retried = false;
    for (;;) {
      try {
        await this.run(() => this.writeRecord(event, line, lineBytes, durable));
        break;
      } catch (err: unknown) {
        if (!retried && isPermissionError(err)) {
          // The directory may have been left untraversable by an older install.
          // Drop the handle so the next pass re-runs mkdir + chmod.
          retried = true;
          await this.run(() => this.dropHandle());
          continue;
        }
        this.eventsFailed++;
        this.recordFailure(err);
        throw err;
      }
    }

    this.eventsWritten++;
    this.bytesWritten += lineBytes;
    this.lastWriteAt = new Date().toISOString();
    this.noteSuccess();
  }

  /**
   * Creates the audit directory (0o700, repairing a stuck 0o600 one) and opens
   * the log file (0o600). Called before the chain head is anchored so a broken
   * install is repaired before anything tries to use the directory.
   */
  async prepare(): Promise<void> {
    try {
      await this.run(() => this.ensureReady());
    } catch (err: unknown) {
      this.recordFailure(err);
      throw err;
    }
  }

  /** Forces an fsync of everything written but not yet committed. */
  async flush(): Promise<void> {
    try {
      await this.run(() => this.flushNow());
    } catch (err: unknown) {
      // A silent flush is a lost record: the caller must learn that the data it
      // was promised is not durable, and health must stop claiming it is.
      this.recordFailure(err);
      throw err;
    }
  }

  /**
   * Flushes every buffered record, `fsync`s it, then closes the long-lived
   * handle. The writer stays usable afterwards — a later `append()` reopens.
   *
   * Shutdown contract, and the reason the daemon may call it after a signal and
   * again on an explicit stop:
   *   - **Idempotent.** A second `close()` is a no-op that resolves: the handle
   *     is cleared before it is closed, so the descriptor can never be closed
   *     twice.
   *   - **Nothing is buffered on return.** The group-commit timer is cancelled
   *     first, so it cannot fire against a closed descriptor afterwards.
   *   - **The handle is released even when the flush fails.** Otherwise a
   *     failing fsync would leak the descriptor *and* hide behind a rejected
   *     promise that a caller may not await. The flush error is reported through
   *     `getHealth()` and rethrown; it is never turned into a fake "flushed OK".
   */
  async close(): Promise<void> {
    try {
      await this.run(async () => {
        this.cancelFlushTimer();
        try {
          await this.flushNow();
        } finally {
          await this.closeHandle();
        }
      });
    } catch (err: unknown) {
      this.recordFailure(err);
      throw err;
    }
  }

  /** Rotates the active file. Chain continuity is the caller's to preserve. */
  async rotate(): Promise<void> {
    try {
      await this.run(() => this.rotateNow());
    } catch (err: unknown) {
      this.recordFailure(err);
      throw err;
    }
  }

  getHealth(): AuditWriterHealth {
    return {
      dir: this.opts.dir,
      active_path: this.activePath,
      ready: this.ready,
      writable: this.lastError === null,
      dir_mode: this.dirMode,
      file_mode: this.fileMode,
      retained_from_seq: this.retainedFromSeq,
      last_write_at: this.lastWriteAt,
      last_error: this.lastError,
      last_error_at: this.lastErrorAt,
      error_count: this.eventsFailed,
      events_written: this.eventsWritten,
      events_failed: this.eventsFailed,
      bytes_written: this.bytesWritten,
      rotations: this.rotations,
    };
  }

  /* ---------------------------------------------------------------- */
  /* Reading                                                           */
  /* ---------------------------------------------------------------- */

  /**
   * Loads every record of the log, oldest archive first.
   *
   * Kept for small callers (filters, tests). It materialises the whole history,
   * so verification goes through {@link verifyAuditLog} instead of this
   * (finding M-06).
   */
  async readAll(opts: { limit?: number } = {}): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    for await (const event of this.stream({ maxRecords: opts.limit })) {
      events.push(event);
    }
    return events;
  }

  /** Streams every record in chronological order, one record at a time. */
  async *stream(opts: { maxRecords?: number } = {}): AsyncGenerator<AuditEvent, void, void> {
    const files = await getAuditFilesChronological(this.opts.dir);
    let seen = 0;
    for (const file of files) {
      for await (const line of readLines(file)) {
        if (opts.maxRecords !== undefined && seen >= opts.maxRecords) return;
        const event = parseLine(line);
        if (!event) continue;
        seen++;
        yield event;
      }
    }
  }

  /**
   * Newest record of the newest non-empty log file.
   *
   * Startup chain recovery: the in-memory head is gone after a restart and
   * `head.json` can be a tick behind the last durable append. Returns `null`
   * when the log is empty or unreadable.
   */
  async readTailEvent(maxBytes = 64 * 1024): Promise<AuditEvent | null> {
    const files = await getAuditFilesReverse(this.opts.dir);
    for (const file of files) {
      const tail = await readLastLine(file, maxBytes);
      if (tail === null) continue;
      const event = parseLine(tail);
      if (event) return event;
    }
    return null;
  }

  /* ---------------------------------------------------------------- */
  /* Internals                                                         */
  /* ---------------------------------------------------------------- */

  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.opChain.then(fn, fn);
    this.opChain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  private async writeRecord(
    event: AuditEvent,
    line: string,
    lineBytes: number,
    durable: boolean,
  ): Promise<void> {
    await this.ensureReady();

    const currentSize = await this.currentFileSize();
    if (currentSize > 0 && currentSize + lineBytes > this.opts.maxFileSize) {
      await this.rotateNow();
    }

    const fd = this.handle;
    if (!fd) {
      throw new Error('audit file handle is not open');
    }
    await fd.appendFile(line);

    this.lastAppended = event;
    this.lastKnownSize = (this.lastKnownSize ?? currentSize ?? 0) + lineBytes;
    this.unflushedBytes += lineBytes;
    this.pendingRecords += 1;

    if (durable || this.pendingRecords >= this.opts.batchSize) {
      await this.flushNow();
    } else {
      this.scheduleFlush();
    }
  }

  private async ensureReady(): Promise<void> {
    if (this.handle) return;

    await fs.promises.mkdir(this.opts.dir, { recursive: true, mode: this.opts.dirMode });
    await this.repairDirMode();

    this.handle = await fs.promises.open(this.activePath, 'a', this.opts.fileMode);
    this.ready = true;
    try {
      const st = await fs.promises.stat(this.activePath);
      this.fileMode = st.mode & 0o777;
      this.lastKnownSize = st.size;
    } catch {
      this.fileMode = this.opts.fileMode;
    }
    await this.refreshRetentionFloor();
  }

  /**
   * Reads the sequence number of the oldest record still on disk.
   *
   * The oldest archive is `audit-<maxArchiveFiles>.jsonl` (higher index = older),
   * and the floor only moves up: it is a promise about what the log retains, so
   * it must never go backwards.
   */
  private async refreshRetentionFloor(): Promise<void> {
    let oldest: string | null = null;
    try {
      const entries = await fs.promises.readdir(this.opts.dir);
      let maxIndex = 0;
      for (const entry of entries) {
        const m = ARCHIVE_NAME.exec(entry);
        if (!m) continue;
        const index = Number.parseInt(m[1], 10);
        if (index > maxIndex) {
          maxIndex = index;
          oldest = path.join(this.opts.dir, entry);
        }
      }
    } catch {
      return;
    }
    if (!oldest) {
      // No archive: everything still in the active file.
      this.retainedFromSeq = this.retainedFromSeq ?? null;
      return;
    }
    const first = await readFirstSeq(oldest);
    if (first !== null && (this.retainedFromSeq === null || first > this.retainedFromSeq)) {
      this.retainedFromSeq = first;
    }
  }

  /**
   * Repairs a directory left untraversable by an older version. `mkdir` is a
   * no-op when the directory already exists, so without this the wrong mode is
   * sticky and every append keeps failing EACCES (finding C-06).
   */
  private async repairDirMode(): Promise<void> {
    const st = await fs.promises.stat(this.opts.dir);
    if (!st.isDirectory()) {
      throw new Error(`audit path ${this.opts.dir} exists but is not a directory`);
    }
    this.dirMode = st.mode & 0o777;
    if (this.dirMode === this.opts.dirMode) return;
    await fs.promises.chmod(this.opts.dir, this.opts.dirMode);
    this.dirMode = this.opts.dirMode;
  }

  private async currentFileSize(): Promise<number> {
    if (this.lastKnownSize !== null) return this.lastKnownSize;
    try {
      const st = await fs.promises.stat(this.activePath);
      return st.size;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return 0;
      throw err;
    }
  }

  private async flushNow(): Promise<void> {
    this.cancelFlushTimer();
    const fd = this.handle;
    if (!fd) return;
    if (this.unflushedBytes > 0 || this.pendingRecords > 0) {
      await fd.sync();
      this.unflushedBytes = 0;
      this.pendingRecords = 0;
      // The records are durable now, so the chain head may be advanced.
      this.notifyCommit();
    }
  }

  /**
   * A failure to anchor the head does not undo the records already on disk, so
   * it is reported rather than thrown — but it is never swallowed either: the
   * writer goes unhealthy and says so once.
   */
  private notifyCommit(): void {
    const fn = this.commitListener;
    if (!fn) return;
    try {
      fn(this.lastAppended, this.retainedFromSeq);
    } catch (err: unknown) {
      this.recordFailure(err);
    }
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;
      void this.run(() => this.flushNow()).catch(() => {
        // append() already reports; a group-commit failure rides along with it.
      });
    }, this.opts.flushIntervalMs);
    this.flushTimer.unref?.();
  }

  private cancelFlushTimer(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }

  private async rotateNow(): Promise<void> {
    this.cancelFlushTimer();
    // Never rotate away records that are written but not yet committed.
    await this.flushNow();
    await this.closeHandle();

    for (let i = this.opts.maxArchiveFiles - 1; i >= 1; i--) {
      const from = path.join(this.opts.dir, `audit-${i}.jsonl`);
      const to = path.join(this.opts.dir, `audit-${i + 1}.jsonl`);
      try {
        await fs.promises.rename(from, to);
      } catch (err: unknown) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== 'ENOENT') throw err;
      }
    }

    try {
      await fs.promises.rename(this.activePath, path.join(this.opts.dir, 'audit-1.jsonl'));
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') throw err;
    }

    for (let i = this.opts.maxArchiveFiles + 1; i <= this.opts.maxArchiveFiles + 5; i++) {
      try {
        await fs.promises.unlink(path.join(this.opts.dir, `audit-${i}.jsonl`));
      } catch {
        // best effort
      }
    }

    this.handle = await fs.promises.open(this.activePath, 'a', this.opts.fileMode);
    this.ready = true;
    this.rotations++;
    this.lastKnownSize = 0;
    try {
      const st = await fs.promises.stat(this.activePath);
      this.fileMode = st.mode & 0o777;
    } catch {
      this.fileMode = this.opts.fileMode;
    }

    // The shift above may have overwritten the oldest archive, i.e. dropped
    // records on purpose. Re-derive the retention floor so the chain anchor
    // stops claiming those records exist.
    const before = this.retainedFromSeq;
    await this.refreshRetentionFloor();
    if (this.retainedFromSeq !== before) {
      this.notifyCommit();
    }
  }

  private async closeHandle(): Promise<void> {
    const fd = this.handle;
    this.handle = null;
    this.ready = false;
    if (fd) await fd.close();
  }

  private async dropHandle(): Promise<void> {
    this.cancelFlushTimer();
    await this.closeHandle().catch(() => undefined);
  }

  /**
   * Records the failure and complains once per distinct error, so audit loss is
   * loud without one stack trace per query.
   */
  private recordFailure(err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    this.lastError = message;
    this.lastErrorAt = new Date().toISOString();
    if (this.reportedError === message) return;
    this.reportedError = message;
    console.error(
      `[audit] FATAL: audit persistence failure (${message}). Audit integrity guarantees are degraded and ` +
        `records may be LOST. Check that ${this.opts.dir} is a directory with mode 0o700, that ${this.activePath} ` +
        'is writable, and that sw-agent status reports a healthy audit writer.',
    );
  }

  private noteSuccess(): void {
    if (this.lastError === null) return;
    this.lastError = null;
    this.reportedError = null;
  }
}

function isPermissionError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | null)?.code;
  return code === 'EACCES' || code === 'EPERM' || code === 'EROFS';
}

/* ------------------------------------------------------------------ */
/* Whole-log verification                                               */
/* ------------------------------------------------------------------ */

export interface VerifyAuditLogOptions {
  /** Signing key. Defaults to `SW_AGENT_AUDIT_KEY` / `audit.key`. */
  key?: Buffer | string;
  /** Expected head. Defaults to `head.json` in `dir`; pass `null` to skip. */
  head?: AuditHead | null;
  /** Directory/keyfile to resolve the key from when `key` is omitted. */
  keyDir?: string;
  /** Stop after this many records. Guards against a runaway log. */
  maxRecords?: number;
  /** First sequence number the log must carry. Defaults to the head's retention floor, else 1. */
  expectedSeq?: number;
}

export interface AuditLogVerification extends ChainVerifyResult {
  /** Log files walked, oldest first. */
  files: string[];
  /** Records that were not parseable JSON. */
  malformed_lines: number;
  /** Files that exist but could not be read. */
  unreadable_files: string[];
  head_present: boolean;
  chain_id: string | null;
  /** Every anchor that was consulted, in the order given. */
  anchor_sources: string[];
  /** Which of them decided the verdict. */
  anchor_source: string | null;
}

export interface VerifyStreamOptions {
  /** Signing key. There is no unkeyed verification. */
  key: Buffer | string;
  /** Expected head. When omitted the stream is verified for internal consistency only. */
  head?: AuditHead | null;
  /** Sequence number the first record must carry. Default 1. */
  expectedSeq?: number;
  /** Hash the first record must chain from. Defaults to the genesis hash. */
  expectedPrevHash?: string;
  /** Chain id every record must carry. Default: pinned from the first record. */
  chainId?: string;
  /** Stop after this many records. */
  maxRecords?: number;
}

/**
 * Incremental verification of an ordered record stream, with early exit on the
 * first bad record (finding M-06).
 *
 * Holds only the previous record's mac/seq, so peak memory is O(1) in the
 * number of records. Anything that is not an object is treated as corruption
 * rather than skipped: silently ignoring an unreadable line would let an
 * attacker delete records that a partial write happened to break.
 */
export async function verifyStream(
  source: AsyncIterable<unknown> | Iterable<unknown>,
  opts: VerifyStreamOptions,
): Promise<ChainVerifyResult> {
  const verifier = new ChainVerifier(opts.key, {
    chainId: opts.chainId,
    expectedSeq: opts.expectedSeq,
    expectedPrevHash: opts.expectedPrevHash,
  });

  for await (const record of source) {
    if (verifier.failed) break;
    verifier.push(record);
    if (opts.maxRecords !== undefined && verifier.events >= opts.maxRecords) break;
  }

  return verifier.result(opts.head ?? null);
}

/**
 * Verifies the whole audit log as one chronological sequence across rotated
 * files, anchored on the strongest available claim about where the chain ends.
 *
 * Two anchors are consulted: `head.json` inside the audit directory and the
 * monotonic floor beside it. Either alone can be rolled back together with the
 * log; the pair cannot, which is what makes a restored older copy detectable
 * (finding C-05).
 *
 * The entry point CLI commands should call: it resolves the key, reads the
 * anchors, streams the log in O(1) memory and early-exits on the first bad
 * record (findings C-05, H-13, M-06).
 */
export async function verifyAuditLog(
  dir: string,
  opts: VerifyAuditLogOptions = {},
): Promise<AuditLogVerification> {
  const files = await getAuditFilesChronological(dir);

  const head = opts.head === undefined ? readHead(dir) : opts.head;
  const { anchor, anchorSource, conflict, sources } = resolveAnchor([
    { head, source: opts.head === undefined ? AUDIT_HEAD_FILENAME : 'supplied head anchor' },
    { head: readHeadFloor(dir), source: `head${AUDIT_FLOOR_SUFFIX}` },
  ]);
  const anchorOrigin = { anchor_sources: sources, anchor_source: anchorSource };

  let key: Buffer | null = null;
  let keyError: string | null = null;
  try {
    key =
      opts.key !== undefined
        ? requireKeyBytes(opts.key)
        : loadAuditKey({ dir: opts.keyDir, create: false }).key;
  } catch (err: unknown) {
    keyError = err instanceof Error ? err.message : String(err);
  }

  const base = {
    files,
    malformed_lines: 0,
    unreadable_files: [] as string[],
    head_present: head !== null,
    ...anchorOrigin,
  };

  if (files.length === 0) {
    const state = await auditDirState(dir);
    // A directory that used to hold an anchored chain but no longer holds a log
    // file has had the log deleted, which is a different failure from "no
    // records have ever been written".
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

  if (!key) {
    return {
      ...base,
      intact: false,
      events: 0,
      reason: 'key_unavailable',
      detail:
        keyError ??
        'no audit key available (SW_AGENT_AUDIT_KEY or ~/.sw-agent/audit.key); the chain cannot be verified',
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

  const verifier = new ChainVerifier(key, {
    chainId: anchor?.chain_id ?? head?.chain_id,
    // Start at the anchored retention floor: rotation evicts the oldest archives
    // on purpose, and demanding the genesis hash after that would report
    // tampering for a log that is merely older than the retained window.
    expectedSeq: opts.expectedSeq ?? anchor?.retained_from_seq ?? 1,
  });
  let malformed = 0;
  const unreadable: string[] = [];

  for (const file of files) {
    if (verifier.failed) break;
    try {
      for await (const line of readLines(file)) {
        const event = parseLine(line);
        if (!event) {
          // A line that is not a record at all is corruption or tampering.
          malformed++;
          verifier.push(null);
          break;
        }
        verifier.push(event);
        if (verifier.failed) break;
        if (opts.maxRecords !== undefined && verifier.events >= opts.maxRecords) break;
      }
    } catch {
      unreadable.push(file);
    }
    if (opts.maxRecords !== undefined && verifier.events >= opts.maxRecords) break;
  }

  const result = verifier.result(anchor);
  return {
    ...result,
    ...base,
    malformed_lines: malformed,
    chain_id: result.observed?.chain_id ?? anchor?.chain_id ?? head?.chain_id ?? null,
  };
}

function requireKeyBytes(key: Buffer | string): Buffer {
  if (Buffer.isBuffer(key)) {
    if (key.length === 0) throw new Error('empty audit key');
    return key;
  }
  if (typeof key === 'string' && key.length > 0) return Buffer.from(key, 'utf8');
  throw new Error('empty audit key');
}

type AuditDirState = 'missing' | 'empty' | 'present';

async function auditDirState(dir: string): Promise<AuditDirState> {
  let entries: string[];
  try {
    entries = await fs.promises.readdir(dir);
  } catch {
    return 'missing';
  }
  return entries.some((e) => e === ACTIVE_AUDIT_FILE || ARCHIVE_NAME.test(e)) ? 'present' : 'empty';
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

/** Yields non-empty lines of a file with bounded memory. */
async function* readLines(file: string): AsyncGenerator<string, void, void> {
  const stream = fs.createReadStream(file, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (line.trim().length > 0) yield line;
    }
  } finally {
    rl.close();
    if (!stream.destroyed) stream.destroy();
    // Wait for the descriptor to be released: a stream torn down mid-read must
    // not be left for the garbage collector to clean up.
    if (!stream.closed) {
      await new Promise<void>((resolve) => {
        const done = () => resolve();
        stream.once('close', done);
        stream.once('error', done);
      });
    }
  }
}

/**
 * First complete non-empty line of a file, reading only its head. Returns
 * `null` for an empty file or an unreadable record.
 */
async function readFirstSeq(file: string): Promise<number | null> {
  let handle: fs.promises.FileHandle | null = null;
  try {
    handle = await fs.promises.open(file, 'r');
    const buffer = Buffer.alloc(READ_HEAD_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, READ_HEAD_BYTES, 0);
    const text = buffer.subarray(0, bytesRead).toString('utf8');
    const newlineAt = text.indexOf('\n');
    const first = newlineAt >= 0 ? text.slice(0, newlineAt) : text;
    const event = parseLine(first);
    const seq = event?.seq;
    return typeof seq === 'number' && Number.isInteger(seq) && seq >= 1 ? seq : null;
  } catch {
    return null;
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

/**
 * Last complete non-empty line of a file, reading only the final `maxBytes`.
 * Returns `null` for an empty file, or when the tail window holds no complete
 * line (the caller then tries the next-newest file).
 */
async function readLastLine(file: string, maxBytes: number): Promise<string | null> {
  let handle: fs.promises.FileHandle | null = null;
  try {
    handle = await fs.promises.open(file, 'r');
    const st = await handle.stat();
    if (st.size === 0) return null;
    const length = Math.min(maxBytes, st.size);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, st.size - length);
    let text = buffer.subarray(0, bytesRead).toString('utf8');
    // If we started mid-line, the first fragment is a partial record.
    const newlineAt = text.indexOf('\n');
    if (st.size > length && newlineAt < 0) return null;
    if (st.size > length) text = text.slice(newlineAt + 1);
    const lines = text.split('\n').filter((l) => l.trim().length > 0);
    return lines.length > 0 ? lines[lines.length - 1] : null;
  } catch {
    return null;
  } finally {
    if (handle) await handle.close().catch(() => undefined);
  }
}

export { AUDIT_HEAD_FILENAME };

/**
 * Re-exported so callers that already import from this module (setup paths,
 * `doctor`, `init`) have one obvious entry point. The implementation lives in
 * `./files` because it needs no writer state.
 */
export {
  AUDIT_DIR_MODE,
  AUDIT_FILE_MODE,
  ensureAuditDir,
  probeAuditDir,
  repairAuditDirMode,
} from './files';
