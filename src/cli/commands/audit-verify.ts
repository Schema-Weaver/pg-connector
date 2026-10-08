import * as path from 'path';
import * as fs from 'fs';
import { getSwAgentDir } from '../../config/paths';
import { AuditHead } from '../../audit/types';
import { isHash64, readHead } from '../../audit/chain';
import { readAuditLogChronological } from '../../audit/files';
import { verifyAuditLog, type AuditLogVerification } from '../../audit/local-writer';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface AuditVerifyOptions {
  verbose?: boolean;
}

export interface VerifyResult {
  file: string;
  totalEvents: number;
  validEvents: number;
  hashErrors: number;
  parseErrors: number;
  chainBrokenIndex?: number;
}

interface AnchorSpec {
  head: AuditHead | null;
  source: string;
  error?: string;
}

/**
 * Parses the operator-supplied head anchor.
 *
 * This is the only verification input that a writer of the audit directory
 * cannot reach. Without it, anyone who can write both the log and `head.json`
 * produces a self-consistent chain that no local comparison can distinguish
 * from the original, so the anchor must come from somewhere else — a ticket, a
 * SIEM field, another host, a password manager.
 */
function parseAnchor(args: string[]): AnchorSpec {
  const inlineIdx = args.indexOf('--anchor');
  const fileIdx = args.indexOf('--anchor-file');
  const seqIdx = args.indexOf('--anchor-seq');
  const hashIdx = args.indexOf('--anchor-hash');

  if (inlineIdx !== -1) {
    const raw = args[inlineIdx + 1];
    if (!raw) return { head: null, source: 'none', error: '--anchor requires <seq>:<hash>' };
    const m = raw.match(/^(\d+):([0-9a-fA-F]{64})$/);
    if (!m)
      return {
        head: null,
        source: 'none',
        error: `--anchor must be <seq>:<64-hex-hash>, got "${raw}"`,
      };
    return {
      head: {
        v: 1,
        chain_id: '*',
        seq: parseInt(m[1], 10),
        last_hash: m[2].toLowerCase(),
        written_at: '',
      },
      source: `--anchor ${raw}`,
    };
  }

  if (seqIdx !== -1 || hashIdx !== -1) {
    const seq = args[seqIdx + 1];
    const lastHash = args[hashIdx + 1];
    const parsedSeq = seq !== undefined ? Number.parseInt(seq, 10) : Number.NaN;
    if (!Number.isInteger(parsedSeq) || parsedSeq < 0 || !lastHash) {
      return {
        head: null,
        source: 'none',
        error: '--anchor-seq and --anchor-hash must be given together',
      };
    }
    if (!isHash64(lastHash.toLowerCase())) {
      return {
        head: null,
        source: 'none',
        error: '--anchor-hash must be a 64-character hex digest',
      };
    }
    return {
      head: {
        v: 1,
        chain_id: '*',
        seq: parsedSeq,
        last_hash: lastHash.toLowerCase(),
        written_at: '',
      },
      source: `--anchor-seq ${parsedSeq}`,
    };
  }

  if (fileIdx !== -1) {
    const file = args[fileIdx + 1];
    if (!file) return { head: null, source: 'none', error: '--anchor-file requires a path' };
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
    } catch (err: unknown) {
      return {
        head: null,
        source: 'none',
        error: `--anchor-file unreadable: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    const rec = parsed as Record<string, unknown>;
    const seq = typeof rec.seq === 'string' ? Number.parseInt(rec.seq, 10) : rec.seq;
    const lastHash =
      typeof rec.last_hash === 'string' ? rec.last_hash.toLowerCase() : rec.last_hash;
    if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 0) {
      return {
        head: null,
        source: 'none',
        error: '--anchor-file: "seq" must be a non-negative integer',
      };
    }
    if (!isHash64(lastHash)) {
      return {
        head: null,
        source: 'none',
        error: '--anchor-file: "last_hash" must be a 64-character hex digest',
      };
    }
    return {
      head: {
        v: 1,
        chain_id: typeof rec.chain_id === 'string' && rec.chain_id.length > 0 ? rec.chain_id : '*',
        seq,
        last_hash: lastHash,
        written_at: '',
      },
      source: `--anchor-file ${path.basename(file)}`,
    };
  }

  return { head: null, source: 'none' };
}

/** Reads the first record so legacy (pre-keying) logs can be named as such. */
async function peekFirstRecord(auditDir: string): Promise<Record<string, unknown> | null> {
  try {
    const read = await readAuditLogChronological(auditDir);
    return (read.events[0] as unknown as Record<string, unknown>) ?? null;
  } catch {
    return null;
  }
}

/**
 * A pre-upgrade record: written before records were MAC'd and sequenced, so it
 * carries no `chain_id`, no `seq` and only an unkeyed SHA-256 `hash`.
 *
 * Such a log is *classified*, never verified: an unkeyed chain over public data
 * proves only internal consistency, and anyone holding the file can reproduce
 * it. Reporting it as "tampered" would be wrong; reporting it as verified would
 * be worse.
 */
function isLegacyRecord(rec: Record<string, unknown> | null): boolean {
  if (!rec) return false;
  return typeof rec.chain_id !== 'string' || typeof rec.seq !== 'number';
}

export async function runAuditVerify(args: string[], opts: AuditVerifyOptions = {}): Promise<void> {
  const verbose = opts.verbose || args.includes('--verbose') || args.includes('-v');
  const json = args.includes('--json');
  const allowLegacy = args.includes('--allow-legacy');
  const spec = parseAnchor(args);

  const swAgentDir = getSwAgentDir();
  const auditDir = path.join(swAgentDir, 'audit');

  console.log();
  console.log(C.bold(C.brand('  Audit Log Verification')));
  console.log();

  if (spec.error) {
    console.log(`  ${C.red(S.cross)} ${C.brightRed('Invalid anchor:')} ${spec.error}`);
    console.log();
    exit_(2);
  }

  const first = await peekFirstRecord(auditDir);
  const legacy = isLegacyRecord(first);

  // `chain_id` identifies the signing key, not the anchor: fill it in from the
  // local head or the first record when the operator supplied only seq+hash.
  const localHead = readHead(auditDir);
  const expectedHead = spec.head
    ? {
        ...spec.head,
        chain_id:
          spec.head.chain_id !== '*'
            ? spec.head.chain_id
            : (localHead?.chain_id ?? (typeof first?.chain_id === 'string' ? first.chain_id : '*')),
      }
    : undefined;

  let result: AuditLogVerification;
  try {
    // Deliberately the UNCACHED verifier. `doctor` and `start` may reuse the
    // per-file verification cache (see `verifyAuditDirCached`), because they
    // re-ask the same question about the same bytes; this command must not.
    //
    // An operator runs `audit verify` precisely when they suspect the log was
    // touched, and its contract is "verify the log as it is on disk right now".
    // A cached verdict is a statement about bytes this process verified
    // earlier, and it rests on stat metadata (inode, size, mtime, ctime) that a
    // writer of the audit directory can restore. On a filesystem with coarse
    // timestamps, a same-size rewrite with the timestamps put back would
    // otherwise be reported here as "integrity verified" — the worst possible
    // answer to this question. Verification is already O(1) in memory and
    // early-exits on the first bad record, so the only thing given up is the
    // time to re-read a log that has not changed.
    result = await verifyAuditLog(auditDir, {
      head: expectedHead,
      keyDir: swAgentDir,
    });
  } catch (err: unknown) {
    console.log(
      `  ${C.red(S.cross)} ${C.brightRed('Verification failed to run:')} ${err instanceof Error ? err.message : String(err)}`,
    );
    console.log();
    exit_(1);
  }

  const headPresent = result.head_present;
  // Every anchor that was consulted is named, not only the one that decided the
  // verdict: an operator has to be able to see that a rollback was caught by the
  // second anchor, or they cannot tell which file to restore from.
  const consulted = result.anchor_sources.length > 0 ? result.anchor_sources.join(' + ') : 'none';
  const anchorSource =
    spec.source === 'none'
      ? headPresent
        ? `${consulted} (local)`
        : 'none'
      : `${spec.source} + ${consulted}`;
  const anchored = spec.source !== 'none' || headPresent;

  if (json) {
    console.log(
      JSON.stringify(
        {
          ...result,
          legacy,
          anchor_source: anchorSource,
          anchor_present: anchored,
          allowed_legacy: allowLegacy,
        },
        null,
        2,
      ),
    );
    exit_(verdictExitCode(result, legacy, allowLegacy));
  }

  const spinner = createSpinner();
  spinner.start('Verifying audit log integrity...');
  await new Promise((resolve) => setTimeout(resolve, 300));
  spinner.stop();

  console.log();
  console.log(`  ${C.bold('Results:')}`);
  console.log(`    Log files:   ${C.white(String(result.files.length))}`);
  console.log(`    Records:     ${C.white(String(result.events))}`);
  if (result.malformed_lines > 0) {
    console.log(`    Parse errors: ${C.red(String(result.malformed_lines))}`);
  }
  if (result.unreadable_files.length > 0) {
    console.log(`    Unreadable:   ${C.red(result.unreadable_files.join(', '))}`);
  }
  if (result.observed) {
    console.log(
      `    Head found:  ${C.white(`seq ${result.observed.seq}`)} ${C.dim(`chain ${result.observed.chain_id}`)}`,
    );
  }
  console.log(`    Anchor:      ${anchored ? C.white(anchorSource) : C.yellow('none available')}`);
  if (!anchored) {
    console.log(
      `      ${C.dim('Without an anchor, truncation, deletion and rollback cannot be detected.')}`,
    );
  }
  console.log(
    result.reason === 'key_unavailable'
      ? `    Chain key:   ${C.yellow('unavailable — the log was NOT cryptographically checked')}`
      : `    Chain key:   ${C.white('HMAC-SHA256 (per-installation key)')}`,
  );

  console.log();

  if (legacy) {
    console.log(
      `  ${C.yellow(S.warning)} ${C.bold('LEGACY LOG')} — records predate keyed chaining (plain SHA-256).`,
    );
    console.log(
      `      ${C.dim('An unkeyed chain over public data can be recomputed by anyone holding the file,')}`,
    );
    console.log(
      `      ${C.dim('so these records are reported as UNVERIFIED rather than checked.')}`,
    );
    if (allowLegacy) {
      console.log(`      ${C.dim('Accepted because --allow-legacy was given.')}`);
    } else {
      console.log(
        `      ${C.dim('Re-run with --allow-legacy to accept a legacy log, or archive it and start a new log.')}`,
      );
    }
    console.log();
  }

  if (result.intact && !legacy) {
    console.log(`  ${C.green(S.check)} ${C.brightGreen('Audit log integrity verified.')}`);
    console.log(
      `      ${C.dim('Proves: no record was modified, inserted, removed or reordered without the chain key,')}`,
    );
    console.log(
      `      ${C.dim(`        and the log ends exactly at the anchored head (seq ${result.observed?.seq ?? 0}).`)}`,
    );
    console.log(
      `      ${C.dim('Does NOT prove: who performed the actions, or completeness past rotation retention.')}`,
    );
  } else if (result.intact && legacy && allowLegacy) {
    console.log(
      `  ${C.yellow(S.warning)} ${C.bold('Accepted as a legacy log (--allow-legacy). Records were NOT cryptographically verified.')}`,
    );
  } else if (legacy) {
    console.log(
      `  ${C.red(S.cross)} ${C.brightRed('Legacy log: records cannot be cryptographically verified.')}`,
    );
  } else {
    console.log(`  ${C.red(S.cross)} ${C.brightRed('Audit log integrity check FAILED.')}`);
    if (result.reason) {
      console.log(`      Reason: ${C.yellow(result.reason)}`);
    }
    if (result.detail) {
      console.log(`      ${C.dim(result.detail)}`);
    }
    if (result.brokenAt !== undefined) {
      console.log(`      First bad record index: ${C.red(String(result.brokenAt))}`);
    }
  }

  if (verbose) {
    console.log();
    console.log(`  ${C.dim(`audit dir: ${auditDir}`)}`);
  }

  console.log();
  exit_(verdictExitCode(result, legacy, allowLegacy));
}

/**
 * Exit policy, strict by default:
 *   - a log that fails verification never exits 0
 *   - a log that cannot be verified at all — legacy, or no key — never exits 0
 *     unless the operator passes --allow-legacy, which downgrades the verdict to
 *     "accepted, unverified" and is visible in the output
 *   - "nothing to verify" is a failure, never a pass
 */
function verdictExitCode(
  result: AuditLogVerification,
  legacy: boolean,
  allowLegacy: boolean,
): number {
  if (result.reason === 'empty') return 1;
  if (!result.intact) return 1;
  if (legacy && !allowLegacy) return 1;
  return 0;
}

/**
 * Per-file diagnostic view retained for callers that report on individual
 * rotated files. It reports parse integrity only; chain verdicts come from
 * `verifyAuditLog`, which verifies the whole log as one sequence.
 */
export async function verifyFile(file: string, _verbose: boolean): Promise<VerifyResult> {
  const result: VerifyResult = {
    file: path.basename(file),
    totalEvents: 0,
    validEvents: 0,
    hashErrors: 0,
    parseErrors: 0,
  };

  let content: string;
  try {
    content = await fs.promises.readFile(file, 'utf8');
  } catch {
    return result;
  }

  const lines = content.split('\n').filter(Boolean);
  result.totalEvents = lines.length;

  for (let i = 0; i < lines.length; i++) {
    try {
      JSON.parse(i === 0 ? stripBom(lines[i]) : lines[i]);
      result.validEvents++;
    } catch {
      result.parseErrors++;
    }
  }

  return result;
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}
