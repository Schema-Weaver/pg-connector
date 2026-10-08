import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { getSwAgentDir } from '../../config/paths';
import {
  createFaultShutdownController,
  type FaultShutdownController,
  type FaultShutdownDeps,
} from './fault-shutdown';
import { assertAndLogResolvedAgentHome } from './state';

export interface ErrorRecord {
  ts: string;
  level: 'error' | 'warn' | 'fatal';
  op?: string;
  code?: string;
  message: string;
  stack?: string;
  agent_id?: string;
  pid: number;
}

/** Rotate at 2 MiB. A daemon that logs an error per query must not fill a disk. */
export const MAX_ERROR_LOG_BYTES = 2 * 1024 * 1024;

/** Keep the active file plus this many rotated archives. */
export const MAX_ERROR_ARCHIVES = 3;

/** Longest persisted `message`, in characters. */
const MAX_MESSAGE_CHARS = 500;

/** Longest persisted `stack`, in characters. */
const MAX_STACK_CHARS = 2_000;

let initialized = false;
let agentId: string | undefined;

/* ------------------------------------------------------------------ */
/* Redaction                                                           */
/* ------------------------------------------------------------------ */

/**
 * `pg` quotes the offending token with double quotes (`syntax error at or near
 * "DROP TABLE users"`) and embeds single-quoted literals
 * (`duplicate key value violates unique constraint "u_email": Key (email)=(a@b.c)`
 * / `unterminated quoted string at or near "'alice@corp.com'"`). Both forms
 * carry user data out of the database and into a file that nobody thinks of as
 * sensitive, so they are replaced with a placeholder before persistence.
 */
const SQL_DOUBLE_QUOTED = /"(?:[^"\\\n]|\\.)*"/g;
const SQL_SINGLE_QUOTED = /'(?:[^']|'')*'/g;
/** `Key (col)=(value)` detail emitted by a unique/pk violation. */
const PG_KEY_VALUE_DETAIL = /=\(([^)]*)\)/g;
/** Two or more `/`-separated segments: an absolute POSIX path. */
const POSIX_ABSOLUTE_PATH = /\/(?:[A-Za-z0-9_.~+@-]+)(?:\/[A-Za-z0-9_.~+@-]+){1,}\/?/g;
/** `C:\Users\...` — matched before the POSIX rule so the drive is not split. */
const WINDOWS_ABSOLUTE_PATH = /[A-Za-z]:\\(?:[^\\\s"'|,;]+\\)*[^\\\s"'|,;]*/g;

function shortenPosixPath(p: string): string {
  for (const home of homeDirPrefixes()) {
    if (p === home) return '~';
    if (p.startsWith(home + '/')) return '~/' + p.slice(home.length + 1);
  }

  const marker = '/node_modules/';
  const nm = p.lastIndexOf(marker);
  if (nm >= 0) return 'node_modules/' + p.slice(nm + marker.length);

  const segments = p.replace(/\/+$/, '').split('/').filter(Boolean);
  if (segments.length <= 1) return p;
  return '<path>/' + segments.slice(-2).join('/');
}

function shortenWindowsPath(p: string): string {
  const segments = p.replace(/\\+$/, '').split('\\').filter(Boolean);
  if (segments.length <= 2) return '<path>/' + (segments[segments.length - 1] ?? '');
  return '<path>/' + segments.slice(-2).join('/');
}

function homeDirPrefixes(): string[] {
  const prefixes: string[] = [];
  try {
    const agentHome = getSwAgentDir();
    if (agentHome) prefixes.push(agentHome.replace(/\/+$/, ''));
  } catch {
    // The home directory may not exist yet; os.homedir() is still useful.
  }
  try {
    const home = os.homedir();
    if (home) prefixes.push(home.replace(/\/+$/, ''));
  } catch {
    // ignore
  }
  return prefixes.filter(Boolean);
}

/**
 * Strip SQL text and absolute filesystem paths out of free-form text.
 *
 * `pg` error messages embed the offending statement and stack frames embed the
 * absolute path of the agent home directory and of `node_modules`. Neither
 * belongs in an error log that no operator is looking at.
 */
export function redactErrorText(input: string): string {
  return input
    .replace(PG_KEY_VALUE_DETAIL, '=(?)')
    .replace(SQL_DOUBLE_QUOTED, '"?"')
    .replace(SQL_SINGLE_QUOTED, "'?'")
    .replace(WINDOWS_ABSOLUTE_PATH, shortenWindowsPath)
    .replace(POSIX_ABSOLUTE_PATH, shortenPosixPath);
}

function clamp(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + '…' : text;
}

/* ------------------------------------------------------------------ */
/* Rotation                                                            */
/* ------------------------------------------------------------------ */

let cachedActiveSize: number | null = null;

function activeSize(): number {
  if (cachedActiveSize !== null) return cachedActiveSize;
  try {
    cachedActiveSize = fs.statSync(getErrorsPath()).size;
  } catch {
    cachedActiveSize = 0;
  }
  return cachedActiveSize;
}

/**
 * Roll `errors.jsonl` to `errors-1.jsonl`, shifting older archives down and
 * dropping anything past the retention window. Mirrors the rotation the audit
 * writer performs for `audit.jsonl`.
 */
export function rotateErrorLog(): void {
  const active = getErrorsPath();
  for (let i = MAX_ERROR_ARCHIVES; i >= 1; i--) {
    const from = path.join(path.dirname(active), `errors-${i}.jsonl`);
    const to = path.join(path.dirname(active), `errors-${i + 1}.jsonl`);
    try {
      fs.renameSync(from, to);
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
  }
  try {
    fs.renameSync(active, path.join(path.dirname(active), 'errors-1.jsonl'));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  // Prune anything left over from a larger previous retention window.
  for (let i = MAX_ERROR_ARCHIVES + 1; i <= MAX_ERROR_ARCHIVES + 5; i++) {
    try {
      fs.unlinkSync(path.join(path.dirname(active), `errors-${i}.jsonl`));
    } catch {
      // ignore
    }
  }
  cachedActiveSize = 0;
}

let dirEnsured: string | null = null;

function appendLine(line: string): void {
  const errorsPath = getErrorsPath();
  const dir = path.dirname(errorsPath);
  if (dirEnsured !== dir) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    dirEnsured = dir;
  }

  const lineBytes = Buffer.byteLength(line, 'utf8');
  let current = activeSize();
  if (current > 0 && current + lineBytes > MAX_ERROR_LOG_BYTES) {
    rotateErrorLog();
    current = 0;
  }

  fs.appendFileSync(errorsPath, line, { encoding: 'utf8', mode: 0o600 });
  cachedActiveSize = current + lineBytes;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/**
 * Track an error to the local, size-capped, rotated `errors.jsonl` log.
 * Structured, one JSON object per line. Never throws: losing the error record
 * must not turn a recoverable failure into a crash.
 *
 * The record is redacted before it is written — SQL fragments and absolute
 * filesystem paths (the agent home directory, `node_modules`) are stripped from
 * both `message` and `stack`. The file stays local; nothing in this module
 * transmits it anywhere.
 */
export function trackError(
  err: unknown,
  opts: { op?: string; level?: 'error' | 'warn' | 'fatal' } = {},
): void {
  try {
    const isErr = err instanceof Error;
    const record: ErrorRecord = {
      ts: new Date().toISOString(),
      level: opts.level ?? 'error',
      op: opts.op,
      code: isErr ? (err as NodeJS.ErrnoException).code : undefined,
      message: clamp(redactErrorText(isErr ? err.message : String(err)), MAX_MESSAGE_CHARS),
      stack: isErr && err.stack ? clamp(redactErrorText(err.stack), MAX_STACK_CHARS) : undefined,
      agent_id: agentId,
      pid: process.pid,
    };

    appendLine(JSON.stringify(record) + '\n');
  } catch {
    // Never let error-tracking itself throw.
  }
}

/** Path to the active local error log file. */
export function getErrorsPath(): string {
  return path.join(getSwAgentDir(), 'errors.jsonl');
}

/** Paths to every file that makes up the error log, oldest archive first. */
export function getErrorLogFiles(): string[] {
  const dir = getSwAgentDir();
  const files: string[] = [];
  for (let i = MAX_ERROR_ARCHIVES; i >= 1; i--) {
    files.push(path.join(dir, `errors-${i}.jsonl`));
  }
  files.push(getErrorsPath());
  return files;
}

export interface ErrorLogStats {
  path: string;
  /** Bytes across the active file and every retained archive. */
  size_bytes: number;
  /** Records in the active file. */
  records: number;
  /** Retained archive files that currently exist. */
  archives: number;
  /** ISO timestamp of the most recent record, if any. */
  last_error_ts: string | null;
}

/**
 * Summarise the on-disk error log for `sw-agent status` and `sw-agent debug`.
 * A missing log is a valid state, not an error.
 */
export function getErrorLogStats(): ErrorLogStats {
  const active = getErrorsPath();
  let sizeBytes = 0;
  let records = 0;
  let archives = 0;
  let lastErrorTs: string | null = null;

  for (const file of getErrorLogFiles()) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(file);
    } catch {
      continue;
    }
    sizeBytes += stat.size;
    if (file !== active) {
      archives++;
      continue;
    }
    try {
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n');
      records = 0;
      for (const line of lines) {
        if (line.trim().length === 0) continue;
        records++;
        try {
          const parsed = JSON.parse(line) as ErrorRecord;
          if (parsed.ts) lastErrorTs = parsed.ts;
        } catch {
          // ignore malformed
        }
      }
    } catch {
      // ignore
    }
  }

  return { path: active, size_bytes: sizeBytes, records, archives, last_error_ts: lastErrorTs };
}

/**
 * fsync the active error log so the record that describes a fatal fault is on
 * the disk before the process exits.
 *
 * `appendLine` uses `appendFileSync`, which hands the data to the kernel and
 * returns — it does not wait for the storage. A process that exits
 * milliseconds later can therefore lose the one record that explains why. Best
 * effort: a missing `errors.jsonl`, a rotated-away active file, or a filesystem
 * that rejects `fsync` must not stop the exit, because the exit is the part that
 * matters.
 */
export function fsyncErrorLog(): boolean {
  const target = getErrorsPath();
  let fd: number | undefined;
  try {
    fd = fs.openSync(target, 'r+');
    fs.fsyncSync(fd);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

/** The controller installed by {@link installGlobalHandlers}. Test seam. */
let faultController: FaultShutdownController | null = null;

/**
 * Hooks registered before the handlers were installed.
 *
 * `runAgent()` builds its audit sink and `PoolManager` after it installs the
 * process handlers — the handlers must exist before the parser load, so a
 * startup crash is tracked — so the runtime cannot pass them in. It calls
 * {@link registerFaultShutdownHooks} instead.
 */
let lateHooks: Pick<FaultShutdownDeps, 'flushAudit' | 'closePools'> = {};

/** The live fault controller, or null before the handlers are installed. */
export function getFaultShutdownController(): FaultShutdownController | null {
  return faultController;
}

/**
 * Register the audit-sink and pool handles the fault path must drain before it
 * exits. Safe to call before or after {@link installGlobalHandlers}.
 *
 * Without this, a fault still exits non-zero and still fsyncs `errors.jsonl`, but
 * the audit sink is left unflushed, so the final record of the action that
 * caused the fault may never reach the chain. See the report's
 * OTHER-FILE CHANGE REQUESTED for the one-line call site in `runtime.ts`.
 */
export function registerFaultShutdownHooks(
  hooks: Pick<FaultShutdownDeps, 'flushAudit' | 'closePools'>,
): void {
  lateHooks = { ...lateHooks, ...hooks };
  faultController?.setHooks(hooks);
}

/**
 * Install process-level handlers for an uncaught exception or an unhandled
 * promise rejection.
 *
 * Both are FAIL-CLOSED: the fault is recorded and redacted, the audit
 * sink and the pools are drained on a bounded timer, and the process then exits
 * non-zero so `Restart=on-failure` brings up a clean one. The previous version
 * only recorded the fault, which OVERRODE Node's terminate-by-default behaviour
 * and left a daemon serving database traffic in an undefined state.
 *
 * `unhandledRejection` is the one place that continues — and only for a reason
 * a call site explicitly tagged with `markNonFatalRejection`. See
 * `fault-shutdown.ts` for why the tag is a non-enumerable symbol.
 *
 * Also emits the startup posture lines. This is the daemon-startup hook the
 * runtime already owns (`runAgent()` calls it right after
 * `stripUnrecognisedSecurityEnv()`), and the resolved agent home has to be
 * logged from somewhere that runs exactly once per daemon start. An
 * `AgentHomeMismatchError` thrown from here propagates out of `runAgent()` and
 * is reported by the CLI with a non-zero exit, which is the intended
 * fail-closed outcome: a daemon running against a home nobody configured would
 * apply a different permission default, a different database scope and a
 * different audit key.
 */
export function installGlobalHandlers(
  currentAgentId?: string,
  hooks: Pick<FaultShutdownDeps, 'flushAudit' | 'closePools'> = {},
): void {
  if (initialized) return;
  initialized = true;
  agentId = currentAgentId;

  const effective = { ...lateHooks, ...hooks };
  const deps: FaultShutdownDeps = {
    track: (err, opts) => {
      trackError(err, opts);
    },
    flushLocalLog: () => {
      fsyncErrorLog();
    },
    log: (line) => {
      // Two destinations, because the operator has two.
      //
      // 1. The journal. The shipped unit sets `StandardError=journal`, so a
      //    narrative that only reaches `errors.jsonl` is invisible to
      //    `journalctl -u <unit>` — which is where an operator looks first after
      //    an unexplained restart. Writing only to the file means the most
      //    important line the daemon ever emits is the one they cannot see.
      try {
        fs.writeSync(2, `${line}\n`);
      } catch {
        try {
          fs.writeSync(1, `${line}\n`);
        } catch {
          // Nothing left to try; the exit still happens.
        }
      }
      // 2. The error log, so `sw-agent debug errors` shows the shutdown
      //    narrative and not just its cause.
      //
      //    The level is taken from the line's own `[warn]` / `[fatal]` prefix
      //    rather than assumed. The survivable path — a rejection explicitly
      //    tagged non-fatal, which the daemon deliberately keeps running
      //    through — is logged as `warn` by the controller, and stamping it
      //    `fatal` here put a second, contradictory `fatal` record in the file
      //    beside it. An operator grepping `errors.jsonl` for `fatal` to answer
      //    "did this host die on its own?" was told yes by a line describing a
      //    rejection it survived.
      try {
        trackError(line, {
          op: 'faultShutdown',
          level: /^\s*\[warn\]/i.test(line) ? 'warn' : 'fatal',
        });
      } catch {
        // ignore
      }
    },
    exit: (code) => {
      process.exit(code);
    },
    ...effective,
  };
  faultController = createFaultShutdownController(deps);

  const controller = faultController;
  process.on('uncaughtException', (err) => {
    void controller.handle('uncaughtException', err);
  });

  process.on('unhandledRejection', (reason) => {
    void controller.handle('unhandledRejection', reason);
  });

  assertAndLogResolvedAgentHome();
}

/** Reset the install latch. Test helper; a second install in one process is a no-op. */
export function resetGlobalHandlersForTests(): void {
  initialized = false;
  agentId = undefined;
  faultController = null;
  lateHooks = {};
}

/** Read recent error records from the local log, newest last. */
export async function readRecentErrors(limit: number): Promise<ErrorRecord[]> {
  try {
    const records: ErrorRecord[] = [];
    for (const file of getErrorLogFiles()) {
      let content: string;
      try {
        content = await fs.promises.readFile(file, 'utf8');
      } catch {
        continue;
      }
      for (const line of content.split('\n')) {
        if (line.trim().length === 0) continue;
        try {
          records.push(JSON.parse(line) as ErrorRecord);
        } catch {
          // ignore malformed
        }
      }
    }
    return records.slice(-limit);
  } catch {
    return [];
  }
}

/** Reset the cached active-file size and directory memo. Test and lifecycle helper. */
export function resetErrorLogCache(): void {
  cachedActiveSize = null;
  dirEnsured = null;
}
