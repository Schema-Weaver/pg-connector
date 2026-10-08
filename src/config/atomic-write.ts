/**
 * Atomic, symlink-refusing, permission-repairing file writes plus the advisory
 * lock used to serialise read-modify-write sequences over config files.
 *
 * Every config file that can hold the agent token or a database password must
 * go through {@link atomicWriteFile}: a plain `writeFileSync` applies `mode`
 * only on create (so a pre-existing 0o644 file stays world-readable), follows
 * symlinks planted by a local attacker, and can truncate the file — which for
 * the machine config means permanent loss of the agent token.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

/** Mode every credential-bearing config file is written and repaired to. */
export const ATOMIC_WRITE_FILE_MODE = 0o600;

/** Mode the containing directory is created and repaired to. */
export const ATOMIC_WRITE_DIR_MODE = 0o700;

export type AtomicWriteErrorCode = 'symlink_refused' | 'write_failed' | 'lock_timeout';

/** Raised when a config write is refused or cannot be completed. */
export class AtomicWriteError extends Error {
  readonly code: AtomicWriteErrorCode;

  constructor(message: string, code: AtomicWriteErrorCode = 'write_failed') {
    super(message);
    this.name = 'AtomicWriteError';
    this.code = code;
  }
}

export interface FileLockOptions {
  /** Age after which an abandoned lock is reaped. Default 30s. */
  staleMs?: number;
  /** How long to wait for a contended lock before failing. Default 5s. */
  timeoutMs?: number;
  /** Lock acquisition poll interval. Default 25ms. */
  retryMs?: number;
}

const DEFAULT_LOCK_STALE_MS = 30_000;
const DEFAULT_LOCK_TIMEOUT_MS = 5_000;
const DEFAULT_LOCK_RETRY_MS = 25;

const NOFOLLOW = (fs.constants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
const TEMP_WRITE_FLAGS =
  fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW;

const heldLocks = new Set<string>();

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function hasCode(err: unknown, code: string): boolean {
  return (
    typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code
  );
}

function chmodIfPosix(target: string, mode: number): void {
  if (process.platform === 'win32') return;
  fs.chmodSync(target, mode);
}

function closeQuietly(fd: number): void {
  try {
    fs.closeSync(fd);
  } catch {
    // ignore
  }
}

function unlinkQuietly(target: string): void {
  try {
    fs.unlinkSync(target);
  } catch {
    // ignore
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Fails when `target` is a symlink. A missing file is not a symlink, so the
 * check is safe to run before every create. Use `lstat`, never `stat`: `stat`
 * follows the link and reports the target's type, which is exactly the check
 * that has to fail here.
 */
export function assertNotSymlink(target: string): void {
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(target);
  } catch (err) {
    if (hasCode(err, 'ENOENT')) return;
    throw new AtomicWriteError(`Cannot inspect ${target}: ${errText(err)}`);
  }
  if (stats.isSymbolicLink()) {
    throw new AtomicWriteError(
      `Refusing to write through the symlink ${target}. Remove it or point SW_AGENT_HOME somewhere else.`,
      'symlink_refused',
    );
  }
}

/** Creates the containing directory if missing; leaves an existing one alone. */
export function ensureDir(dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: ATOMIC_WRITE_DIR_MODE });
  } catch (err) {
    if (!hasCode(err, 'EEXIST')) {
      throw new AtomicWriteError(`Failed to create directory ${dir}: ${errText(err)}`);
    }
  }
}

/**
 * Creates the containing directory and repairs the mode of a pre-existing one
 * that is group- or world-accessible. Used for the agent home, which holds the
 * token: a 0o755 home is a failed control, not a cosmetic detail.
 */
export function ensureSecureDir(dir: string): void {
  ensureDir(dir);
  chmodIfPosix(dir, ATOMIC_WRITE_DIR_MODE);
}

/** fsync of the directory so the rename survives a power loss, where supported. */
function fsyncDir(dir: string): void {
  if (process.platform === 'win32') return;
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch {
    // EINVAL/EPERM/EISDIR: the filesystem does not support directory fsync.
  } finally {
    if (fd !== undefined) closeQuietly(fd);
  }
}

/**
 * Writes `data` to `filePath` atomically:
 * create a private temp file, fsync it, rename it over the target, then fsync
 * the directory. A reader therefore only ever sees the complete old file or the
 * complete new one, and a crash cannot truncate the config.
 *
 * The temp file is created with O_EXCL|O_NOFOLLOW, so it can never be
 * pre-created (or symlinked) by another process, and is chmod'ed to `mode`
 * unconditionally: `mode` passed to `open` is masked by the umask, so it alone
 * cannot guarantee 0o600.
 */
export function atomicWriteFile(
  filePath: string,
  data: string | Buffer,
  mode: number = ATOMIC_WRITE_FILE_MODE,
): void {
  const dir = path.dirname(filePath);
  ensureDir(dir);
  assertNotSymlink(filePath);

  const tmp = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmp, TEMP_WRITE_FLAGS, mode);
    assertNotSymlink(tmp);
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    let written = 0;
    while (written < buf.length) {
      written += fs.writeSync(fd, buf, written, buf.length - written);
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    chmodIfPosix(tmp, mode);
    fs.renameSync(tmp, filePath);
    chmodIfPosix(filePath, mode);
    fsyncDir(dir);
  } catch (err) {
    if (fd !== undefined) closeQuietly(fd);
    unlinkQuietly(tmp);
    if (err instanceof AtomicWriteError) throw err;
    throw new AtomicWriteError(`Failed to write ${filePath}: ${errText(err)}`);
  }
}

/** `atomicWriteFile` for a JSON document, pretty-printed with a trailing newline. */
export function atomicWriteJson(
  filePath: string,
  value: unknown,
  mode: number = ATOMIC_WRITE_FILE_MODE,
): void {
  atomicWriteFile(filePath, `${JSON.stringify(value, null, 2)}\n`, mode);
}

/**
 * True when the lock file next to `target` was abandoned (older than `staleMs`)
 * or is not a real lock file. Reaps it as a side effect.
 */
function reapStaleLock(lockPath: string, staleMs: number): boolean {
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(lockPath);
  } catch (err) {
    return hasCode(err, 'ENOENT');
  }
  if (stats.isSymbolicLink() || !stats.isFile()) {
    unlinkQuietly(lockPath);
    return true;
  }
  if (Date.now() - stats.mtimeMs > staleMs) {
    unlinkQuietly(lockPath);
    return true;
  }
  return false;
}

function acquireLock(
  lockPath: string,
  staleMs: number,
  timeoutMs: number,
  retryMs: number,
): void {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', ATOMIC_WRITE_FILE_MODE);
      try {
        fs.writeSync(
          fd,
          `${JSON.stringify({ pid: process.pid, acquired_at: new Date().toISOString() })}\n`,
        );
        fs.fsyncSync(fd);
      } finally {
        closeQuietly(fd);
      }
      chmodIfPosix(lockPath, ATOMIC_WRITE_FILE_MODE);
      heldLocks.add(lockPath);
      return;
    } catch (err) {
      if (!hasCode(err, 'EEXIST')) {
        throw new AtomicWriteError(`Failed to take the lock ${lockPath}: ${errText(err)}`);
      }
    }
    if (reapStaleLock(lockPath, staleMs)) continue;
    if (Date.now() >= deadline) {
      throw new AtomicWriteError(
        `Timed out after ${timeoutMs}ms waiting for the lock ${lockPath}. Another sw-agent process is writing the same config; retry once it finishes.`,
        'lock_timeout',
      );
    }
    sleepSync(retryMs);
  }
}

function releaseLock(lockPath: string): void {
  heldLocks.delete(lockPath);
  unlinkQuietly(lockPath);
}

/**
 * Runs `fn` while holding an exclusive advisory lock on `targetPath`. Use it
 * around every load → mutate → save sequence so two concurrent CLI
 * invocations cannot lose one another's update. The lock is an `O_EXCL` lock
 * file, so it is released by the kernel even if the process is killed; a lock
 * whose holder died is reaped after `staleMs`.
 *
 * Re-entrant within one process: a nested call for the same target runs `fn`
 * directly instead of deadlocking against itself.
 */
export function withFileLock<T>(
  targetPath: string,
  fn: () => T,
  opts: FileLockOptions = {},
): T {
  const lockPath = `${targetPath}.lock`;
  if (heldLocks.has(lockPath)) {
    return fn();
  }
  const dir = path.dirname(lockPath);
  ensureSecureDir(dir);
  acquireLock(
    lockPath,
    opts.staleMs ?? DEFAULT_LOCK_STALE_MS,
    opts.timeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS,
    opts.retryMs ?? DEFAULT_LOCK_RETRY_MS,
  );
  try {
    return fn();
  } finally {
    releaseLock(lockPath);
  }
}