import * as fs from 'fs';
import { spawnSync } from 'child_process';
import {
  getPidFilePath,
  getStatusFilePath,
  getDaemonLogPath,
  getErrorsPath,
  getAuditDirPath,
} from '../../config/paths';
import { floorPathFor } from '../../audit/chain';
import { readPidFile, deletePidFile, isProcessAlive } from '../daemon/pid-file';
import { getErrorLogFiles, resetErrorLogCache } from '../daemon/error-tracker';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface CleanOptions {
  force?: boolean;
  logs?: boolean;
  all?: boolean;
  audit?: boolean;
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Removes an audit directory together with the monotonic floor anchor that sits
 * *beside* it.
 *
 * The anchor is a sibling of the audit directory, not a file inside it, so
 * deleting the directory alone leaves a floor behind that then refuses every
 * later append with a "log was deleted" verdict — a reset that cannot be used.
 * The operator would have to find and delete a hidden file by hand to recover.
 *
 * The `audit.key` HMAC key is deliberately left alone: it lives outside the
 * audit directory and a new chain re-derives its identity from it.
 *
 * @returns the paths that were actually removed, in the order they were tried.
 */
export function purgeAuditTrail(auditDir: string): string[] {
  const removed: string[] = [];
  if (fs.existsSync(auditDir)) {
    fs.rmSync(auditDir, { recursive: true, force: true });
    removed.push(auditDir);
  }
  const floorPath = floorPathFor(auditDir);
  if (fs.existsSync(floorPath)) {
    fs.rmSync(floorPath, { force: true });
    removed.push(floorPath);
  }
  return removed;
}

function terminatePid(pid: number, force = false): boolean {
  if (pid <= 0) return false;

  if (process.platform === 'win32') {
    try {
      const res = spawnSync('taskkill', ['/pid', String(pid), '/t', '/f'], {
        stdio: 'ignore',
        windowsHide: true,
      });
      if (res.status === 0) return true;
    } catch {
      // fallback
    }
  }

  try {
    process.kill(pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    // Process might already be terminating
  }

  return true;
}

export async function runClean(args: string[] = [], opts: CleanOptions = {}): Promise<void> {
  const force = opts.force || args.includes('--force') || args.includes('-f');
  const cleanLogs =
    opts.logs ||
    opts.all ||
    args.includes('--logs') ||
    args.includes('--all') ||
    args.includes('-l');
  // Deliberately NOT implied by --all: the audit trail is the forensic record,
  // not a log, so deleting it is its own opt-in and it needs --force.
  const cleanAudit = opts.audit || args.includes('--audit');

  const pidFilePath = getPidFilePath();
  const statusFilePath = getStatusFilePath();
  const daemonLogPath = getDaemonLogPath();
  const errorsPath = getErrorsPath();

  console.log();
  console.log(`  ${C.bold(C.brand('Cleaning Agent Daemon & State'))}`);
  console.log();

  let cleanedSomething = false;
  const killedPids = new Set<number>();

  // 1. Check PID file
  const pidInfo = await readPidFile({ path: pidFilePath });
  if (pidInfo) {
    const pid = pidInfo.pid;
    if (isProcessAlive(pid)) {
      const spinner = createSpinner();
      spinner.start(`Terminating running daemon process (pid ${C.white(String(pid))})...`);

      terminatePid(pid, force);

      // Give it up to 3 seconds to fully exit
      const deadline = Date.now() + 3000;
      while (isProcessAlive(pid) && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 200));
      }

      if (isProcessAlive(pid)) {
        terminatePid(pid, true);
      }

      spinner.stop();

      if (!isProcessAlive(pid)) {
        console.log(`  ${C.green(S.check)} Terminated daemon process ${C.white(`(PID ${pid})`)}`);
        killedPids.add(pid);
        cleanedSomething = true;
      } else {
        console.log(`  ${C.yellow(S.warning)} Process ${pid} could not be completely terminated.`);
      }
    } else {
      console.log(`  ${C.dim(`${S.dot} Process ${pid} was not running.`)}`);
    }

    try {
      await deletePidFile({ path: pidFilePath });
      console.log(`  ${C.green(S.check)} Removed stale PID file: ${C.dim(pidFilePath)}`);
      cleanedSomething = true;
    } catch (err) {
      console.log(`  ${C.red(S.cross)} Failed to delete PID file: ${errText(err)}`);
    }
  } else if (fs.existsSync(pidFilePath)) {
    try {
      fs.unlinkSync(pidFilePath);
      console.log(`  ${C.green(S.check)} Removed stale PID file: ${C.dim(pidFilePath)}`);
      cleanedSomething = true;
    } catch {
      // ignore
    }
  }

  // 2. Check Status file
  if (fs.existsSync(statusFilePath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(statusFilePath, 'utf8'));
      if (raw && typeof raw.pid === 'number' && !killedPids.has(raw.pid)) {
        if (isProcessAlive(raw.pid)) {
          terminatePid(raw.pid, force);
          console.log(
            `  ${C.green(S.check)} Terminated lingering process from status file ${C.white(`(PID ${raw.pid})`)}`,
          );
          killedPids.add(raw.pid);
          cleanedSomething = true;
        }
      }
    } catch {
      // Invalid status JSON
    }

    try {
      fs.unlinkSync(statusFilePath);
      console.log(`  ${C.green(S.check)} Removed daemon status file: ${C.dim(statusFilePath)}`);
      cleanedSomething = true;
    } catch (err) {
      console.log(`  ${C.red(S.cross)} Failed to delete status file: ${errText(err)}`);
    }
  }

  // 3. Clean daemon logs if requested
  if (cleanLogs && fs.existsSync(daemonLogPath)) {
    try {
      fs.truncateSync(daemonLogPath, 0);
      console.log(`  ${C.green(S.check)} Truncated daemon log: ${C.dim(daemonLogPath)}`);
      cleanedSomething = true;
    } catch (err) {
      console.log(`  ${C.red(S.cross)} Failed to truncate daemon log: ${errText(err)}`);
    }
  }

  // 4. Clean the rotated error log. The audit trail is deliberately NOT
  //    touched here: it is the forensic record, not a log. Archives are removed
  //    outright — truncating the active file alone would leave every rotated
  //    copy, up to 3 x the active cap, on disk.
  if (cleanLogs) {
    for (const file of getErrorLogFiles()) {
      if (!fs.existsSync(file)) continue;
      try {
        fs.truncateSync(file, 0);
        cleanedSomething = true;
      } catch (err) {
        console.log(
          `  ${C.red(S.cross)} Failed to truncate error log ${C.dim(file)}: ${errText(err)}`,
        );
      }
    }
    if (fs.existsSync(errorsPath)) {
      console.log(`  ${C.green(S.check)} Truncated error log: ${C.dim(errorsPath)}`);
    }
    resetErrorLogCache();
  }

  // 5. Reset the audit trail (C-05). Opt-in only: the trail is the forensic
  //    record, so this never happens as a side effect of --logs or --all, and it
  //    is refused outright without --force. The chain's monotonic floor anchor
  //    is a *sibling* of the audit directory, so it has to be removed with it —
  //    left behind, it refuses every later append with "log was deleted" and the
  //    reset is unusable.
  if (cleanAudit) {
    const auditDir = getAuditDirPath();
    if (!force) {
      console.log(
        `  ${C.yellow(S.warning)} ${C.yellow('Refusing to delete the audit trail without')} ${C.white('--force')}${C.yellow('.')}`,
      );
      console.log(
        `  ${C.dim('The trail is the forensic record: after deletion it cannot be verified or recovered.')}`,
      );
    } else {
      console.log();
      console.log(
        `  ${C.yellow(S.warning)} ${C.yellow('Destroying the audit trail and its chain anchor.')}`,
      );
      try {
        const removed = purgeAuditTrail(auditDir);
        if (removed.length === 0) {
          console.log(`  ${C.dim(`${S.dot} No audit trail found to remove.`)}`);
        } else {
          for (const p of removed) {
            console.log(`  ${C.green(S.check)} Removed: ${C.dim(p)}`);
          }
          cleanedSomething = true;
        }
      } catch (err) {
        console.log(`  ${C.red(S.cross)} Failed to remove audit trail: ${errText(err)}`);
      }
    }
  }

  console.log();
  if (cleanedSomething) {
    console.log(`  ${C.green(S.check)} ${C.bold('Agent daemon operation cleaned successfully.')}`);
  } else {
    console.log(
      `  ${C.cyan(S.info)} ${C.dim('Agent daemon is stopped and no stale PID/status files found. Already clean.')}`,
    );
  }
  console.log();

  exit_(0);
}
