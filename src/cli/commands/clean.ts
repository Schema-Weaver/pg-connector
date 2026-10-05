import * as fs from 'fs';
import { spawnSync } from 'child_process';
import { getPidFilePath, getStatusFilePath, getDaemonLogPath } from '../../config/paths';
import { readPidFile, deletePidFile, isProcessAlive } from '../daemon/pid-file';
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
  const cleanLogs = opts.logs || opts.all || args.includes('--logs') || args.includes('--all') || args.includes('-l');

  const pidFilePath = getPidFilePath();
  const statusFilePath = getStatusFilePath();
  const daemonLogPath = getDaemonLogPath();

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
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to delete PID file: ${err?.message || err}`);
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
          console.log(`  ${C.green(S.check)} Terminated lingering process from status file ${C.white(`(PID ${raw.pid})`)}`);
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
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to delete status file: ${err?.message || err}`);
    }
  }

  // 3. Clean daemon logs if requested
  if (cleanLogs && fs.existsSync(daemonLogPath)) {
    try {
      fs.truncateSync(daemonLogPath, 0);
      console.log(`  ${C.green(S.check)} Truncated daemon log: ${C.dim(daemonLogPath)}`);
      cleanedSomething = true;
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to truncate daemon log: ${err?.message || err}`);
    }
  }

  console.log();
  if (cleanedSomething) {
    console.log(`  ${C.green(S.check)} ${C.bold('Agent daemon operation cleaned successfully.')}`);
  } else {
    console.log(`  ${C.cyan(S.info)} ${C.dim('Agent daemon is stopped and no stale PID/status files found. Already clean.')}`);
  }
  console.log();

  exit_(0);
}
