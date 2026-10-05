import { getPidFilePath } from '../../config/paths';
import { readPidFile, deletePidFile, isProcessAlive } from '../daemon/pid-file';
import { waitForAgentGone } from '../daemon/readiness';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface StopOptions {
  force?: boolean;
  timeoutMs?: number;
}

export async function runStop(args: string[], opts: StopOptions = {}): Promise<void> {
  const force = opts.force || args.includes('--force') || args.includes('-f');
  const timeoutMs = opts.timeoutMs ?? 30_000;

  const pidFile = getPidFilePath();

  const pidInfo = await readPidFile({ path: pidFile });
  if (!pidInfo) {
    console.log(`  ${C.yellow(S.warning)} No agent running (no PID file found)`);
    exit_(0);
  }

  const { pid, started_at, version } = pidInfo;

  if (!isProcessAlive(pid)) {
    console.log(`  ${C.yellow(S.warning)} Agent (pid ${pid}) is not running. Cleaning up stale PID file.`);
    await deletePidFile({ path: pidFile });
    exit_(0);
  }

  console.log();
  console.log(`  ${C.dim('Stopping agent...')}`);
  console.log(`    PID:      ${C.white(String(pid))}`);
  console.log(`    Started:  ${C.dim(started_at)}`);
  console.log(`    Version:  ${C.dim(version)}`);
  console.log();

  const spinner = createSpinner();

  if (force) {
    spinner.start('Sending SIGTERM...');
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      // ignore
    }

    const deadline = Date.now() + timeoutMs;
    while (isProcessAlive(pid) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    if (isProcessAlive(pid)) {
      spinner.update('SIGTERM failed, sending SIGKILL...');
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        // ignore
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    spinner.stop();

    if (isProcessAlive(pid)) {
      console.log(`  ${C.red(S.cross)} Failed to kill process ${pid}`);
      exit_(1);
    }
  } else {
    spinner.start('Sending SIGTERM...');
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      spinner.stop();
      console.log(`  ${C.red(S.cross)} Failed to send SIGTERM to process ${pid}`);
      exit_(1);
    }

    // Wait for process to actually exit
    const deadline = Date.now() + timeoutMs;
    while (isProcessAlive(pid) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    spinner.stop();

    if (isProcessAlive(pid)) {
      console.log(`  ${C.yellow(S.warning)} Process did not exit gracefully. Use ${C.cyan('--force')} to kill.`);
      exit_(1);
    }
  }

  // Clean up PID file
  await deletePidFile({ path: pidFile });
  // Confirm the process is truly gone so a follow-up status check is accurate.
  const gone = await waitForAgentGone(pidFile, { timeoutMs: 3_000 });
  if (gone.gone) {
    console.log(`  ${C.green(S.check)} Agent stopped and PID file cleaned up.`);
  } else {
    console.log(`  ${C.yellow(S.warning)} PID file removed, but process may still be exiting.`);
  }
  console.log();
  exit_(0);
}
