import { readPidFile, isProcessAlive } from './pid-file';
import { readStatusFile, isStatusStale } from './status-file';

export interface ReadinessOptions {
  /** Max time to wait in ms. Default 8000. */
  timeoutMs?: number;
  /** Poll interval in ms. Default 250. */
  intervalMs?: number;
}

export interface ReadinessResult {
  ready: boolean;
  pid: number | null;
  /** Time spent waiting in ms. */
  waitedMs: number;
  /** Why we stopped polling. */
  reason: 'ready' | 'timeout' | 'process_dead' | 'no_pid';
}

/**
 * Poll until the daemon has written a fresh PID file AND a non-stale status
 * file with a live process. Fixes the start → status race where status was
 * queried before the detached daemon had a chance to write its files.
 */
export async function waitForAgentReady(
  pidFile: string,
  statusFile: string,
  opts: ReadinessOptions = {},
): Promise<ReadinessResult> {
  const timeoutMs = opts.timeoutMs ?? 8_000;
  const intervalMs = opts.intervalMs ?? 250;
  const start = Date.now();

  for (;;) {
    const pidInfo = await readPidFile({ path: pidFile });

    if (pidInfo) {
      const alive = isProcessAlive(pidInfo.pid);
      if (!alive) {
        // PID file exists but process is gone — it crashed during startup.
        return {
          ready: false,
          pid: pidInfo.pid,
          waitedMs: Date.now() - start,
          reason: 'process_dead',
        };
      }

      const status = await readStatusFile({ path: statusFile });
      if (status && status.pid === pidInfo.pid && !isStatusStale(status)) {
        return {
          ready: true,
          pid: pidInfo.pid,
          waitedMs: Date.now() - start,
          reason: 'ready',
        };
      }
    }

    if (Date.now() - start >= timeoutMs) {
      return {
        ready: false,
        pid: pidInfo?.pid ?? null,
        waitedMs: Date.now() - start,
        reason: pidInfo ? 'timeout' : 'no_pid',
      };
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/**
 * Poll until the daemon process is gone AND its PID file is cleaned up.
 * Fixes the symmetric race on stop, so an immediately-following status
 * check never reports a half-shutdown agent.
 */
export async function waitForAgentGone(
  pidFile: string,
  opts: ReadinessOptions = {},
): Promise<{ gone: boolean; waitedMs: number }> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const intervalMs = opts.intervalMs ?? 250;
  const start = Date.now();

  const pidInfo = await readPidFile({ path: pidFile });
  const pid = pidInfo?.pid ?? null;

  if (pid === null) {
    return { gone: true, waitedMs: 0 };
  }

  for (;;) {
    if (!isProcessAlive(pid)) {
      return { gone: true, waitedMs: Date.now() - start };
    }
    if (Date.now() - start >= timeoutMs) {
      return { gone: false, waitedMs: Date.now() - start };
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}
