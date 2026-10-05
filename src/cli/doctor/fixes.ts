import * as fs from 'fs';
import * as path from 'path';
import { isProcessAlive } from '../daemon/pid-file';
import { DoctorContext } from './checks';

export interface FixResult {
  name: string;
  applied: boolean;
  detail: string;
}

/**
 * Remove a stale PID file (the referenced process is no longer alive).
 */
async function fixStalePidFile(ctx: DoctorContext): Promise<FixResult> {
  const pidPath = path.join(ctx.swAgentDir, 'sw-agent.pid');
  try {
    const content = await fs.promises.readFile(pidPath, 'utf8');
    const pidInfo = JSON.parse(content);
    if (isProcessAlive(pidInfo.pid)) {
      return { name: 'Stale PID file', applied: false, detail: `Agent still running (pid ${pidInfo.pid})` };
    }
    await fs.promises.unlink(pidPath);
    return { name: 'Stale PID file', applied: true, detail: `Removed stale PID file (was pid ${pidInfo.pid})` };
  } catch {
    return { name: 'Stale PID file', applied: false, detail: 'No PID file present' };
  }
}

/**
 * Remove a stale status file whose heartbeat is old and whose PID is gone.
 */
async function fixStaleStatusFile(ctx: DoctorContext): Promise<FixResult> {
  const statusPath = path.join(ctx.swAgentDir, 'sw-agent.status');
  const pidPath = path.join(ctx.swAgentDir, 'sw-agent.pid');
  try {
    const pidExists = fs.existsSync(pidPath);
    let pidAlive = false;
    if (pidExists) {
      try {
        const pidInfo = JSON.parse(await fs.promises.readFile(pidPath, 'utf8'));
        pidAlive = isProcessAlive(pidInfo.pid);
      } catch { /* ignore */ }
    }

    if (pidAlive) {
      return { name: 'Stale status file', applied: false, detail: 'Agent still running' };
    }

    if (fs.existsSync(statusPath)) {
      await fs.promises.unlink(statusPath);
      return { name: 'Stale status file', applied: true, detail: 'Removed stale status file' };
    }
    return { name: 'Stale status file', applied: false, detail: 'No status file present' };
  } catch (err: unknown) {
    return { name: 'Stale status file', applied: false, detail: (err as Error).message };
  }
}

/**
 * Ensure the sw-agent home and audit directories exist with correct perms.
 */
async function fixMissingDirs(ctx: DoctorContext): Promise<FixResult> {
  let created = false;
  try {
    if (!fs.existsSync(ctx.swAgentDir)) {
      await fs.promises.mkdir(ctx.swAgentDir, { recursive: true, mode: 0o700 });
      created = true;
    }
    const auditDir = path.join(ctx.swAgentDir, 'audit');
    if (!fs.existsSync(auditDir)) {
      await fs.promises.mkdir(auditDir, { recursive: true, mode: 0o700 });
      created = true;
    }
    return { name: 'Missing directories', applied: created, detail: created ? 'Created sw-agent home + audit dirs' : 'Already present' };
  } catch (err: unknown) {
    return { name: 'Missing directories', applied: false, detail: (err as Error).message };
  }
}

/**
 * Tighten permissions on config files to 0o600 on POSIX systems. On Windows
 * this is a no-op (POSIX modes don't apply).
 */
async function fixConfigPerms(ctx: DoctorContext): Promise<FixResult> {
  if (ctx.platform === 'win32') {
    return { name: 'Config permissions', applied: false, detail: 'Skipped (Windows)' };
  }
  const targets = ['sw-agent.config.json', 'databases.config.json'];
  let changed = 0;
  for (const name of targets) {
    const p = path.join(ctx.swAgentDir, name);
    if (fs.existsSync(p)) {
      try {
        await fs.promises.chmod(p, 0o600);
        changed++;
      } catch { /* ignore */ }
    }
  }
  return { name: 'Config permissions', applied: changed > 0, detail: changed > 0 ? `Set 0o600 on ${changed} file(s)` : 'Already 0o600' };
}

/** Run all self-repair fixes in a safe order. */
export async function runAllFixes(ctx: DoctorContext): Promise<FixResult[]> {
  return [
    await fixMissingDirs(ctx),
    await fixStalePidFile(ctx),
    await fixStaleStatusFile(ctx),
    await fixConfigPerms(ctx),
  ];
}
