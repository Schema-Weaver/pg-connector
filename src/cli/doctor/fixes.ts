import * as fs from 'fs';
import * as path from 'path';
import { isProcessAlive } from '../daemon/pid-file';
import { ensureAuditDir } from '../../audit/files';
import { DoctorContext, formatMode, inspectConfigFileModes, SECURE_CONFIG_MODE } from './checks';

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
      return {
        name: 'Stale PID file',
        applied: false,
        detail: `Agent still running (pid ${pidInfo.pid})`,
      };
    }
    await fs.promises.unlink(pidPath);
    return {
      name: 'Stale PID file',
      applied: true,
      detail: `Removed stale PID file (was pid ${pidInfo.pid})`,
    };
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
      } catch {
        /* ignore */
      }
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
 * Ensure the sw-agent home and audit directories exist with a *traversable* mode.
 *
 * `mkdir({ recursive: true })` is a no-op on an existing directory, so an audit
 * directory left at 0o600 (no execute bit, therefore untraversable) stays broken
 * and every append fails EACCES — the audit log then records nothing while every
 * command reports success. `ensureAuditDir` chmods it back to 0o700.
 */
async function fixMissingDirs(ctx: DoctorContext): Promise<FixResult> {
  try {
    if (!fs.existsSync(ctx.swAgentDir)) {
      await fs.promises.mkdir(ctx.swAgentDir, { recursive: true, mode: 0o700 });
    }
    const auditDir = path.join(ctx.swAgentDir, 'audit');
    const before = statMode(auditDir);
    const repaired = await ensureAuditDir(auditDir);
    const after = statMode(auditDir);

    const notes: string[] = [];
    if (before === null) notes.push('created audit dir 0o700');
    else if (repaired)
      notes.push(`repaired audit dir ${formatMode(before)} -> ${formatMode(after ?? 0o700)}`);
    else notes.push(`audit dir ${formatMode(before)}`);

    return {
      name: 'Missing directories',
      applied: repaired || before === null,
      detail: notes.join('; '),
    };
  } catch (err: unknown) {
    return { name: 'Missing directories', applied: false, detail: (err as Error).message };
  }
}

function statMode(p: string): number | null {
  try {
    return fs.statSync(p).mode & 0o777;
  } catch {
    return null;
  }
}

/**
 * Tighten permissions on the config files to 0o600 on POSIX systems, repairing
 * the pre-existing mode rather than only setting one on creation. On Windows
 * this is a no-op (POSIX modes don't apply).
 *
 * A config file that is not a regular file is reported but never chmodded: the
 * fix must not follow a symlink and rewrite the mode of something outside the
 * agent home.
 */
async function fixConfigPerms(ctx: DoctorContext): Promise<FixResult> {
  if (ctx.platform === 'win32') {
    return { name: 'Config permissions', applied: false, detail: 'Skipped (Windows)' };
  }

  const inspected = inspectConfigFileModes(ctx.swAgentDir);
  let changed = 0;
  const skipped: string[] = [];
  for (const file of inspected) {
    if (!file.exists) continue;
    if (file.irregular) {
      skipped.push(`${file.name} (not a regular file)`);
      continue;
    }
    if (file.mode === SECURE_CONFIG_MODE) continue;
    try {
      await fs.promises.chmod(file.path, SECURE_CONFIG_MODE);
      const repaired = fs.statSync(file.path).mode & 0o777;
      if (repaired !== SECURE_CONFIG_MODE) {
        skipped.push(`${file.name} (still ${formatMode(repaired)})`);
        continue;
      }
      changed++;
    } catch (err: unknown) {
      skipped.push(`${file.name} (${err instanceof Error ? err.message : String(err)})`);
    }
  }

  const parts: string[] = [];
  parts.push(
    changed > 0 ? `Set ${formatMode(SECURE_CONFIG_MODE)} on ${changed} file(s)` : 'Already secure',
  );
  if (skipped.length > 0) {
    parts.push(`could not fix: ${skipped.join(', ')}`);
  }
  return {
    name: 'Config permissions',
    applied: changed > 0,
    detail: parts.join('; '),
  };
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
