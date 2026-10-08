import * as fs from 'fs';
import * as path from 'path';
import { AuditEvent } from './types';

export interface AuditLogFilter {
  project?: string;
  user?: string;
  action?: string;
  decision?: string;
  outcome?: string;
  search?: string;
  since?: string | number;
  until?: string | number;
  order?: 'asc' | 'desc';
  limit?: number;
}

/** Whole-log read result, used by chain verification. */
export interface AuditLogReadResult {
  /** Log files in chronological order (oldest archive first, active file last). */
  files: string[];
  /** Every parsed record, oldest first. */
  events: AuditEvent[];
  /** Log files that exist but could not be read. */
  unreadableFiles: string[];
  /** Lines that are not parseable JSON — corruption or injected content. */
  malformedLines: number;
}

/**
 * Mode for the audit **directory**. A directory needs the execute bit to be
 * traversable; creating one with a regular file's mode (0o600) makes every
 * stat/open/readdir inside it fail with EACCES, which is how a clean install
 * ended up with no audit trail at all.
 */
export const AUDIT_DIR_MODE = 0o700;

/** Mode for the audit log files themselves: read/write for the owner only. */
export const AUDIT_FILE_MODE = 0o600;

function posixModes(): boolean {
  return process.platform !== 'win32';
}

/**
 * Repairs an audit directory left with a mode that cannot be traversed.
 *
 * `fs.mkdir({ recursive: true })` is a no-op on an existing directory, so a
 * directory created earlier with the wrong mode stays wrong and every later
 * append keeps failing EACCES. The explicit chmod is what makes an
 * already-broken install repair itself.
 *
 * @returns true when the mode had to be corrected.
 */
export async function repairAuditDirMode(
  dir: string,
  mode: number = AUDIT_DIR_MODE,
): Promise<boolean> {
  if (!posixModes()) return false;
  let st;
  try {
    st = await fs.promises.stat(dir);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw err;
  }
  if (!st.isDirectory()) {
    throw new Error(`audit path exists but is not a directory: ${dir}`);
  }
  if ((st.mode & 0o777) === mode) return false;
  await fs.promises.chmod(dir, mode);
  return true;
}

/**
 * Ensures the audit directory exists and is traversable, creating it at mode
 * 0o700 and repairing a pre-existing wrong mode.
 *
 * Idempotent and safe to call from setup, startup, append and repair paths:
 *
 * ```ts
 * await ensureAuditDir(path.join(getSwAgentDir(), 'audit'));
 * ```
 *
 * @returns true when the directory had to be created or its mode corrected.
 */
export async function ensureAuditDir(
  dir: string,
  opts: { dirMode?: number } = {},
): Promise<boolean> {
  const dirMode = opts.dirMode ?? AUDIT_DIR_MODE;
  let existed = true;
  try {
    await fs.promises.stat(dir);
  } catch {
    existed = false;
  }
  await fs.promises.mkdir(dir, { recursive: true, mode: dirMode });
  const repaired = await repairAuditDirMode(dir, dirMode);
  return !existed || repaired;
}

/** Result of {@link probeAuditDir}. */
export interface AuditDirProbe {
  ok: boolean;
  dir: string;
  dirMode: number;
  /** True when {@link repairAuditDirMode} had to change the mode. */
  repaired: boolean;
  reason?: string;
}

/**
 * Startup gate for the audit path: creates/repairs the directory, then proves a
 * real write + fsync succeeds. "Audit loss must not be silent" is only
 * enforceable if startup refuses to claim the log is fine without trying it.
 */
export async function probeAuditDir(
  dir: string,
  opts: { dirMode?: number; fileMode?: number } = {},
): Promise<AuditDirProbe> {
  const dirMode = opts.dirMode ?? AUDIT_DIR_MODE;
  const fileMode = opts.fileMode ?? AUDIT_FILE_MODE;

  let repaired = false;
  let actualMode = dirMode;
  try {
    repaired = await repairAuditDirMode(dir, dirMode).catch(() => false);
    const st = await fs.promises.stat(dir);
    if (!st.isDirectory()) {
      return { ok: false, dir, dirMode, repaired, reason: `audit path is not a directory: ${dir}` };
    }
    actualMode = st.mode & 0o777;
  } catch (err: unknown) {
    return {
      ok: false,
      dir,
      dirMode,
      repaired,
      reason: `cannot create audit directory: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const probe = path.join(dir, '.write_test');
  try {
    const fd = await fs.promises.open(probe, 'w', fileMode);
    try {
      await fd.writeFile('audit preflight');
      await fd.sync();
    } finally {
      await fd.close();
    }
    await fs.promises.unlink(probe);
  } catch (err: unknown) {
    return {
      ok: false,
      dir,
      dirMode: actualMode,
      repaired,
      reason: `audit directory is not writable: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return { ok: true, dir, dirMode: actualMode, repaired };
}

/**
 * Returns audit log files in strict chronological order:
 * audit-N.jsonl (oldest archive) -> ... -> audit-1.jsonl (most recent archive) -> audit.jsonl (active file)
 */
export async function getAuditFilesChronological(auditDir: string): Promise<string[]> {
  const archives: { file: string; index: number }[] = [];
  let hasActive = false;

  try {
    const entries = await fs.promises.readdir(auditDir);
    for (const entry of entries) {
      if (entry === 'audit.jsonl') {
        hasActive = true;
        continue;
      }
      const match = entry.match(/^audit-(\d+)\.jsonl$/);
      if (match) {
        archives.push({ file: path.join(auditDir, entry), index: parseInt(match[1], 10) });
      }
    }
  } catch {
    return [];
  }

  // Older archives have higher numbers (audit-2 is older than audit-1)
  archives.sort((a, b) => b.index - a.index);

  const result = archives.map((a) => a.file);
  if (hasActive) {
    result.push(path.join(auditDir, 'audit.jsonl'));
  }
  return result;
}

/**
 * Returns audit log files in reverse-chronological order:
 * audit.jsonl (active, newest) -> audit-1.jsonl -> audit-2.jsonl -> ... -> audit-N.jsonl (oldest)
 */
export async function getAuditFilesReverse(auditDir: string): Promise<string[]> {
  const chrono = await getAuditFilesChronological(auditDir);
  return chrono.reverse();
}

/**
 * Parse relative time string (e.g. "15m", "1h", "24h", "7d", "today") or ISO string into unix timestamp (ms).
 */
export function parseSince(since?: string | number): number | null {
  if (since === undefined || since === null || since === '') return null;
  if (typeof since === 'number') return since;

  const s = since.trim().toLowerCase();
  if (s === 'today') {
    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    return startOfToday.getTime();
  }

  const relMatch = s.match(/^(\d+)\s*(s|sec|m|min|h|hr|d|day|w|week)s?$/);
  if (relMatch) {
    const val = parseInt(relMatch[1], 10);
    const unit = relMatch[2];
    let mult = 1000;
    if (unit.startsWith('s')) mult = 1000;
    else if (unit.startsWith('m')) mult = 60 * 1000;
    else if (unit.startsWith('h')) mult = 3600 * 1000;
    else if (unit.startsWith('d')) mult = 86400 * 1000;
    else if (unit.startsWith('w')) mult = 7 * 86400 * 1000;
    return Date.now() - val * mult;
  }

  const parsed = Date.parse(since);
  if (!Number.isNaN(parsed)) {
    return parsed;
  }
  return null;
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

/**
 * Reads every record of the audit log in strict chronological order across all
 * rotated files, with no limit.
 *
 * Chain verification must see the log as one sequence: verifying each rotated
 * file in isolation reports every file that begins mid-chain as broken, which is
 * what made routine rotation look like tampering.
 */
export async function readAuditLogChronological(auditDir: string): Promise<AuditLogReadResult> {
  const result: AuditLogReadResult = {
    files: [],
    events: [],
    unreadableFiles: [],
    malformedLines: 0,
  };

  const files = await getAuditFilesChronological(auditDir);
  result.files = files;

  for (const file of files) {
    let content: string;
    try {
      content = await fs.promises.readFile(file, 'utf8');
    } catch {
      result.unreadableFiles.push(file);
      continue;
    }
    const lines = content.split('\n').filter((l) => l.trim().length > 0);
    for (let i = 0; i < lines.length; i++) {
      const raw = i === 0 ? stripBom(lines[i]) : lines[i];
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          result.malformedLines++;
          continue;
        }
        result.events.push(parsed as AuditEvent);
      } catch {
        result.malformedLines++;
      }
    }
  }

  return result;
}

/**
 * Checks whether an event satisfies the given filter.
 */
export function eventMatchesFilter(
  event: AuditEvent,
  filter: AuditLogFilter,
  sinceTs?: number | null,
  untilTs?: number | null,
  searchLower?: string,
): boolean {
  if (filter.project && event.project.toLowerCase() !== filter.project.toLowerCase()) {
    return false;
  }
  if (filter.user && !event.user_id.toLowerCase().includes(filter.user.toLowerCase())) {
    return false;
  }
  if (filter.action && event.action.toLowerCase() !== filter.action.toLowerCase()) {
    return false;
  }
  if (filter.decision && event.decision.toLowerCase() !== filter.decision.toLowerCase()) {
    return false;
  }
  if (filter.outcome && event.outcome.toLowerCase() !== filter.outcome.toLowerCase()) {
    return false;
  }

  const eventTs = new Date(event.ts).getTime();
  if (sinceTs !== null && sinceTs !== undefined && eventTs < sinceTs) {
    return false;
  }
  if (untilTs !== null && untilTs !== undefined && eventTs > untilTs) {
    return false;
  }

  if (searchLower) {
    const haystack = [
      event.statement_preview ?? '',
      event.project,
      event.user_id,
      event.action,
      event.decision,
      event.outcome,
      event.error_code ?? '',
      event.denial_reason ?? '',
      event.statement_fingerprint ?? '',
    ]
      .join(' ')
      .toLowerCase();

    if (!haystack.includes(searchLower)) {
      return false;
    }
  }

  return true;
}

/**
 * Reads audit events matching the filter.
 * Defaults to descending order (newest first).
 * Fast backwards reading: stops as soon as `limit` matches are satisfied.
 */
export async function readAuditEvents(
  auditDir: string,
  filter: AuditLogFilter = {},
): Promise<AuditEvent[]> {
  const isAsc = filter.order === 'asc';
  const limit = filter.limit && filter.limit > 0 ? filter.limit : 50;
  const sinceTs = parseSince(filter.since);
  const untilTs = parseSince(filter.until);
  const searchLower = filter.search?.trim().toLowerCase();

  const matched: AuditEvent[] = [];

  if (!isAsc) {
    // Newest first: read files in reverse (audit.jsonl first, then audit-1.jsonl, etc.)
    const files = await getAuditFilesReverse(auditDir);
    for (const file of files) {
      try {
        const content = await fs.promises.readFile(file, 'utf8');
        const lines = content.split('\n').filter((l) => l.trim().length > 0);

        // Process lines from bottom to top (newest in file to oldest)
        for (let i = lines.length - 1; i >= 0; i--) {
          const raw = i === 0 ? stripBom(lines[i]) : lines[i];
          try {
            const event = JSON.parse(raw) as AuditEvent;
            if (eventMatchesFilter(event, filter, sinceTs, untilTs, searchLower)) {
              matched.push(event);
              if (matched.length >= limit) {
                return matched;
              }
            }
          } catch {
            // ignore malformed line
          }
        }
      } catch {
        // ignore unreadable file
      }
    }
    return matched;
  } else {
    // Oldest first: read files in chronological order
    const files = await getAuditFilesChronological(auditDir);
    for (const file of files) {
      try {
        const content = await fs.promises.readFile(file, 'utf8');
        const lines = content.split('\n').filter((l) => l.trim().length > 0);

        for (let i = 0; i < lines.length; i++) {
          const raw = i === 0 ? stripBom(lines[i]) : lines[i];
          try {
            const event = JSON.parse(raw) as AuditEvent;
            if (eventMatchesFilter(event, filter, sinceTs, untilTs, searchLower)) {
              matched.push(event);
              if (matched.length >= limit) {
                return matched;
              }
            }
          } catch {
            // ignore malformed line
          }
        }
      } catch {
        // ignore unreadable file
      }
    }
    return matched;
  }
}
