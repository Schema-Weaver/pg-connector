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
 * Checks whether an event satisfies the given filter.
 */
export function eventMatchesFilter(
  event: AuditEvent,
  filter: AuditLogFilter,
  sinceTs?: number | null,
  untilTs?: number | null,
  searchLower?: string
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
  filter: AuditLogFilter = {}
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
