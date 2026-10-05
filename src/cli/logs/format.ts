import { AuditEvent } from '../../audit/types';
import { C, S, alignAnsi, renderTable, truncateAnsi, terminalWidth, visibleLength } from '../ui';

function truncate(s: string, n: number): string {
  return truncateAnsi(s, n, S.ellipsis);
}

export function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const sec = Math.max(0, Math.floor(diff / 1000));
  if (sec < 5) return 'now';
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hrs = Math.floor(min / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.floor(hrs / 24);
  return `${days}d`;
}

export const DECISION_COLOR: Record<string, (s: string) => string> = {
  allow: C.green,
  deny: C.red,
  pending: C.yellow,
  approved: C.yellow,
  rejected: C.brightRed,
  expired: C.brightRed,
};

export const OUTCOME_COLOR: Record<string, (s: string) => string> = {
  success: C.green,
  error: C.red,
  cancelled: C.yellow,
  'n/a': C.dim,
};

export function renderLogTable(events: AuditEvent[], maxWidth = terminalWidth() - 2): string {
  const rows = events.map((event) => ({
    when: event.ts.slice(5, 19).replace('T', ' '),
    age: relativeTime(event.ts),
    project: event.project,
    user: event.user_id,
    action: event.action,
    decision: event.decision,
    outcome: event.outcome,
    ms: event.duration_ms === undefined ? '-' : `${event.duration_ms}ms`,
    preview: event.statement_preview ?? '-',
  }));

  return renderTable(rows, {
    maxWidth,
    columns: [
      { key: 'when', header: 'WHEN', minWidth: 12, maxWidth: 14, priority: 2 },
      { key: 'age', header: 'AGE', minWidth: 4, maxWidth: 6, priority: 8, color: C.dim },
      { key: 'project', header: 'PROJECT', minWidth: 10, maxWidth: 18, priority: 1, formatter: (v) => truncate(String(v), 18) },
      { key: 'user', header: 'USER', minWidth: 8, maxWidth: 16, priority: 5, formatter: (v) => truncate(String(v), 16) },
      { key: 'action', header: 'ACTION', minWidth: 10, maxWidth: 16, priority: 3 },
      {
        key: 'decision',
        header: 'DECISION',
        minWidth: 7,
        maxWidth: 10,
        priority: 4,
        color: (value, row) => (DECISION_COLOR[String(row.decision)] ?? C.white)(value),
      },
      {
        key: 'outcome',
        header: 'OUTCOME',
        minWidth: 7,
        maxWidth: 10,
        priority: 6,
        color: (value, row) => (OUTCOME_COLOR[String(row.outcome)] ?? C.white)(value),
      },
      { key: 'ms', header: 'TIME', minWidth: 6, maxWidth: 8, priority: 7, align: 'right' },
      { key: 'preview', header: 'SQL PREVIEW', minWidth: 18, maxWidth: 72, priority: 0, formatter: (v) => truncate(String(v), 72) },
    ],
  });
}

export function formatEventRow(event: AuditEvent): string {
  const tsFormatted = event.ts.slice(0, 19).replace('T', ' ');
  const decision = (DECISION_COLOR[event.decision] ?? C.white)(event.decision);
  const outcome = (OUTCOME_COLOR[event.outcome] ?? C.white)(event.outcome);
  const preview = truncate(event.statement_preview ?? '-', Math.max(12, terminalWidth() - 72));
  return [
    C.dim(tsFormatted),
    C.cyan(truncate(event.project, 14).padEnd(14)),
    truncate(event.action, 14).padEnd(14),
    alignAnsi(decision, 10),
    alignAnsi(outcome, 10),
    preview,
  ].join('  ');
}

export function formatTableHeader(): string {
  const line1 = [
    C.dim(' TS'.padEnd(19)),
    C.dim('PROJECT'.padEnd(14)),
    C.dim('ACTION'.padEnd(14)),
    C.dim('DECISION'.padEnd(10)),
    C.dim('OUTCOME'.padEnd(10)),
    C.dim('SQL PREVIEW'),
  ].join('  ');
  const line2 = C.dim(S.h.repeat(Math.min(120, terminalWidth() - 2)));
  return `${line1}\n${line2}`;
}

export function formatEventJson(event: AuditEvent): string {
  return JSON.stringify(event);
}

/**
 * Formats a detailed modal card for inspecting a single audit event without truncating SQL.
 */
export function renderEventDetailLines(event: AuditEvent, width: number): string[] {
  const innerWidth = Math.max(40, width - 4);
  const lines: string[] = [];

  const decColor = DECISION_COLOR[event.decision] ?? C.white;
  const outColor = OUTCOME_COLOR[event.outcome] ?? C.white;

  const title = ` AUDIT EVENT: ${event.id} `;
  lines.push(C.cyan(S.tl + S.h + C.bold(title) + S.h.repeat(Math.max(0, innerWidth - visibleLength(title) + 1)) + S.tr));

  const addField = (label: string, value: string) => {
    const paddedLabel = C.dim(label.padEnd(16));
    const content = `${paddedLabel} ${value}`;
    const fitted = truncateAnsi(content, innerWidth, S.ellipsis);
    lines.push(C.cyan(S.v) + ' ' + fitted + ' '.repeat(Math.max(0, innerWidth - visibleLength(fitted))) + ' ' + C.cyan(S.v));
  };

  addField('Timestamp', `${C.white(event.ts)} ${C.dim(`(${relativeTime(event.ts)} ago)`)}`);
  addField('Action', C.cyan(event.action));
  addField('Decision', decColor(C.bold(event.decision)));
  addField('Outcome', outColor(C.bold(event.outcome)));
  addField('Project', C.white(event.project));
  addField('User ID', C.white(event.user_id));
  addField('Role', C.dim(event.role));
  addField('Permission', C.dim(event.permission_level));

  if (event.duration_ms !== undefined) {
    addField('Duration', C.white(`${event.duration_ms} ms`));
  }
  if (event.rows_affected !== undefined || event.rows_returned !== undefined) {
    addField(
      'Rows',
      C.dim(`affected: ${event.rows_affected ?? '-'}, returned: ${event.rows_returned ?? '-'}`)
    );
  }
  if (event.denial_reason) {
    addField('Denial Reason', C.brightRed(event.denial_reason));
  }
  if (event.error_code) {
    addField('Error Code', C.brightRed(event.error_code));
  }

  // Divider
  lines.push(C.cyan(S.v) + C.dim(S.h.repeat(innerWidth + 2)) + C.cyan(S.v));

  // Statement preview / SQL query
  lines.push(C.cyan(S.v) + ' ' + C.bold('SQL Statement / Payload:') + ' '.repeat(Math.max(0, innerWidth - 25)) + ' ' + C.cyan(S.v));
  const rawSql = event.statement_preview || '<no statement preview>';
  const sqlLines = rawSql.split('\n');

  for (const sLine of sqlLines) {
    // Word wrap or chunk if line is too wide
    let remaining = sLine;
    while (remaining.length > 0) {
      const chunk = remaining.slice(0, innerWidth - 2);
      remaining = remaining.slice(innerWidth - 2);
      const fitted = C.white(chunk);
      lines.push(C.cyan(S.v) + '   ' + fitted + ' '.repeat(Math.max(0, innerWidth - visibleLength(fitted) - 2)) + C.cyan(S.v));
    }
  }

  // Divider
  lines.push(C.cyan(S.v) + C.dim(S.h.repeat(innerWidth + 2)) + C.cyan(S.v));

  // Hashes
  if (event.statement_fingerprint) {
    addField('Fingerprint', C.dim(event.statement_fingerprint));
  }
  addField('Prev Hash', C.dim(event.prev_hash.slice(0, 32) + '...'));
  addField('Event Hash', C.dim(event.hash.slice(0, 32) + '...'));

  lines.push(C.cyan(S.bl + S.h.repeat(innerWidth + 2) + S.br));
  lines.push(C.dim('  Press Enter, Esc, or q to close detail view'));

  return lines;
}
