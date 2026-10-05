import * as crypto from 'crypto';

// Single-quoted SQL string literals, including escaped quotes ('it''s').
const SQL_STRING_LITERAL = /'(?:[^']|'')*'/g;
// Bare numeric literals outside identifiers.
const SQL_NUMBER_LITERAL = /\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g;
// Postgres duplicate-key detail: Key (email)=(value)
const PG_KEY_VALUE_DETAIL = /=\(([^)]*)\)/g;

/**
 * Replace data-bearing literals with placeholders. Preview text is shipped to
 * the cloud audit store (agent_audit_events.statement_preview), so it must not
 * carry user data — this is a zero-retention boundary, not just truncation.
 */
export function redactSqlLiterals(sql: string): string {
  return sql
    .replace(SQL_STRING_LITERAL, "'?'")
    .replace(SQL_NUMBER_LITERAL, '?')
    .replace(PG_KEY_VALUE_DETAIL, '= (?)');
}

export function fingerprintStatement(sql: string): string {
  // Fingerprint the redacted form so the same logical statement with different
  // literal values maps to one id (literals are not part of the identity).
  const normalized = redactSqlLiterals(sql)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/;\s*$/, '')
    .trim();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex').slice(0, 16);
}

export function previewStatement(sql: string): string {
  const trimmed = redactSqlLiterals(sql.trim());
  return trimmed.length > 200 ? trimmed.slice(0, 200) + '…' : trimmed;
}
