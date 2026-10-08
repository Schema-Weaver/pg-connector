/**
 * Outbound error sanitisation.
 *
 * `Dispatcher.mapErrorToPayload` used to copy PostgreSQL's `message`, `detail`
 * and `hint` straight onto the wire. DETAIL lines routinely carry row data:
 *
 *     ERROR:  duplicate key value violates unique constraint "users_email_key"
 *     DETAIL:  Key (email)=(alice@corp.com) already exists.
 *
 * and `PoolError` messages embed host, port, user and database name. This path
 * had no redaction at all, which made it the most reliable PII leak in the
 * connector.
 *
 * The rules here are deny-by-default:
 *   - only SQLSTATE codes on {@link PG_DETAIL_ALLOWLIST} may contribute
 *     anything other than `code` + `severity`;
 *   - the raw `detail`/`hint` are NEVER forwarded — the hint is always one of
 *     our own strings from {@link PG_CURATED_HINTS};
 *   - anything that does survive is passed through the SQL lexer (which turns
 *     `Key (email)=(…)` into `Key (email)=(?)` and strips literals) and then
 *     through {@link scrubTopology}, which removes hosts, users, database
 *     names, absolute paths, URLs and email addresses.
 */
import { redactSqlLiterals, UNREDACTABLE } from './redact';

export interface SafeDbError {
  code: string;
  severity?: string;
  /** Sanitised, operator-useful message. Never contains row data or topology. */
  message: string;
  /** Optional curated hint, only for codes on a safe allow-list. */
  hint?: string;
  retryable?: boolean;
}

/** Connection parameters whose values must never leave the process. */
export interface SanitizeTopology {
  host?: string;
  port?: number;
  user?: string;
  database?: string;
  project?: string;
}

export interface SanitizeOptions {
  /** Literal/comment redactor. Defaults to `redactSqlLiterals`. */
  redactSql?: (s: string) => string;
  /** Exact connection strings to scrub, when the caller knows them. */
  topology?: SanitizeTopology;
}

/** Upper bound on any message we put on the wire. */
const MAX_MESSAGE_CHARS = 400;

/**
 * SQLSTATE codes for which operator-useful detail text is surfaced.
 *
 * These are all class-22/23 (integrity), class-28 (auth), class-40 (transaction
 * rollback), class-42 (syntax/access), class-53/55 (resource) and 57 (cancel)
 * codes whose text is structural. Anything NOT listed here yields `code` +
 * `severity` + a generic message only.
 */
export const PG_DETAIL_ALLOWLIST: ReadonlySet<string> = new Set([
  '23505', // unique_violation
  '23503', // foreign_key_violation
  '23502', // not_null_violation
  '23514', // check_violation
  '42501', // insufficient_privilege
  '42P01', // undefined_table
  '42703', // undefined_column
  '42883', // undefined_function
  '57014', // query_canceled
  '53300', // too_many_connections
  '55P03', // lock_not_available
  '40001', // serialization_failure
  '40P01', // deadlock_detected
  '3D000', // invalid_catalog_name
  '28P01', // invalid_password
  '28000', // invalid_authorization_specification
  '25P02', // in_failed_sql_transaction
]);

/**
 * Our own one-line description for each SQLSTATE we recognise.
 *
 * These are strings written here, not derived from PostgreSQL output, so they
 * cannot carry row data. Codes that are absent get a generic message that names
 * only the SQLSTATE.
 */
export const PG_CURATED_MESSAGES: Readonly<Record<string, string>> = {
  '22001': 'A value was longer than its column allows.',
  '22003': 'A numeric value was outside the range its column allows.',
  '22007': 'A date or time value is not valid.',
  '22008': 'A date or time value was out of range.',
  '22012': 'Division by zero.',
  '22023': 'A parameter is outside the valid range.',
  '22P02': 'A value could not be converted to the required type.',
  '23502': 'A column that requires a value was given none.',
  '23503': 'A foreign key constraint was violated: the referenced row is missing.',
  '23505': 'A unique constraint was violated: the row already exists.',
  '23514': 'A value failed a check constraint on the table.',
  '23P01': 'No exclusion constraint permits this row.',
  '25000': 'The transaction is in an invalid state for this operation.',
  '25P01': 'The transaction is already aborted.',
  '25P02': 'The current transaction cannot be committed or rolled back in this state.',
  '28000': 'The database refused the operation for this role.',
  '28P01': 'The database rejected the configured credentials.',
  '3D000': 'The requested database does not exist.',
  '40001': 'The transaction lost a serialization conflict. Retry it.',
  '40P01': 'Deadlock detected. The transaction was rolled back.',
  '42501': 'The database refused the operation: insufficient privilege.',
  '42601': 'The statement is not valid PostgreSQL syntax.',
  '42701': 'A column was specified more than once.',
  '42703': 'A referenced column does not exist.',
  '42704': 'The referenced object does not exist.',
  '42710': 'A constraint with that name already exists.',
  '42711': 'A column is defined more than once.',
  '42804': 'A column, function or operator has the wrong type.',
  '42883': 'The referenced function or operator does not exist.',
  '42P01': 'The referenced table or view does not exist.',
  '42P04': 'The requested database does not exist.',
  '42P06': 'The requested schema already exists.',
  '42P07': 'The requested table already exists.',
  '53300': 'The database is out of connection slots.',
  '55P03': 'The target object is currently locked by another transaction.',
  '57014': 'The statement was cancelled or exceeded its timeout.',
  '58030': 'The connection to the server was lost.',
  XX000: 'The database reported an internal error.',
};

/**
 * Our own hints. Never the server's `hint` field — that is attacker-influenced
 * free text in the general case and is not on any allow-list.
 */
export const PG_CURATED_HINTS: Readonly<Record<string, string>> = {
  '23505': 'A row with the same value already exists in a unique column or index.',
  '23503': 'The referenced row is missing, or the child row is still referenced.',
  '23502': 'A NOT NULL column was given NULL.',
  '23514': 'A CHECK constraint rejected the row.',
  '42501': 'The PostgreSQL role used by this agent lacks the required privilege.',
  '42P01': 'Check the schema and table name, or run Introspect to list tables.',
  '42703': 'Check the column name against the table definition.',
  '42883': 'Check the function name and its argument types.',
  '57014': 'The statement hit the configured statement_timeout or was cancelled.',
  '53300': 'Wait for other sessions to finish, or raise the server max_connections.',
  '55P03': 'Another transaction holds a conflicting lock. Retry after it commits.',
  '40001': 'Retry the whole transaction; concurrent updates were detected.',
  '40P01': 'Retry the transaction. Deadlocks are reported, not prevented.',
  '3D000': 'Check the `database` value on this database entry.',
  '28P01': 'Verify the password env var and that the PostgreSQL role can log in.',
  '28000': 'Check the PostgreSQL role and its LOGIN attribute.',
  '25P02': 'The current transaction is aborted; roll back before continuing.',
};

/** Codes where retrying the identical request can succeed. */
export const PG_RETRYABLE_CODES: ReadonlySet<string> = new Set([
  '40001',
  '40P01',
  '53300',
  '55P03',
  '57014',
  '57P03', // cannot_connect_now
  '08000',
  '08003',
  '08006', // connection exceptions
  '58030',
]);

/**
 * Replacement text for `PoolError` codes. The originals interpolate host, port,
 * user and database name, so they are never forwarded verbatim.
 */
export const POOL_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  env_var_missing: 'The database password is not available to the agent.',
  connection_failed: 'Cannot reach the PostgreSQL server for this database.',
  auth_failed: 'PostgreSQL rejected the credentials for this database.',
  db_not_found: 'The configured PostgreSQL database does not exist.',
  ssl_error: 'The TLS handshake with PostgreSQL failed.',
  pool_exhausted: 'The connection pool for this database is exhausted.',
  unsafe_session_setting: 'A session setting this agent requires was rejected.',
};

const GENERIC_MESSAGE = 'The database rejected the request. See the agent log for details.';

/* ------------------------------------------------------------------ */
/* Topology scrubbing                                                   */
/* ------------------------------------------------------------------ */

const SCRUB_RULES: ReadonlyArray<readonly [RegExp, string]> = [
  // Connection URIs: postgres://user:pass@host:5432/db
  [/\b[a-z][a-z0-9+.-]*:\/\/[^\s'")]+/gi, '<url>'],
  // key=value forms used by libpq and the driver
  [/\b(password|passfile|sslpassword)\s*=\s*("[^"]*"|'[^']*'|\S+)/gi, '$1=<redacted>'],
  [
    /\b(user|username|role|database|dbname|host|hostaddr|address|application_name)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)/gi,
    '$1=<redacted>',
  ],
  // prose forms: `for user "app_user"`, `on database "acme"`, `by role bob`
  [
    /\b(user|username|role|database|dbname|host|hostname|address)\s+("[^"]*"|'[^']*')/gi,
    '$1 <redacted>',
  ],
  [
    /\b(for|by|on)\s+(user|role|database|dbname)\s+("[^"]*"|'[^']*'|[^\s,;]+)/gi,
    '$1 $2 <redacted>',
  ],
  // IPv4 / IPv6 literals, with or without a port
  [/\[\s*[0-9A-Fa-f:.]+\s*\](?::\d{1,5})?/g, '<host>'],
  [/\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b/g, '<host>'],
  // a port, which is topology even without the host next to it
  [/:\d{2,5}\b/g, ':<port>'],
  // absolute filesystem paths
  [/(^|[\s"'(=:])(?:\/[A-Za-z0-9._+-]+){2,}/g, '$1<path>'],
  // email addresses (unquoted row values, log lines, NOTICE output)
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g, '<email>'],
  // a DNS name immediately followed by a port, as libpq and the driver print them
  [/\b[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z][A-Za-z0-9-]*:\d{1,5}\b/g, '<host>'],
];

/**
 * Remove hostnames, usernames, database names, URLs, absolute paths and email
 * addresses from text that is about to leave the process.
 */
export function scrubTopology(text: string, topology?: SanitizeTopology): string {
  if (typeof text !== 'string' || text.length === 0) return '';

  let out = text;
  const exact: string[] = [];
  if (topology) {
    for (const value of [topology.host, topology.user, topology.database, topology.project]) {
      // 3 characters is the floor: a shorter value would match inside ordinary
      // words and mangle the message. Leaking beats cosmetic damage, so this
      // is deliberately low.
      if (typeof value === 'string' && value.length >= 3) exact.push(value);
    }
  }
  // Longest first so `db.internal` is removed before `db`.
  exact.sort((a, b) => b.length - a.length);
  for (const value of exact) {
    out = out.split(value).join('<redacted>');
  }

  for (const [re, replacement] of SCRUB_RULES) {
    out = out.replace(re, replacement);
  }
  return collapse(out);
}

function collapse(text: string): string {
  return text.replace(/[ \t]{2,}/g, ' ').trim();
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

/** True when `code` may contribute detail text and a curated hint. */
export function isDetailAllowed(code: string): boolean {
  return PG_DETAIL_ALLOWLIST.has(code);
}

function readString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asRecord(err: unknown): Record<string, unknown> {
  return err !== null && typeof err === 'object' ? (err as Record<string, unknown>) : {};
}

/**
 * Redact + scrub one piece of free text so it can be shown to the operator and
 * shipped to the browser. Quoted identifiers are redacted too, because
 * PostgreSQL quotes row values in messages such as
 * `invalid input syntax for type integer: "alice@corp.com"`.
 */
function cleanText(
  text: string | undefined,
  opts: SanitizeOptions,
  redactIdentifiers = true,
): string | undefined {
  if (!text) return undefined;
  // The strict pass always runs first, so a caller-supplied redactor can never
  // widen the output.
  const first = redactSqlLiterals(text, { redactIdentifiers });
  if (first === UNREDACTABLE) return undefined;
  const second = opts.redactSql ? opts.redactSql(first) : first;
  if (!second || second === UNREDACTABLE) return undefined;
  const scrubbed = scrubTopology(second, opts.topology);
  return scrubbed.length > 0 ? scrubbed : undefined;
}

/**
 * Convert an arbitrary thrown value into a wire-safe error description.
 *
 * Never throws. Never returns row data, credentials, hostnames, usernames,
 * database names or filesystem paths.
 */
export function sanitizePgError(err: unknown, opts: SanitizeOptions = {}): SafeDbError {
  const raw = asRecord(err);
  const code = readString(raw.code) ?? 'UNKNOWN';
  const severity = readString(raw.severity);
  const name = readString(raw.name);
  const message = readString(raw.message) ?? (typeof err === 'string' ? err : undefined);
  const detail = readString(raw.detail);

  const out: SafeDbError = { code, message: '' };
  if (severity) out.severity = severity;

  if (name === 'PoolError') {
    out.message = POOL_ERROR_MESSAGES[code] ?? 'The agent could not use this database connection.';
  } else if (isDetailAllowed(code)) {
    const parts: string[] = [PG_CURATED_MESSAGES[code] ?? 'The database reported an error.'];
    const cleanedMessage = cleanText(message, opts);
    if (cleanedMessage) parts.push(cleanedMessage);
    const cleanedDetail = cleanText(detail, opts);
    if (cleanedDetail) parts.push(cleanedDetail);
    out.message = clamp(parts.join(' '));
    const hint = PG_CURATED_HINTS[code];
    if (hint) out.hint = hint;
  } else {
    out.message = clamp(`Database error (${code}). ${GENERIC_MESSAGE}`);
  }

  if (PG_RETRYABLE_CODES.has(code)) out.retryable = true;
  return out;
}

/**
 * Sanitise a free-text reason that came from our own permission layer. Those
 * strings can embed a parser error, and a parser error embeds the SQL that
 * failed to parse — so identifiers and literals are both redacted here.
 */
export function sanitizeReason(reason: string, opts: SanitizeOptions = {}): string {
  const cleaned = cleanText(reason, opts);
  return cleaned ?? 'Request denied.';
}

/**
 * Sanitise a message that arrived as a bare string (e.g. a migration
 * statement's recorded error) rather than as an error object.
 */
export function sanitizeErrorText(
  text: string | undefined | null,
  opts: SanitizeOptions = {},
): string {
  return cleanText(text ?? undefined, opts) ?? GENERIC_MESSAGE;
}

function clamp(text: string): string {
  const trimmed = collapse(text);
  return trimmed.length > MAX_MESSAGE_CHARS ? trimmed.slice(0, MAX_MESSAGE_CHARS) + '…' : trimmed;
}
