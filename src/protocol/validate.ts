/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  AgentMessage,
  ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT,
  EVENT_KINDS,
  MESSAGE_TYPES,
  MessageType,
  ROLES,
  Role,
  isRole,
  isValidEnvelopeNonce,
  verifyEnvelopeMac,
} from './envelope';
import { ProtocolError } from './serialize';
import { ERROR_CATALOG } from './errors';
import {
  APPROVAL_NONCE_PATTERN,
  DEFAULTS,
  ENVELOPE_MAC_REQUIRED_DEFAULT,
  LIMITS,
  PROTOCOL_VERSION,
} from './constants';

/**
 * Validate the envelope structure (not the payload).
 * Checks: required fields present, types correct, v=1, type is valid enum,
 *         project/user/db_alias/id non-empty, ts is a number.
 * Throws ProtocolError on any failure.
 *
 * Shape only. This proves the envelope is well-formed, never that its contents
 * are authentic — use `InboundEnvelopeGuard` for that.
 */
export function validateEnvelope(msg: unknown): asserts msg is AgentMessage {
  if (typeof msg !== 'object' || msg === null) {
    throw new ProtocolError('invalid_message', 'Message is not a JSON object');
  }

  const m = msg as Record<string, any>;

  if (m.v === undefined) {
    throw new ProtocolError('invalid_message', 'Version field "v" is missing');
  }
  if (typeof m.v !== 'number') {
    throw new ProtocolError('invalid_message', 'Version field "v" must be a number');
  }
  if (m.v !== PROTOCOL_VERSION) {
    throw new ProtocolError('protocol_version_mismatch', `Protocol version mismatch. Expected ${PROTOCOL_VERSION}, got ${m.v}`);
  }

  if (typeof m.id !== 'string' || m.id.length === 0 || m.id.length > LIMITS.ID_MAX_LENGTH) {
    throw new ProtocolError('invalid_message', `Field "id" must be a non-empty string under ${LIMITS.ID_MAX_LENGTH} characters`);
  }

  if (typeof m.type !== 'string' || !(MESSAGE_TYPES as readonly string[]).includes(m.type)) {
    throw new ProtocolError('unknown_message_type', `Unknown or invalid message type: ${m.type}`);
  }

  if (typeof m.project !== 'string' || m.project.length === 0 || m.project.length > LIMITS.PROJECT_MAX_LENGTH) {
    throw new ProtocolError('invalid_message', `Field "project" must be a non-empty string under ${LIMITS.PROJECT_MAX_LENGTH} characters`);
  }

  if (typeof m.user !== 'object' || m.user === null) {
    throw new ProtocolError('invalid_message', 'Field "user" must be a valid JSON object');
  }
  const u = m.user;
  if (typeof u.id !== 'string' || u.id.length === 0) {
    throw new ProtocolError('invalid_message', 'Field "user.id" must be a non-empty string');
  }
  if (!isRole(u.role)) {
    throw new ProtocolError('invalid_message', `Field "user.role" must be one of: ${ROLES.join(', ')}`);
  }
  if (u.actor_id !== undefined && typeof u.actor_id !== 'string') {
    throw new ProtocolError('invalid_message', 'Field "user.actor_id" must be a string when present');
  }

  if (typeof m.db_alias !== 'string' || m.db_alias.length === 0 || m.db_alias.length > LIMITS.ALIAS_MAX_LENGTH) {
    throw new ProtocolError('invalid_message', `Field "db_alias" must be a non-empty string under ${LIMITS.ALIAS_MAX_LENGTH} characters`);
  }

  if (typeof m.ts !== 'number' || isNaN(m.ts) || m.ts <= 0) {
    throw new ProtocolError('invalid_message', 'Field "ts" must be a positive number timestamp');
  }

  if (m.nonce !== undefined && !isValidEnvelopeNonce(m.nonce)) {
    throw new ProtocolError('invalid_message', 'Field "nonce" must be a 16-64 character [A-Za-z0-9_-] string when present');
  }
  if (m.mac !== undefined && (typeof m.mac !== 'string' || !/^[0-9a-f]{64}$/.test(m.mac))) {
    throw new ProtocolError('invalid_message', 'Field "mac" must be 64 lowercase hex characters when present');
  }
}

/* ------------------------------------------------------------------ */
/* Inbound envelope authentication (C-04)                             */
/* ------------------------------------------------------------------ */

export interface InboundEnvelopeGuardOptions {
  /**
   * Per-session MAC key, from `deriveSessionMacKey({ dataChannelToken, agentId,
   * browserSessionId })`.
   */
  macKey: Buffer;
  /**
   * Roles the cloud negotiated when this session was created. An envelope whose
   * `user.role` is not in this set is rejected even when its MAC is valid: the
   * relay must not be able to escalate a session to a role it did not ask for.
   */
  allowedRoles: readonly Role[];
  /**
   * Reject envelopes that carry no MAC. Defaults to
   * ENVELOPE_MAC_REQUIRED_DEFAULT (true). Only a deliberate machine-config
   * override turns this off; an envelope that does carry a MAC must always
   * verify.
   */
  requireMac?: boolean;
  /** Maximum absolute skew tolerated on `ts`. Defaults to DEFAULTS.ENVELOPE_MAX_CLOCK_SKEW_MS. */
  maxClockSkewMs?: number;
  /**
   * Hard local ceiling on the role a frame may assert, applied in `verify()`
   * AFTER the negotiated-set check. Defaults to
   * ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT (`developer`).
   *
   * This is deliberately independent of `allowedRoles`. A caller that computed
   * the negotiated set wrongly — or that was never told about the operator's
   * ceiling at all — cannot widen this ceiling by widening the set.
   */
  maxNegotiableRole?: Role;
  /** Replay cache capacity. Defaults to LIMITS.REPLAY_CACHE_MAX_ENTRIES. */
  replayCacheEntries?: number;
  /** Clock injection point for tests. Defaults to `Date.now`. */
  now?: () => number;
}

/**
 * Fails an envelope closed on: a bad or missing MAC, a stale `ts`, a replayed
 * `nonce`, a `user.role` that was not negotiated for this session, or a
 * `user.role` above this installation's local ceiling.
 *
 * Every rejection throws a fatal ProtocolError; there is no "log and proceed"
 * path. Call `verify` on the *inbound* path only, before the message reaches the
 * dispatcher — after this point `msg.user.role` may be treated as an
 * authenticated fact rather than a claim.
 */
export class InboundEnvelopeGuard {
  private readonly opts: Required<
    Pick<
      InboundEnvelopeGuardOptions,
      | 'macKey'
      | 'allowedRoles'
      | 'requireMac'
      | 'maxClockSkewMs'
      | 'maxNegotiableRole'
      | 'replayCacheEntries'
      | 'now'
    >
  >;
  /** nonce -> `ts` at first sight. Insertion-ordered so eviction is FIFO. */
  private readonly seenNonces = new Map<string, number>();

  constructor(options: InboundEnvelopeGuardOptions) {
    this.opts = {
      macKey: options.macKey,
      allowedRoles: Object.freeze([...options.allowedRoles]),
      requireMac: options.requireMac ?? ENVELOPE_MAC_REQUIRED_DEFAULT,
      maxClockSkewMs: options.maxClockSkewMs ?? DEFAULTS.ENVELOPE_MAX_CLOCK_SKEW_MS,
      // An invalid configured ceiling falls back to the default rather than
      // failing open to `admin`.
      maxNegotiableRole: isRole(options.maxNegotiableRole)
        ? options.maxNegotiableRole
        : ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT,
      replayCacheEntries: options.replayCacheEntries ?? LIMITS.REPLAY_CACHE_MAX_ENTRIES,
      now: options.now ?? Date.now,
    };
  }

  /** Roles this guard will accept. */
  getAllowedRoles(): Role[] {
    return [...this.opts.allowedRoles];
  }

  /**
   * The local role ceiling this guard enforces, whatever it was handed as
   * `allowedRoles`. Reported so an operator surface (`sw-agent status`,
   * `doctor`) can state the effective bound rather than the negotiated set.
   */
  getMaxNegotiableRole(): Role {
    return this.opts.maxNegotiableRole;
  }

  /** Number of nonces currently held in the replay cache. */
  replayCacheSize(): number {
    return this.seenNonces.size;
  }

  /** Forget every seen nonce. Call when the session ends or rolls over. */
  reset(): void {
    this.seenNonces.clear();
  }

  /**
   * Authenticate and admit one inbound envelope, or throw. Checks run cheapest
   * and most decisive first: nonce shape, freshness, MAC, replay, negotiated role.
   */
  verify(msg: AgentMessage): void {
    if (!isValidEnvelopeNonce(msg.nonce)) {
      throw new ProtocolError(
        'invalid_message',
        'Envelope "nonce" is missing or malformed; a fresh anti-replay nonce is required',
      );
    }

    const now = this.opts.now();
    if (Math.abs(now - msg.ts) > this.opts.maxClockSkewMs) {
      throw new ProtocolError(
        'invalid_message',
        `Envelope "ts" is outside the ${this.opts.maxClockSkewMs}ms freshness window`,
      );
    }

    if (msg.mac === undefined) {
      if (this.opts.requireMac) {
        throw new ProtocolError('invalid_message', 'Envelope "mac" is required but missing');
      }
    } else if (!verifyEnvelopeMac(this.opts.macKey, msg)) {
      throw new ProtocolError('invalid_message', 'Envelope "mac" does not verify for this session');
    }

    if (this.seenNonces.has(msg.nonce)) {
      throw new ProtocolError('invalid_message', 'Envelope "nonce" has already been used in this session');
    }
    this.seenNonces.set(msg.nonce, now);
    while (this.seenNonces.size > this.opts.replayCacheEntries) {
      const oldest = this.seenNonces.keys().next();
      if (oldest.done) {
        break;
      }
      this.seenNonces.delete(oldest.value);
    }

    if (!this.opts.allowedRoles.includes(msg.user.role)) {
      throw new ProtocolError(
        'permission_denied',
        `Field "user.role" (${msg.user.role}) was not negotiated for this session`,
      );
    }

    // Hard local ceiling, applied AFTER the negotiated-set check.
    //
    // The negotiated set is the relay's claim about what the session may do;
    // this is the operator's bound on how much of that claim to believe. A
    // valid MAC proves the frame came from the session, not that the session was
    // allowed to assert `admin`. Without this check the declared
    // `security.max_negotiable_role` had no reader at all, and a compromised
    // relay had the full capability set on every configured database.
    //
    // `ROLES` is ordered most- to least-privileged, so a role is within the
    // ceiling when its index is greater than or equal to the ceiling's.
    if (ROLES.indexOf(msg.user.role) < ROLES.indexOf(this.opts.maxNegotiableRole)) {
      throw new ProtocolError(
        'role_above_ceiling',
        `Field "user.role" (${msg.user.role}) is above this installation's negotiated-role ceiling ` +
          `("${this.opts.maxNegotiableRole}"); raise security.max_negotiable_role in the machine ` +
          'config if that is intended',
      );
    }
  }
}

/**
 * Validate the payload for a given message type.
 * Each type has its own validator.
 * Throws ProtocolError with code 'payload_invalid' on failure.
 */
export function validatePayload(type: MessageType, payload: unknown): void {
  if (typeof payload !== 'object' || payload === null) {
    throw new ProtocolError('payload_invalid', 'Payload must be a JSON object');
  }

  switch (type) {
    case 'ping':
      validatePingPayload(payload);
      break;
    case 'introspect':
      validateIntrospectPayload(payload);
      break;
    case 'query':
      validateQueryPayload(payload);
      break;
    case 'stream_query':
      validateStreamQueryPayload(payload);
      break;
    case 'stream_chunk':
      validateStreamChunkPayload(payload);
      break;
    case 'stream_end':
      validateStreamEndPayload(payload);
      break;
    case 'migration_run':
      validateMigrationRunPayload(payload);
      break;
    case 'cancel':
      validateCancelPayload(payload);
      break;
    case 'response':
      validateResponsePayload(payload);
      break;
    case 'error':
      validateErrorPayload(payload);
      break;
    case 'event':
      validateEventPayload(payload);
      break;
    default:
      throw new ProtocolError('unknown_message_type', `Cannot validate payload for unknown type: ${type}`);
  }
}

/**
 * Convenience: validate envelope + payload together.
 */
export function validateMessage(msg: unknown): asserts msg is AgentMessage {
  validateEnvelope(msg);
  validatePayload(msg.type, msg.payload);
}

export function validatePingPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.sent_at !== 'number' || data.sent_at <= 0 || isNaN(data.sent_at)) {
    throw new ProtocolError('payload_invalid', 'Field "sent_at" must be a positive number timestamp');
  }
  if (data.sender_id !== undefined && typeof data.sender_id !== 'string') {
    throw new ProtocolError('payload_invalid', 'Field "sender_id" must be a string if provided');
  }
}

export function validateIntrospectPayload(p: unknown): void {
  const data = p as Record<string, any>;
  const boolKeys = ['include_views', 'include_indexes', 'include_triggers', 'include_partitions', 'include_extensions'];
  for (const key of boolKeys) {
    if (typeof data[key] !== 'boolean') {
      throw new ProtocolError('payload_invalid', `Field "${key}" must be a boolean`);
    }
  }
  if (data.pg_version_hint !== null && typeof data.pg_version_hint !== 'string') {
    throw new ProtocolError('payload_invalid', 'Field "pg_version_hint" must be a string or null');
  }
}

/* ------------------------------------------------------------------ */
/* SQL statement counting (cheap protocol-level early rejection)        */
/* ------------------------------------------------------------------ */

const IDENT_CHAR = /[A-Za-z0-9_$\u0080-\uffff]/;
const QUOTE_PREFIXES = new Set(['b', 'B', 'e', 'E', 'x', 'X', 'n', 'N']);

/**
 * Count the top-level statements in a SQL string.
 *
 * This is a lexical scan, not a parser, and it is written to be sound over the
 * constructs an attacker would use to hide a `;` from it:
 *
 *   - `'...'` string constants, where `''` is an escaped quote;
 *   - `E'...'` / `B'...'` / `X'...'` / `N'...'` prefixed constants;
 *   - `U&'...'` unicode constants, whose escapes are backslash sequences, plus
 *     the optional trailing `UESCAPE '<char>'` clause;
 *   - dollar quoting, both `$$...$$` and `$tag$...$tag$`;
 *   - `"..."` quoted identifiers, where `""` is an escaped double quote;
 *   - `-- ...` line comments and nestable slash-star block comments;
 *
 * `\` is treated as an escape inside `E'...'` / `U&'...'` only, matching
 * PostgreSQL's default `standard_conforming_strings = on`. If that GUC is ever
 * turned off on a pooled connection the plain-string rule below would differ
 * from the server's; pinning it at acquire time (Group 1 owns `pool.ts`) closes
 * that, and `src/execution/sql-parser.ts` (Group 2) is the authoritative check.
 *
 * Unterminated literals, dollar quotes, identifiers and block comments throw
 * rather than guessing: a construct this scan cannot account for is one it
 * cannot rule a hidden `;` out of.
 */
export function countSqlStatements(sql: string, field = 'sql'): number {
  const len = sql.length;
  let i = 0;
  let statements = 0;
  let segmentHasContent = false;

  while (i < len) {
    const c = sql[i];

    if (c === '-' && sql[i + 1] === '-') {
      while (i < len && sql[i] !== '\n') {
        i++;
      }
      continue;
    }

    if (c === '/' && sql[i + 1] === '*') {
      let depth = 1;
      i += 2;
      while (i < len && depth > 0) {
        if (sql[i] === '/' && sql[i + 1] === '*') {
          depth++;
          i += 2;
        } else if (sql[i] === '*' && sql[i + 1] === '/') {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      if (depth > 0) {
        throw new ProtocolError('unparseable_statement', `Field "${field}" contains an unterminated block comment`);
      }
      continue;
    }

    if (c === '$') {
      const tagEnd = readDollarQuoteTag(sql, i);
      if (tagEnd > 0) {
        const opening = sql.slice(i, tagEnd);
        const closing = sql.indexOf(opening, tagEnd);
        if (closing === -1) {
          throw new ProtocolError('unparseable_statement', `Field "${field}" contains an unterminated dollar-quoted string`);
        }
        i = closing + opening.length;
      } else {
        i++;
      }
      segmentHasContent = true;
      continue;
    }

    if (c === "'") {
      i = scanQuoted(sql, i + 1, "'", false, field);
      segmentHasContent = true;
      continue;
    }

    if (c === '"') {
      i = scanQuoted(sql, i + 1, '"', false, field);
      segmentHasContent = true;
      continue;
    }

    const prefixEnd = scanStringPrefix(sql, i);
    if (prefixEnd > 0) {
      const prefix = sql.slice(i, prefixEnd).toLowerCase();
      if (prefix === 'u&') {
        const end = scanQuoted(sql, prefixEnd + 1, "'", true, field);
        i = end;
        if (sql.slice(i, i + 8).toUpperCase() === 'UESCAPE') {
          let j = i + 8;
          while (j < len && /\s/.test(sql[j])) {
            j++;
          }
          if (sql[j] === "'") {
            i = scanQuoted(sql, j + 1, "'", true, field);
          }
        }
      } else {
        i = scanQuoted(sql, prefixEnd + 1, "'", true, field);
      }
      segmentHasContent = true;
      continue;
    }

    if (c === ';') {
      if (segmentHasContent) {
        statements++;
      }
      segmentHasContent = false;
      i++;
      continue;
    }

    if (!/\s/.test(c)) {
      segmentHasContent = true;
    }
    i++;
  }

  if (segmentHasContent) {
    statements++;
  }
  return statements;
}

/**
 * Reject anything that is not exactly one statement. A single trailing `;`
 * terminator is allowed (`SELECT 1;` is one statement); a second statement is
 * not, whatever separates them.
 */
export function assertSingleStatement(sql: string, field = 'sql'): void {
  const count = countSqlStatements(sql, field);
  if (count > LIMITS.MAX_STATEMENT_COUNT_PER_QUERY) {
    throw new ProtocolError(
      'multiple_statements',
      `Field "${field}" must contain at most ${LIMITS.MAX_STATEMENT_COUNT_PER_QUERY} statement, found ${count}`,
    );
  }
}

/** End index (exclusive) of a `$tag$` / `$$` delimiter starting at `start`, or -1. */
function readDollarQuoteTag(sql: string, start: number): number {
  let i = start + 1;
  if (i < sql.length && sql[i] === '$') {
    return i + 1;
  }
  if (i >= sql.length || !/[A-Za-z_]/.test(sql[i])) {
    return -1;
  }
  i++;
  while (i < sql.length && /[A-Za-z0-9_]/.test(sql[i])) {
    i++;
  }
  return i < sql.length && sql[i] === '$' ? i + 1 : -1;
}

/**
 * End index (exclusive) of the quoted run that starts just after `from`, where
 * the run ends at `close` or `close` doubled up. `backslashEscapes` selects the
 * `E'...'` / `U&'...'` rule, where a backslash escapes the next character.
 */
function scanQuoted(
  sql: string,
  from: number,
  close: string,
  backslashEscapes: boolean,
  field: string,
): number {
  const len = sql.length;
  const label = close === "'" ? 'string literal' : 'quoted identifier';
  let i = from;
  while (i < len) {
    const c = sql[i];
    if (backslashEscapes && c === '\\') {
      i += 2;
      continue;
    }
    if (c === close) {
      if (sql[i + 1] === close) {
        i += 2;
        continue;
      }
      return i + 1;
    }
    i++;
  }
  throw new ProtocolError('unparseable_statement', `Field "${field}" contains an unterminated ${label}`);
}

/**
 * End index (exclusive) of a string-constant prefix at `start`
 * (`E`, `X`, `B`, `N`, or the two characters of `U&`), or -1 when `start` does
 * not begin one. A prefix is only a prefix when it is not preceded by an
 * identifier character, so `someE'x'` stays a bare word.
 */
function scanStringPrefix(sql: string, start: number): number {
  const c = sql[start];
  if (start > 0 && IDENT_CHAR.test(sql[start - 1])) {
    return -1;
  }
  if (c === 'u' || c === 'U') {
    return sql[start + 1] === '&' ? start + 2 : -1;
  }
  return QUOTE_PREFIXES.has(c) && sql[start + 1] === "'" ? start + 1 : -1;
}

export function validateQueryPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.sql !== 'string' || data.sql.trim().length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "sql" must be a non-empty string');
  }
  if (Buffer.byteLength(data.sql, 'utf8') > LIMITS.MAX_STATEMENT_LENGTH) {
    throw new ProtocolError('payload_invalid', `SQL statement length exceeds limit of ${LIMITS.MAX_STATEMENT_LENGTH} bytes`);
  }
  assertSingleStatement(data.sql, 'sql');
  if (data.params !== undefined && !Array.isArray(data.params)) {
    throw new ProtocolError('payload_invalid', 'Field "params" must be an array');
  }
  if (data.timeout_ms !== undefined && (typeof data.timeout_ms !== 'number' || data.timeout_ms < 0 || isNaN(data.timeout_ms))) {
    throw new ProtocolError('payload_invalid', 'Field "timeout_ms" must be a non-negative number');
  }
  // `migration` is not a legal intent for a query/stream_query message. It used
  // to be accepted here and, on the permission side, that one value skipped the
  // "claimed intent must match the classified statement" comparison entirely.
  const validIntents = ['read', 'write', 'ddl'];
  if (typeof data.intent !== 'string' || !validIntents.includes(data.intent)) {
    throw new ProtocolError('payload_invalid', 'Field "intent" must be read, write, or ddl');
  }
  if (data.plan_id !== undefined && typeof data.plan_id !== 'string') {
    throw new ProtocolError('payload_invalid', 'Field "plan_id" must be a string');
  }
}

export function validateStreamQueryPayload(p: unknown): void {
  // Validate standard Query fields first
  validateQueryPayload(p);
  const data = p as Record<string, any>;
  
  if (data.cursor !== undefined) {
    if (typeof data.cursor !== 'object' || data.cursor === null) {
      throw new ProtocolError('payload_invalid', 'Field "cursor" must be an object');
    }
    const c = data.cursor;
    if (typeof c.column !== 'string' || c.column.length === 0) {
      throw new ProtocolError('payload_invalid', 'Field "cursor.column" must be a non-empty string');
    }
    if (c.last_value === undefined) {
      throw new ProtocolError('payload_invalid', 'Field "cursor.last_value" must be defined');
    }
    if (c.direction !== 'forward' && c.direction !== 'backward') {
      throw new ProtocolError('payload_invalid', 'Field "cursor.direction" must be forward or backward');
    }
  }

  if (data.page_size !== undefined) {
    if (typeof data.page_size !== 'number' || !Number.isInteger(data.page_size) || data.page_size < 1 || data.page_size > 1000) {
      throw new ProtocolError('payload_invalid', 'Field "page_size" must be an integer between 1 and 1000');
    }
  }
}

export function validateStreamChunkPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.request_id !== 'string' || data.request_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "request_id" must be a non-empty string');
  }
  if (data.columns !== null && !Array.isArray(data.columns)) {
    throw new ProtocolError('payload_invalid', 'Field "columns" must be an array or null');
  }
  if (data.columns !== null && Array.isArray(data.columns)) {
    data.columns.forEach((col: any, idx: number) => {
      if (typeof col !== 'object' || col === null) {
        throw new ProtocolError('payload_invalid', `Field "columns[${idx}]" must be a JSON object`);
      }
      if (typeof col.name !== 'string' || col.name.length === 0) {
        throw new ProtocolError('payload_invalid', `Field "columns[${idx}].name" must be a non-empty string`);
      }
      if (typeof col.type_oid !== 'number') {
        throw new ProtocolError('payload_invalid', `Field "columns[${idx}].type_oid" must be a number`);
      }
      if (typeof col.type_name !== 'string' || col.type_name.length === 0) {
        throw new ProtocolError('payload_invalid', `Field "columns[${idx}].type_name" must be a non-empty string`);
      }
    });
  }
  if (!Array.isArray(data.rows)) {
    throw new ProtocolError('payload_invalid', 'Field "rows" must be an array');
  }
  data.rows.forEach((row: any, idx: number) => {
    if (!Array.isArray(row)) {
      throw new ProtocolError('payload_invalid', `Field "rows[${idx}]" must be an array`);
    }
  });
  if (typeof data.chunk_index !== 'number' || data.chunk_index < 0 || !Number.isInteger(data.chunk_index)) {
    throw new ProtocolError('payload_invalid', 'Field "chunk_index" must be a non-negative integer');
  }
  if (typeof data.has_truncated_cells !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "has_truncated_cells" must be a boolean');
  }
}

export function validateStreamEndPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.request_id !== 'string' || data.request_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "request_id" must be a non-empty string');
  }
  const nonNegInts = ['total_rows', 'ms', 'chunk_count'];
  for (const key of nonNegInts) {
    if (typeof data[key] !== 'number' || data[key] < 0 || !Number.isInteger(data[key])) {
      throw new ProtocolError('payload_invalid', `Field "${key}" must be a non-negative integer`);
    }
  }
  if (typeof data.truncated !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "truncated" must be a boolean');
  }
}

export function validateMigrationRunPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.plan_id !== 'string' || data.plan_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "plan_id" must be a non-empty string');
  }
  if (!Array.isArray(data.statements) || data.statements.length === 0 || data.statements.length > LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION) {
    throw new ProtocolError('payload_invalid', `Field "statements" must be a non-empty array under ${LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION} items`);
  }
  data.statements.forEach((stmt: any, idx: number) => {
    if (typeof stmt !== 'string' || stmt.trim().length === 0) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}]" must be a non-empty string`);
    }
    if (Buffer.byteLength(stmt, 'utf8') > LIMITS.MAX_STATEMENT_LENGTH) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}]" length exceeds limit of ${LIMITS.MAX_STATEMENT_LENGTH} bytes`);
    }
  });
  if (data.strategy !== 'single_tx' && data.strategy !== 'per_statement') {
    throw new ProtocolError('payload_invalid', 'Field "strategy" must be single_tx or per_statement');
  }
  if (data.timeout_ms !== undefined && (typeof data.timeout_ms !== 'number' || data.timeout_ms <= 0 || isNaN(data.timeout_ms))) {
    throw new ProtocolError('payload_invalid', 'Field "timeout_ms" must be a positive number');
  }
  if (typeof data.dry_run !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "dry_run" must be a boolean');
  }
}

export function validateMigrationResultPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.plan_id !== 'string' || data.plan_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "plan_id" must be a non-empty string');
  }
  const validStatuses = ['committed', 'rolled_back', 'partial', 'dry_run_ok', 'dry_run_failed'];
  if (typeof data.status !== 'string' || !validStatuses.includes(data.status)) {
    throw new ProtocolError('payload_invalid', 'Field "status" must be committed, rolled_back, partial, dry_run_ok, or dry_run_failed');
  }
  if (!Array.isArray(data.statements)) {
    throw new ProtocolError('payload_invalid', 'Field "statements" must be an array');
  }
  const validStmtStatuses = ['pending', 'running', 'success', 'failed', 'rolled_back'];
  data.statements.forEach((stmt: any, idx: number) => {
    if (typeof stmt !== 'object' || stmt === null) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}]" must be an object`);
    }
    if (typeof stmt.index !== 'number' || stmt.index < 0 || !Number.isInteger(stmt.index)) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].index" must be a non-negative integer`);
    }
    if (typeof stmt.status !== 'string' || !validStmtStatuses.includes(stmt.status)) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].status" must be pending, running, success, failed, or rolled_back`);
    }
    if (typeof stmt.ms !== 'number' || stmt.ms < 0 || isNaN(stmt.ms)) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].ms" must be a non-negative number`);
    }
    if (typeof stmt.rows_affected !== 'number' || !Number.isInteger(stmt.rows_affected)) {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].rows_affected" must be an integer`);
    }
    if (stmt.error !== undefined && typeof stmt.error !== 'string') {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].error" must be a string`);
    }
    if (stmt.pg_error_code !== undefined && typeof stmt.pg_error_code !== 'string') {
      throw new ProtocolError('payload_invalid', `Field "statements[${idx}].pg_error_code" must be a string`);
    }
  });

  if (typeof data.total_ms !== 'number' || data.total_ms < 0 || isNaN(data.total_ms)) {
    throw new ProtocolError('payload_invalid', 'Field "total_ms" must be a non-negative number');
  }
  if (!Array.isArray(data.rolled_back_indices)) {
    throw new ProtocolError('payload_invalid', 'Field "rolled_back_indices" must be an array');
  }
  data.rolled_back_indices.forEach((val: any, idx: number) => {
    if (typeof val !== 'number' || !Number.isInteger(val)) {
      throw new ProtocolError('payload_invalid', `Field "rolled_back_indices[${idx}]" must be an integer`);
    }
  });
  if (data.strategy_changed_from !== undefined && data.strategy_changed_from !== 'single_tx' && data.strategy_changed_from !== 'per_statement') {
    throw new ProtocolError('payload_invalid', 'Field "strategy_changed_from" must be single_tx or per_statement');
  }
}

export function validateCancelPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.target_id !== 'string' || data.target_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "target_id" must be a non-empty string');
  }
  const validReasons = ['user_cancelled', 'timeout', 'session_closed', 'orphaned'];
  if (typeof data.reason !== 'string' || !validReasons.includes(data.reason)) {
    throw new ProtocolError('payload_invalid', 'Field "reason" must be user_cancelled, timeout, session_closed, or orphaned');
  }
}

export function validateCancelResultPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.target_id !== 'string' || data.target_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "target_id" must be a non-empty string');
  }
  if (typeof data.cancelled !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "cancelled" must be a boolean');
  }
  if (typeof data.terminated !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "terminated" must be a boolean');
  }
  if (data.reason !== undefined && typeof data.reason !== 'string') {
    throw new ProtocolError('payload_invalid', 'Field "reason" must be a string');
  }
}

export function validateResponsePayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.request_id !== 'string' || data.request_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "request_id" must be a non-empty string');
  }
  if (typeof data.ok !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "ok" must be a boolean');
  }
  if (data.data === undefined) {
    throw new ProtocolError('payload_invalid', 'Field "data" must be defined');
  }
  if (data.ms !== undefined && (typeof data.ms !== 'number' || data.ms < 0 || isNaN(data.ms))) {
    throw new ProtocolError('payload_invalid', 'Field "ms" must be a non-negative number');
  }
}

export function validateErrorPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.request_id !== 'string' || data.request_id.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "request_id" must be a non-empty string');
  }
  if (typeof data.code !== 'string' || !(data.code in ERROR_CATALOG)) {
    throw new ProtocolError('payload_invalid', `Field "code" must be a valid ErrorCode: ${data.code}`);
  }
  if (typeof data.message !== 'string' || data.message.length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "message" must be a non-empty string');
  }
  if (data.pg_error !== undefined && data.pg_error !== null) {
    if (typeof data.pg_error !== 'object') {
      throw new ProtocolError('payload_invalid', 'Field "pg_error" must be an object');
    }
    const pg = data.pg_error;
    if (typeof pg.code !== 'string' || pg.code.length === 0) {
      throw new ProtocolError('payload_invalid', 'Field "pg_error.code" must be a non-empty string');
    }
    if (typeof pg.severity !== 'string' || pg.severity.length === 0) {
      throw new ProtocolError('payload_invalid', 'Field "pg_error.severity" must be a non-empty string');
    }
    if (pg.detail !== undefined && typeof pg.detail !== 'string') {
      throw new ProtocolError('payload_invalid', 'Field "pg_error.detail" must be a string');
    }
    if (pg.hint !== undefined && typeof pg.hint !== 'string') {
      throw new ProtocolError('payload_invalid', 'Field "pg_error.hint" must be a string');
    }
    if (pg.position !== undefined && (typeof pg.position !== 'number' || !Number.isInteger(pg.position))) {
      throw new ProtocolError('payload_invalid', 'Field "pg_error.position" must be an integer');
    }
  }
  if (typeof data.fatal !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "fatal" must be a boolean');
  }
  if (typeof data.retryable !== 'boolean') {
    throw new ProtocolError('payload_invalid', 'Field "retryable" must be a boolean');
  }
}

/**
 * An approval nonce is `crypto.randomBytes(32)` in lowercase hex: exactly 64 hex
 * characters and nothing else. The agent mints it and compares the returned value
 * against its own copy, so any looser shape (truncated, padded, non-hex, or a
 * different length entirely) must be refused at the protocol boundary.
 */
function assertApprovalNonce(value: unknown, field: string): void {
  if (typeof value !== 'string' || !APPROVAL_NONCE_PATTERN.test(value)) {
    throw new ProtocolError(
      'payload_invalid',
      `Field "${field}" must be ${LIMITS.APPROVAL_NONCE_HEX_LENGTH} lowercase hex characters (32 bytes)`,
    );
  }
}

export function validateEventPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.kind !== 'string' || !(EVENT_KINDS as readonly string[]).includes(data.kind)) {
    throw new ProtocolError('payload_invalid', `Field "kind" must be one of: ${EVENT_KINDS.join(', ')}`);
  }
  if (typeof data.data !== 'object' || data.data === null) {
    throw new ProtocolError('payload_invalid', 'Field "data" must be a JSON object');
  }
  const d = data.data;

  switch (data.kind) {
    case 'status_change': {
      const validStatuses = ['online', 'offline', 'degraded', 'maintenance'];
      if (typeof d.new_status !== 'string' || !validStatuses.includes(d.new_status)) {
        throw new ProtocolError('payload_invalid', 'Field "data.new_status" must be online, offline, degraded, or maintenance');
      }
      if (d.reason !== undefined && typeof d.reason !== 'string') {
        throw new ProtocolError('payload_invalid', 'Field "data.reason" must be a string');
      }
      break;
    }
    case 'migration_progress': {
      if (typeof d.plan_id !== 'string' || d.plan_id.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.plan_id" must be a non-empty string');
      }
      if (typeof d.statement_index !== 'number' || d.statement_index < 0 || !Number.isInteger(d.statement_index)) {
        throw new ProtocolError('payload_invalid', 'Field "data.statement_index" must be a non-negative integer');
      }
      if (typeof d.statement_sql_preview !== 'string') {
        throw new ProtocolError('payload_invalid', 'Field "data.statement_sql_preview" must be a string');
      }
      const validStmtStatuses = ['pending', 'running', 'success', 'failed', 'rolled_back'];
      if (typeof d.status !== 'string' || !validStmtStatuses.includes(d.status)) {
        throw new ProtocolError('payload_invalid', 'Field "data.status" must be pending, running, success, failed, or rolled_back');
      }
      if (d.ms !== undefined && (typeof d.ms !== 'number' || d.ms < 0 || isNaN(d.ms))) {
        throw new ProtocolError('payload_invalid', 'Field "data.ms" must be a non-negative number');
      }
      if (d.error !== undefined && typeof d.error !== 'string') {
        throw new ProtocolError('payload_invalid', 'Field "data.error" must be a string');
      }
      if (d.replayed !== undefined && typeof d.replayed !== 'boolean') {
        throw new ProtocolError('payload_invalid', 'Field "data.replayed" must be a boolean');
      }
      break;
    }
    case 'approval_required': {
      if (typeof d.request_id !== 'string' || d.request_id.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.request_id" must be a non-empty string');
      }
      if (typeof d.sql !== 'string' || d.sql.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.sql" must be a non-empty string');
      }
      if (typeof d.sql_preview !== 'string') {
        throw new ProtocolError('payload_invalid', 'Field "data.sql_preview" must be a string');
      }
      if (d.intent !== 'write' && d.intent !== 'ddl') {
        throw new ProtocolError('payload_invalid', 'Field "data.intent" must be write or ddl');
      }
      if (typeof d.db_alias !== 'string' || d.db_alias.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.db_alias" must be a non-empty string');
      }
      if (typeof d.expires_at !== 'number' || d.expires_at <= 0 || isNaN(d.expires_at)) {
        throw new ProtocolError('payload_invalid', 'Field "data.expires_at" must be a positive number timestamp');
      }
      assertApprovalNonce(d.approval_nonce, 'data.approval_nonce');
      break;
    }
    case 'approval_response': {
      if (typeof d.request_id !== 'string' || d.request_id.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.request_id" must be a non-empty string');
      }
      if (typeof d.approved !== 'boolean') {
        throw new ProtocolError('payload_invalid', 'Field "data.approved" must be a boolean');
      }
      // The nonce is minted by the agent and must come back verbatim. Shape is
      // all that can be checked here; proving the sender is the right person is
      // the dispatcher's job, and it must compare against its own copy.
      assertApprovalNonce(d.approval_nonce, 'data.approval_nonce');
      // `approved_by` is display-only. It carries no authority — the approver is
      // taken from the authenticated envelope — so it is bounded but otherwise
      // untrusted, and its absence is not an error.
      if (
        d.approved_by !== undefined &&
        (typeof d.approved_by !== 'string' || d.approved_by.length === 0 || d.approved_by.length > LIMITS.ID_MAX_LENGTH)
      ) {
        throw new ProtocolError(
          'payload_invalid',
          `Field "data.approved_by" must be a 1-${LIMITS.ID_MAX_LENGTH} character string when present`,
        );
      }
      break;
    }
    case 'warning': {
      if (typeof d.code !== 'string' || d.code.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.code" must be a non-empty string');
      }
      if (typeof d.message !== 'string' || d.message.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.message" must be a non-empty string');
      }
      if (d.context !== undefined && (typeof d.context !== 'object' || d.context === null)) {
        throw new ProtocolError('payload_invalid', 'Field "data.context" must be an object');
      }
      break;
    }
    case 'resume_request': {
      if (typeof d.request_id !== 'string' || d.request_id.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.request_id" must be a non-empty string');
      }
      break;
    }
    case 'plan_register': {
      if (!Array.isArray(d.statements)) {
        throw new ProtocolError('payload_invalid', 'Field "data.statements" must be an array of SQL strings');
      }
      for (let i = 0; i < d.statements.length; i++) {
        if (typeof d.statements[i] !== 'string') {
          throw new ProtocolError('payload_invalid', `Field "data.statements[${i}]" must be a string`);
        }
      }
      if (d.risk_level !== undefined && d.risk_level !== 'low' && d.risk_level !== 'medium' && d.risk_level !== 'high') {
        throw new ProtocolError('payload_invalid', 'Field "data.risk_level" must be low, medium, or high');
      }
      break;
    }
  }
}
