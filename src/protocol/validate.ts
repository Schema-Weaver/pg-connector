/* eslint-disable @typescript-eslint/no-explicit-any */
import { AgentMessage, MessageType, Role } from './envelope';
import { ProtocolError } from './serialize';
import { ERROR_CATALOG } from './errors';
import { LIMITS, PROTOCOL_VERSION } from './constants';

/**
 * Validate the envelope structure (not the payload).
 * Checks: required fields present, types correct, v=1, type is valid enum,
 *         project/user/db_alias/id non-empty, ts is a number.
 * Throws ProtocolError on any failure.
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

  const validTypes: MessageType[] = [
    'ping',
    'introspect',
    'query',
    'stream_query',
    'migration_run',
    'cancel',
    'response',
    'error',
    'stream_chunk',
    'stream_end',
    'event',
  ];
  if (typeof m.type !== 'string' || !validTypes.includes(m.type as MessageType)) {
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
  const validRoles: Role[] = ['admin', 'developer', 'data_reader', 'viewer'];
  if (typeof u.role !== 'string' || !validRoles.includes(u.role as Role)) {
    throw new ProtocolError('invalid_message', `Field "user.role" must be a valid Role: ${u.role}`);
  }

  if (typeof m.db_alias !== 'string' || m.db_alias.length === 0 || m.db_alias.length > LIMITS.ALIAS_MAX_LENGTH) {
    throw new ProtocolError('invalid_message', `Field "db_alias" must be a non-empty string under ${LIMITS.ALIAS_MAX_LENGTH} characters`);
  }

  if (typeof m.ts !== 'number' || isNaN(m.ts) || m.ts <= 0) {
    throw new ProtocolError('invalid_message', 'Field "ts" must be a positive number timestamp');
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

export function validateQueryPayload(p: unknown): void {
  const data = p as Record<string, any>;
  if (typeof data.sql !== 'string' || data.sql.trim().length === 0) {
    throw new ProtocolError('payload_invalid', 'Field "sql" must be a non-empty string');
  }
  if (Buffer.byteLength(data.sql, 'utf8') > LIMITS.MAX_STATEMENT_LENGTH) {
    throw new ProtocolError('payload_invalid', `SQL statement length exceeds limit of ${LIMITS.MAX_STATEMENT_LENGTH} bytes`);
  }
  if (data.params !== undefined && !Array.isArray(data.params)) {
    throw new ProtocolError('payload_invalid', 'Field "params" must be an array');
  }
  if (data.timeout_ms !== undefined && (typeof data.timeout_ms !== 'number' || data.timeout_ms < 0 || isNaN(data.timeout_ms))) {
    throw new ProtocolError('payload_invalid', 'Field "timeout_ms" must be a non-negative number');
  }
  const validIntents = ['read', 'write', 'ddl', 'migration'];
  if (typeof data.intent !== 'string' || !validIntents.includes(data.intent)) {
    throw new ProtocolError('payload_invalid', 'Field "intent" must be read, write, ddl, or migration');
  }
  if (data.intent === 'migration' && (typeof data.plan_id !== 'string' || data.plan_id.length === 0)) {
    throw new ProtocolError('payload_invalid', 'Field "plan_id" is required and must be non-empty when intent is migration');
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

export function validateEventPayload(p: unknown): void {
  const data = p as Record<string, any>;
  const validKinds = ['status_change', 'migration_progress', 'approval_required', 'approval_response', 'warning', 'resume_request', 'plan_register'];
  if (typeof data.kind !== 'string' || !validKinds.includes(data.kind)) {
    throw new ProtocolError('payload_invalid', 'Field "kind" must be a valid EventKind');
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
      if (d.intent !== 'write' && d.intent !== 'ddl' && d.intent !== 'migration') {
        throw new ProtocolError('payload_invalid', 'Field "data.intent" must be write, ddl, or migration');
      }
      if (typeof d.db_alias !== 'string' || d.db_alias.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.db_alias" must be a non-empty string');
      }
      if (typeof d.expires_at !== 'number' || d.expires_at <= 0 || isNaN(d.expires_at)) {
        throw new ProtocolError('payload_invalid', 'Field "data.expires_at" must be a positive number timestamp');
      }
      break;
    }
    case 'approval_response': {
      if (typeof d.request_id !== 'string' || d.request_id.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.request_id" must be a non-empty string');
      }
      if (typeof d.approved !== 'boolean') {
        throw new ProtocolError('payload_invalid', 'Field "data.approved" must be a boolean');
      }
      if (typeof d.approved_by !== 'string' || d.approved_by.length === 0) {
        throw new ProtocolError('payload_invalid', 'Field "data.approved_by" must be a non-empty string');
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
