import { ErrorPayload } from './messages';

export type ErrorCode =
  // Protocol-level errors
  | 'invalid_message'           // envelope malformed, missing fields, bad version
  | 'unknown_message_type'      // type field has invalid value
  | 'payload_invalid'           // payload doesn't match expected schema for type
  | 'protocol_version_mismatch' // v field is not 1

  // Auth errors
  | 'auth_failed'               // token invalid or expired
  | 'token_expired'             // specifically: token TTL exceeded
  | 'permission_denied'         // user.role or permission_level blocks this action
  | 'role_insufficient'         // viewer/data_reader tried to write
  | 'approval_timeout'          // manual approval not given in 60s
  | 'approval_denied'           // user explicitly denied approval
  | 'MANUAL_APPROVAL_TIMEOUT'   // manual approval timed out
  | 'MANUAL_APPROVAL_REJECTED'  // manual approval explicitly rejected

  // DB connection errors
  | 'db_unavailable'            // can't reach DB (network/firewall)
  | 'db_auth_failed'            // PG rejected credentials
  | 'db_not_found'              // db_alias doesn't exist in config
  | 'db_pool_exhausted'         // pool at max connections
  | 'db_ssl_error'              // TLS handshake failed

  // Migration errors
  | 'migration_in_progress'     // another migration running on same project
  | 'migration_plan_not_registered'  // plan_id not pre-registered with cloud
  | 'migration_statement_failed'     // a statement in the plan errored
  | 'migration_rolled_back'          // tx rolled back (informational)
  | 'migration_partial'              // per_statement mode, some committed some failed

  // Query errors
  | 'query_timeout'             // statement_timeout exceeded
  | 'query_cancelled'           // pg_cancel_backend succeeded
  | 'query_too_large'           // result exceeded MAX_QUERY_ROWS
  | 'stream_too_large'          // result exceeded MAX_STREAM_ROWS
  | 'STREAM_ROW_LIMIT'
  | 'CELL_SIZE_LIMIT'

  // Cancellation
  | 'cancel_failed'             // couldn't cancel (query already done?)
  | 'cancel_target_not_found'   // target_id doesn't match any in-flight request

  // Concurrency
  | 'concurrent_request_rejected'  // queue full

  // Lifecycle
  | 'orphaned_request'          // no reconnect in ORPHAN_REQUEST_TIMEOUT_MS
  | 'channel_closed'            // WSS closed unexpectedly
  | 'rate_limited'              // too many requests from this browser session

  // Config errors
  | 'config_invalid'            // machine or db config file invalid
  | 'config_not_found'          // config file missing
  | 'env_var_missing'           // password_env var not set in OS env

  // Generic
  | 'execution_failed'          // PG returned an error not covered above
  | 'internal_error'            // agent bug (should never happen)
  | 'not_implemented';          // feature not yet built;

export interface ErrorMetadata {
  code: ErrorCode;
  /** Default human-readable message. May be overridden at throw site. */
  default_message: string;
  /** Whether browser should tear down the connection. */
  fatal: boolean;
  /** Whether browser may auto-retry the request. */
  retryable: boolean;
  /** Suggested recovery action shown in browser UI. */
  recovery_hint: string;
}

export const ERROR_CATALOG: Record<ErrorCode, ErrorMetadata> = {
  invalid_message: {
    code: 'invalid_message',
    default_message: 'Message envelope is malformed.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Update your browser to the latest version of Schema Weaver.',
  },
  unknown_message_type: {
    code: 'unknown_message_type',
    default_message: 'Unknown message type received.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Protocol version mismatch. Update browser and agent.',
  },
  payload_invalid: {
    code: 'payload_invalid',
    default_message: 'Message payload is invalid.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Check the request payload structure.',
  },
  protocol_version_mismatch: {
    code: 'protocol_version_mismatch',
    default_message: 'Protocol version mismatch. Agent expects v1.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Update both browser and agent to the latest version.',
  },
  auth_failed: {
    code: 'auth_failed',
    default_message: 'Agent token is invalid.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Run `sw-agent link <project> --token <new_token>` to relink.',
  },
  token_expired: {
    code: 'token_expired',
    default_message: 'Agent token has expired.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Rotate token in browser settings, then run `sw-agent relink`.',
  },
  permission_denied: {
    code: 'permission_denied',
    default_message: 'Permission denied for this action.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Check the DB permission level or your team role.',
  },
  role_insufficient: {
    code: 'role_insufficient',
    default_message: 'Your team role does not allow this action.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Ask an admin to upgrade your role from viewer/data_reader.',
  },
  approval_timeout: {
    code: 'approval_timeout',
    default_message: 'Manual approval timed out (60s).',
    fatal: false,
    retryable: true,
    recovery_hint: 'Approve the action next time, or change DB permission to auto_upgrade.',
  },
  approval_denied: {
    code: 'approval_denied',
    default_message: 'Manual approval was denied.',
    fatal: false,
    retryable: false,
    recovery_hint: 'User denied the action. No retry possible.',
  },
  MANUAL_APPROVAL_TIMEOUT: {
    code: 'MANUAL_APPROVAL_TIMEOUT',
    default_message: 'Manual approval timed out.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Approve the action next time, or change DB permission to auto_upgrade.',
  },
  MANUAL_APPROVAL_REJECTED: {
    code: 'MANUAL_APPROVAL_REJECTED',
    default_message: 'Manual approval was denied.',
    fatal: false,
    retryable: false,
    recovery_hint: 'User denied the action. No retry possible.',
  },
  db_unavailable: {
    code: 'db_unavailable',
    default_message: 'Cannot reach database.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Check that the DB host is reachable and the agent machine has network access.',
  },
  db_auth_failed: {
    code: 'db_auth_failed',
    default_message: 'Database rejected credentials.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Verify the password env var is set correctly and the PG user has login permission.',
  },
  db_not_found: {
    code: 'db_not_found',
    default_message: 'Database alias not found in agent config.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Run `sw-agent db:add` to add this database.',
  },
  db_pool_exhausted: {
    code: 'db_pool_exhausted',
    default_message: 'Connection pool exhausted.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Wait a few seconds and retry. If persistent, increase pool size in agent config.',
  },
  db_ssl_error: {
    code: 'db_ssl_error',
    default_message: 'SSL/TLS handshake with database failed.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Check ssl_mode and ssl_root_cert in the DB config entry.',
  },
  migration_in_progress: {
    code: 'migration_in_progress',
    default_message: 'Another migration is already running on this project.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Wait for the other migration to finish, or cancel it.',
  },
  migration_plan_not_registered: {
    code: 'migration_plan_not_registered',
    default_message: 'Migration plan_id was not pre-registered with cloud.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Re-submit the migration from the browser. The plan must be registered first.',
  },
  migration_statement_failed: {
    code: 'migration_statement_failed',
    default_message: 'A migration statement failed.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Check the per-statement error in the migration result. Entire transaction was rolled back.',
  },
  migration_rolled_back: {
    code: 'migration_rolled_back',
    default_message: 'Migration was rolled back.',
    fatal: false,
    retryable: false,
    recovery_hint: 'See migration result for which statement failed.',
  },
  migration_partial: {
    code: 'migration_partial',
    default_message: 'Migration partially applied (per_statement mode).',
    fatal: false,
    retryable: false,
    recovery_hint: 'Some statements committed, some failed. Manual verification required before retrying.',
  },
  query_timeout: {
    code: 'query_timeout',
    default_message: 'Query timed out.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Increase timeout_ms or optimize the query.',
  },
  query_cancelled: {
    code: 'query_cancelled',
    default_message: 'Query was cancelled.',
    fatal: false,
    retryable: false,
    recovery_hint: 'User or system cancelled the query.',
  },
  query_too_large: {
    code: 'query_too_large',
    default_message: 'Result set exceeded maximum (10,000 rows).',
    fatal: false,
    retryable: false,
    recovery_hint: 'Use stream_query instead, or add a LIMIT clause.',
  },
  stream_too_large: {
    code: 'stream_too_large',
    default_message: 'Stream exceeded maximum (1,000,000 rows).',
    fatal: false,
    retryable: false,
    recovery_hint: 'Add a WHERE clause or use cursor-based pagination.',
  },
  STREAM_ROW_LIMIT: {
    code: 'STREAM_ROW_LIMIT',
    default_message: 'Stream exceeded maximum rows.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Add a WHERE clause or LIMIT.',
  },
  CELL_SIZE_LIMIT: {
    code: 'CELL_SIZE_LIMIT',
    default_message: 'Cell size limit exceeded.',
    fatal: false,
    retryable: false,
    recovery_hint: 'Verify cell values are under 1MB.',
  },
  cancel_failed: {
    code: 'cancel_failed',
    default_message: 'Could not cancel the request.',
    fatal: false,
    retryable: false,
    recovery_hint: 'The request may have already completed.',
  },
  cancel_target_not_found: {
    code: 'cancel_target_not_found',
    default_message: 'No in-flight request matches the target_id.',
    fatal: false,
    retryable: false,
    recovery_hint: 'The request may have already finished.',
  },
  concurrent_request_rejected: {
    code: 'concurrent_request_rejected',
    default_message: 'Too many concurrent requests. Queue full.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Wait a moment and retry.',
  },
  orphaned_request: {
    code: 'orphaned_request',
    default_message: 'Request orphaned: no reconnect within 5 minutes.',
    fatal: false,
    retryable: false,
    recovery_hint: 'The agent cancelled the request after the browser disconnected.',
  },
  channel_closed: {
    code: 'channel_closed',
    default_message: 'WebSocket channel closed unexpectedly.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Browser will auto-reconnect. In-flight requests may resume.',
  },
  rate_limited: {
    code: 'rate_limited',
    default_message: 'Too many requests from this browser session.',
    fatal: false,
    retryable: true,
    recovery_hint: 'Slow down and retry after a few seconds.',
  },
  config_invalid: {
    code: 'config_invalid',
    default_message: 'Agent config file is invalid.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Run `sw-agent doctor` to diagnose, then fix the config file.',
  },
  config_not_found: {
    code: 'config_not_found',
    default_message: 'Agent config file not found.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Run `sw-agent init` first.',
  },
  env_var_missing: {
    code: 'env_var_missing',
    default_message: 'Password environment variable is not set.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Set the env var before starting the agent. See `sw-agent db:ls` for the var name.',
  },
  execution_failed: {
    code: 'execution_failed',
    default_message: 'Database query failed.',
    fatal: false,
    retryable: false,
    recovery_hint: 'See pg_error in the error payload for details.',
  },
  internal_error: {
    code: 'internal_error',
    default_message: 'Internal agent error.',
    fatal: true,
    retryable: false,
    recovery_hint: 'Run `sw-agent doctor` and report this issue with logs.',
  },
  not_implemented: {
    code: 'not_implemented',
    default_message: 'Feature not yet implemented.',
    fatal: false,
    retryable: false,
    recovery_hint: 'This part of the protocol is reserved for a future agent version.',
  },
};

export function getErrorMetadata(code: ErrorCode): ErrorMetadata {
  return ERROR_CATALOG[code];
}

export function isFatalError(code: ErrorCode): boolean {
  return ERROR_CATALOG[code].fatal;
}

export function isRetryableError(code: ErrorCode): boolean {
  return ERROR_CATALOG[code].retryable;
}

/**
 * Construct an ErrorPayload for a given code.
 * Optional overrides for message and request_id.
 */
export function makeError(
  code: ErrorCode,
  request_id: string,
  overrides?: {
    message?: string;
    pg_error?: ErrorPayload['pg_error'];
  },
): ErrorPayload {
  const meta = ERROR_CATALOG[code];
  return {
    request_id,
    code,
    message: overrides?.message ?? meta.default_message,
    pg_error: overrides?.pg_error,
    fatal: meta.fatal,
    retryable: meta.retryable,
  };
}
