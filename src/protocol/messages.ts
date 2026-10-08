import { MigrationStatementStatus, EventKind } from './envelope';
import { ErrorCode } from './errors';

// 3.1 Ping
export interface PingPayload {
  /** Sender's epoch ms when ping was sent. */
  sent_at: number;
  /** Optional: sender reports its agent_id or browser_session_id. */
  sender_id?: string;
}

// 3.2 Introspect
export interface IntrospectPayload {
  /** Include views in snapshot. Default true. */
  include_views: boolean;
  /** Include indexes. Default true. */
  include_indexes: boolean;
  /** Include triggers. Default false (expensive). */
  include_triggers: boolean;
  /** Include partitions. Default true. */
  include_partitions: boolean;
  /** Include extensions. Default true. */
  include_extensions: boolean;
  /**
   * Declared server version the caller expects, e.g. "16.2", or null for "no
   * expectation".
   *
   * Honoured, not ignored (audit L-08): the agent compares the major version
   * against the server it is actually connected to and refuses the request on a
   * mismatch, so a snapshot taken against a different server than the caller
   * believes is never presented as this one.
   */
  pg_version_hint: string | null;
}

export interface IntrospectResultPayload {
  /** PG version string, e.g. "16.2". */
  pg_version: string;
  /** When snapshot was taken (epoch ms). */
  snapshot_at: number;
  /** Schema snapshot. Structure mirrors pg-ddl-parser output (ParsedSchema). */
  schema: unknown;
  /** List of installed extensions. */
  extensions: Array<{ name: string; version: string; enabled: boolean }>;
  /** List of schemas (namespaces). */
  schemas: string[];
  /**
   * On-disk size of the database, from `pg_database_size`, or `null` when the
   * server does not permit it to be read.
   *
   * Audit M-30: this field previously carried the JSON byte length of the
   * snapshot itself, so a viewer of the API could reasonably read it as the
   * database size and be wrong by orders of magnitude. The response's own size
   * is now reported separately and honestly as `snapshot_json_bytes`.
   */
  size_bytes: number | null;
  /** Serialised size of this snapshot, in bytes. Use this for budgeting. */
  snapshot_json_bytes: number;
  /**
   * Detail level actually applied, after the requester's role was taken into
   * account. `structure` means definitions, defaults, trigger metadata, owners,
   * comments and partition bounds were omitted.
   */
  detail: 'full' | 'structure';
}

// 3.3 Query
export interface QueryPayload {
  /** SQL statement. Single statement only. Multi-statement = rejected. */
  sql: string;
  /** Parameter values for prepared statement. */
  params?: unknown[];
  /** Override default timeout. 0 = no timeout (dangerous). */
  timeout_ms?: number;
  /** Intent tag (advisory only — agent re-parses to verify). */
  intent: 'read' | 'write' | 'ddl' | 'migration';
  /** If intent='migration', the pre-registered plan_id (anti-spoofing). */
  plan_id?: string;
}

export interface QueryResultPayload {
  /** Column metadata. */
  columns: Array<{ name: string; type_oid: number; type_name: string }>;
  /** Row data. Each row is an array of cell values (in column order). */
  rows: unknown[][];
  /** Rows affected (for INSERT/UPDATE/DELETE). -1 if not applicable. */
  rows_affected: number;
  /** Execution time in ms. */
  ms: number;
  /** Whether result was truncated due to MAX_QUERY_ROWS. */
  truncated: boolean;
}

// 3.4 Stream Query
/**
 * Keyset pagination cursor. `column` is applied as an ordered, exclusive bound
 * on the result (`>` forward, `<` backward), so a page never re-reads or skips
 * the rows already seen the way an offset does.
 */
export interface StreamCursor {
  column: string;       // column to paginate on (must be unique, ordered)
  last_value: unknown;  // last value seen (exclusive)
  direction: 'forward' | 'backward';
}

export interface StreamQueryPayload {
  sql: string;
  params?: unknown[];
  timeout_ms?: number;
  intent: 'read' | 'write' | 'ddl' | 'migration';
  plan_id?: string;
  /** Optional: cursor for pagination. If provided, agent uses cursor-based fetch. */
  cursor?: StreamCursor;
  /** Page size for cursor pagination. Default 50 (Data Explorer mode). */
  page_size?: number;
}

// 3.5 Stream Chunk
export interface StreamChunkPayload {
  /** Matches the stream_query request id. */
  request_id: string;
  /** Column metadata (sent on first chunk only, null on subsequent). */
  columns: Array<{ name: string; type_oid: number; type_name: string }> | null;
  /** Row data in this chunk. */
  rows: unknown[][];
  /** Chunk sequence number (0, 1, 2, ...). */
  chunk_index: number;
  /** Whether any cell in this chunk was truncated due to MAX_CELL_BYTES. */
  has_truncated_cells: boolean;
}

// 3.6 Stream End
export interface StreamEndPayload {
  request_id: string;
  /** Total rows across all chunks. */
  total_rows: number;
  /** Whether stream was truncated due to MAX_STREAM_ROWS. */
  truncated: boolean;
  /** Total execution time in ms. */
  ms: number;
  /** Chunk count sent. */
  chunk_count: number;
  /**
   * True when the request carried a cursor and the page ended with rows still
   * available on the server. Absent means the whole result was delivered.
   */
  has_more?: boolean;
  /** Cursor for the next page. Present only when `has_more` is true. */
  next_cursor?: StreamCursor;
}

// 3.7 Migration Run
export interface MigrationRunPayload {
  /** Pre-registered plan ID (anti-spoofing). */
  plan_id: string;
  /** SQL statements in order. */
  statements: string[];
  /** Execution strategy. */
  strategy: 'single_tx' | 'per_statement';
  /** Optional timeout override. */
  timeout_ms?: number;
  /** Whether to dry-run (parse only, no execution). */
  dry_run: boolean;
}

export interface MigrationResultPayload {
  plan_id: string;
  /** Final status. */
  status: 'committed' | 'rolled_back' | 'partial' | 'dry_run_ok' | 'dry_run_failed';
  /** Per-statement outcome. */
  statements: Array<{
    index: number;
    status: MigrationStatementStatus;
    ms: number;
    rows_affected: number;
    error?: string;
    pg_error_code?: string;
  }>;
  /** Total execution time in ms. */
  total_ms: number;
  /** If rolled_back: which statement indices were rolled back. */
  rolled_back_indices: number[];
  /** If strategy was auto-switched (e.g. CONCURRENTLY detected), original strategy is here. */
  strategy_changed_from?: 'single_tx' | 'per_statement';
}

// 3.8 Cancel
export interface CancelPayload {
  /** The request_id to cancel. */
  target_id: string;
  /** Reason for cancellation (for audit). */
  reason: 'user_cancelled' | 'timeout' | 'session_closed' | 'orphaned';
}

export interface CancelResultPayload {
  target_id: string;
  /** Whether the cancel signal was sent. */
  cancelled: boolean;
  /** Whether the original request actually terminated. */
  terminated: boolean;
  /**
   * Whether the agent's in-process cooperative abort fired. True here with
   * `terminated: false` means the request stopped locally while the
   * PostgreSQL backend could not be signalled.
   */
  local_abort?: boolean;
  /** If false, why not. */
  reason?: string;
}

// 3.9 Response
export interface ResponsePayload<T = unknown> {
  /** Matches the request_id. */
  request_id: string;
  /** Whether the request succeeded. */
  ok: boolean;
  /** Type-specific result. Shape depends on the original request type. */
  data: T;
  /** Execution time in ms (for queries/migrations). */
  ms?: number;
}

/** PG-specific error fields that may appear on the wire. */
export interface PgErrorSummary {
  /** SQLSTATE, e.g. "23505". Stable, so the browser can branch on failure kind. */
  code: string;
  /** ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG or INFO. */
  severity: string;
  /**
   * Operator-facing hint, always one of the agent's own curated strings for the
   * SQLSTATE. It is never PostgreSQL's `hint` field, which can quote schema
   * and column names and suggest DDL the caller did not ask for.
   */
  hint?: string;
}

/**
 * 3.10 Error
 *
 * `pg_error` is an allow-list of two fields. PostgreSQL `DETAIL` and `HINT`
 * lines routinely contain row data (`DETAIL:  Key (email)=(alice@corp.com)
 * already exists.`) and error messages embed the offending SQL and absolute
 * filesystem paths, so neither is carried on this frame; the agent substitutes
 * a curated message per SQLSTATE instead.
 */
export interface ErrorPayload {
  request_id: string;
  /** Stable error code (see errors.ts catalog). */
  code: ErrorCode;
  /** Human-readable message. Safe to show in browser UI. */
  message: string;
  /** Optional: reduced, data-free PostgreSQL error summary. */
  pg_error?: PgErrorSummary;
  /** Whether the error is fatal (connection should be torn down). */
  fatal: boolean;
  /** Whether the error is retryable (browser may auto-retry). */
  retryable: boolean;
}

// 3.11 Event
export interface EventPayload {
  kind: EventKind;
  /** Type-specific event data. */
  data: EventData;
}

export type EventData =
  | StatusChangeEvent
  | MigrationProgressEvent
  | ApprovalRequiredEvent
  | ApprovalResponseEvent
  | WarningEvent
  | ResumeRequestEvent;

export interface StatusChangeEvent {
  new_status: 'online' | 'offline' | 'degraded' | 'maintenance';
  reason?: string;
}

export interface MigrationProgressEvent {
  plan_id: string;
  statement_index: number;
  /**
   * Preview of the statement. MUST be redacted (`redactSqlLiterals`) before it
   * is transmitted: it is shipped to the cloud by default, and a raw
   * `substring(0, 100)` carries every literal in the first 100 characters.
   */
  statement_sql_preview: string;
  status: MigrationStatementStatus;
  ms?: number;
  error?: string;
  /** True if this event is a replay after reconnect (not fresh). */
  replayed?: boolean;
}

export interface ApprovalRequiredEvent {
  request_id: string;
  sql: string;
  /** Redacted + truncated preview. Safe to log and to transmit. */
  sql_preview: string;
  intent: 'write' | 'ddl';
  db_alias: string;
  /**
   * Unguessable value minted by the agent. The approver must echo it back in
   * ApprovalResponseEvent; without it any sender could approve any pending
   * write by guessing the request id.
   */
  approval_nonce: string;
  /** When approval expires (epoch ms). */
  expires_at: number;
}

export interface ApprovalResponseEvent {
  request_id: string;
  approved: boolean;
  /**
   * Must equal the `approval_nonce` from the corresponding ApprovalRequiredEvent.
   * Verified by the agent.
   */
  approval_nonce: string;
  /**
   * Display-only. The agent IGNORES this value and records the approver from
   * the authenticated envelope instead, so a spoofed string cannot be used to
   * fabricate an approval in the audit log.
   */
  approved_by?: string;
}

export interface WarningEvent {
  code: string;  // warning code (free-form for now)
  message: string;
  /** Optional context object. */
  context?: Record<string, unknown>;
}

export interface ResumeRequestEvent {
  /** The request_id to resume (after reconnect). */
  request_id: string;
}

export type AnyPayload =
  | PingPayload
  | IntrospectPayload
  | QueryPayload
  | StreamQueryPayload
  | StreamChunkPayload
  | StreamEndPayload
  | MigrationRunPayload
  | MigrationResultPayload
  | CancelPayload
  | CancelResultPayload
  | ResponsePayload
  | ErrorPayload
  | EventPayload;

/** Maps message type → expected payload type. */
export interface PayloadByType {
  ping: PingPayload;
  introspect: IntrospectPayload | ResponsePayload<IntrospectResultPayload>;
  query: QueryPayload | ResponsePayload<QueryResultPayload>;
  stream_query: StreamQueryPayload;
  stream_chunk: StreamChunkPayload;
  stream_end: StreamEndPayload;
  migration_run: MigrationRunPayload | ResponsePayload<MigrationResultPayload>;
  cancel: CancelPayload | ResponsePayload<CancelResultPayload>;
  response: ResponsePayload;
  error: ErrorPayload;
  event: EventPayload;
}
