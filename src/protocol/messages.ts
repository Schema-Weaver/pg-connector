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
  /** PG version filter. If null, snapshot current state. If "12.0", snapshot as PG 12. */
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
  /** Snapshot size in bytes (for budgeting). */
  size_bytes: number;
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
export interface StreamQueryPayload {
  sql: string;
  params?: unknown[];
  timeout_ms?: number;
  intent: 'read' | 'write' | 'ddl' | 'migration';
  plan_id?: string;
  /** Optional: cursor for pagination. If provided, agent uses cursor-based fetch. */
  cursor?: {
    column: string;       // column to paginate on (must be unique, ordered)
    last_value: unknown;  // last value seen (exclusive)
    direction: 'forward' | 'backward';
  };
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

// 3.10 Error
export interface ErrorPayload {
  request_id: string;
  /** Stable error code (see errors.ts catalog). */
  code: ErrorCode;
  /** Human-readable message. Safe to show in browser UI. */
  message: string;
  /** Optional: PG-specific error details. */
  pg_error?: {
    code: string;        // PG error code, e.g. "42601"
    severity: string;    // ERROR, FATAL, etc.
    detail?: string;
    hint?: string;
    position?: number;
  };
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
  statement_sql_preview: string;  // first 200 chars of SQL
  status: MigrationStatementStatus;
  ms?: number;
  error?: string;
  /** True if this event is a replay after reconnect (not fresh). */
  replayed?: boolean;
}

export interface ApprovalRequiredEvent {
  request_id: string;
  sql: string;
  sql_preview: string;  // first 200 chars
  intent: 'write' | 'ddl' | 'migration';
  db_alias: string;
  /** When approval expires (epoch ms). */
  expires_at: number;
}

export interface ApprovalResponseEvent {
  request_id: string;
  approved: boolean;
  /** ID of user who approved/denied (browser stamps this). */
  approved_by: string;
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
