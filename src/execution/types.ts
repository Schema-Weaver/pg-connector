import { AgentMessage, MigrationStatementStatus } from '../protocol/envelope';

/** Result of classifying a SQL statement. */
export interface StatementClassification {
  /** High-level type. */
  type: 'read' | 'write' | 'ddl' | 'migration' | 'utility' | 'unknown';
  /** Specific statement kind (SELECT, INSERT, CREATE TABLE, ALTER INDEX, etc.). */
  kind: string;
  /** Whether this statement can run inside a transaction. */
  transactional: boolean;
  /** Detected statement name (uppercased first keyword(s)). */
  verb: string;
}

/** Tracks one in-flight request. */
export interface InFlightRequest {
  request_id: string;
  db_alias: string;
  /** PG backend PID for this request. Used by canceller. */
  pid: number;
  /** When the request started (epoch ms). */
  started_at: number;
  /** The original message. */
  message: AgentMessage;
  /** Abort controller for cancellation. */
  abort: AbortController;
  /** Whether this is a streaming request. */
  is_streaming: boolean;
}

/** Result of a single migration statement execution. */
export interface StatementResult {
  index: number;
  status: MigrationStatementStatus;
  ms: number;
  rows_affected: number;
  error?: string;
  pg_error_code?: string;
}

/** Snapshot of one table's schema. */
export interface TableSnapshot {
  schema: string;
  name: string;
  type: 'table' | 'view' | 'materialized_view';
  columns: Array<{
    name: string;
    type: string;
    nullable: boolean;
    default: string | null;
    is_primary_key: boolean;
    is_unique: boolean;
    is_foreign_key: boolean;
    foreign_key?: {
      references_schema: string;
      references_table: string;
      references_column: string;
      on_delete: string | null;
      on_update: string | null;
    };
  }>;
  indexes: Array<{
    name: string;
    columns: string[];
    is_unique: boolean;
    is_primary: boolean;
    definition: string;
  }>;
  constraints: Array<{
    name: string;
    type: 'CHECK' | 'FOREIGN KEY' | 'UNIQUE' | 'PRIMARY KEY' | 'EXCLUSION';
    definition: string;
  }>;
  triggers: Array<{
    name: string;
    event: string;
    timing: string;
    function: string;
  }>;
  partition_info?: {
    is_partitioned: boolean;
    partition_key: string | null;
    partitions: Array<{ name: string; for_values: string }>;
  };
  owner: string;
  comment: string | null;
}

/** Full schema snapshot of a database. */
export interface SchemaSnapshot {
  pg_version: string;
  snapshot_at: number;
  schemas: string[];
  tables: TableSnapshot[];
  extensions: Array<{ name: string; version: string; enabled: boolean }>;
  size_bytes: number;
}

/** Pool manager events. */
export interface PoolManagerEvents {
  onPoolOpen?: (dbAlias: string) => void;
  onPoolClose?: (dbAlias: string, reason: 'idle' | 'explicit' | 'error') => void;
  onConnectionAcquired?: (dbAlias: string) => void;
  onConnectionReleased?: (dbAlias: string) => void;
}
