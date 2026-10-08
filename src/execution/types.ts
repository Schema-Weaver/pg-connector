import type { AgentMessage, MigrationStatementStatus } from '../protocol/envelope';
import type { PoolClient, QueryArrayConfig, QueryArrayResult, QueryConfig } from 'pg';
import type { FunctionEffectRecord, SideEffectKind } from './function-effects';

/* ------------------------------------------------------------------ */
/* Extended query protocol                                             */
/* ------------------------------------------------------------------ */

/**
 * node-postgres selects the **simple** query protocol whenever `values` is
 * falsy (`pg/lib/query.js` → `requiresPreparation`: `if (!this.values) return
 * false`), and the simple protocol executes *every* semicolon-separated
 * statement in one round trip. A payload without `params` therefore reached
 * PostgreSQL as a multi-command string.
 *
 * `queryMode: 'extended'` forces Parse/Bind/Execute. PostgreSQL refuses to
 * parse more than one command into a single prepared statement, so anything
 * sent through {@link extendedQuery} reaches the engine as exactly one command
 * regardless of what the classifier or the protocol validator admitted.
 * `$1`-style parameters keep working because Bind still carries `values`.
 *
 * `queryMode` is not yet declared by `@types/pg`.
 */
export type ExtendedQueryConfig = QueryConfig & { queryMode: 'extended' };
export type ExtendedQueryArrayConfig = QueryArrayConfig & { queryMode: 'extended' };

/** Minimal result shape used by the internal session/hardening statements. */
export interface SimpleResult {
  rows: unknown[];
  rowCount: number | null;
  fields: Array<{ name: string; dataTypeID: number }>;
}

/**
 * Build a query config that is guaranteed to travel over the extended query
 * protocol. `values` is always an array, so node-postgres never takes the
 * falsy-`values` shortcut; an empty array means "no bind parameters".
 */
export function extendedQuery(text: string, values?: readonly unknown[]): ExtendedQueryConfig {
  return { text, queryMode: 'extended', values: values ? [...values] : [] };
}

/** {@link extendedQuery} for `rowMode: 'array'` results. */
export function extendedArrayQuery(
  text: string,
  values?: readonly unknown[],
): ExtendedQueryArrayConfig {
  return { text, queryMode: 'extended', rowMode: 'array', values: values ? [...values] : [] };
}

/** Run a single statement over the extended protocol. */
export async function runExtended(
  client: PoolClient,
  text: string,
  values?: readonly unknown[],
): Promise<SimpleResult> {
  const res = await client.query(extendedQuery(text, values));
  return res as unknown as SimpleResult;
}

/** Run a single statement over the extended protocol, rows as arrays. */
export async function runExtendedArray(
  client: PoolClient,
  text: string,
  values?: readonly unknown[],
): Promise<QueryArrayResult<unknown[]>> {
  return (await client.query(extendedArrayQuery(text, values))) as QueryArrayResult<unknown[]>;
}

/** Result of classifying a SQL statement. */
export interface StatementClassification {
  /** High-level type. Derived from the PostgreSQL parse tree root node. */
  type: 'read' | 'write' | 'ddl' | 'utility' | 'unknown';
  /** Specific statement kind (SELECT, DROP TABLE, ALTER ROLE, …). */
  kind: string;
  /** Whether this statement can run inside a transaction block. */
  transactional: boolean;
  /** Detected statement name (uppercased). */
  verb: string;
  /**
   * How many statements PostgreSQL's parser found in the input. Anything other
   * than 1 must be rejected: the previous token classifier could not see a
   * trailing `; DROP TABLE`, and node-postgres executes every statement when
   * the simple query protocol is used.
   */
  statement_count: number;
  /** False when the input could not be parsed. Callers must fail closed. */
  parse_ok: boolean;
  /**
   * Reasons a syntactically valid SELECT is nonetheless not a safe read:
   * SELECT INTO creates a table, writable CTEs and FOR UPDATE mutate state,
   * denylisted functions reach the filesystem, other servers, or session
   * control, and any function reference the catalogue could not prove
   * `IMMUTABLE` may do anything the calling role may do. Empty array means the
   * statement is a provable read.
   */
  read_violations: string[];
  /**
   * Per-function catalogue verdicts for the statement.
   *
   * Optional in the type only, so that a hand-built classification (a test
   * fixture, an older constructor in another package) still compiles. It is
   * ALWAYS populated by the classifier, and the permission layer treats an
   * absent array as UNKNOWN rather than as "no functions were referenced" —
   * `isProvableRead()` refuses such a classification. Reading it as "empty,
   * therefore safe" is precisely the bug this field exists to close.
   */
  function_effects?: FunctionEffectRecord[];
  /**
   * Side effects the statement's function references perform outside the
   * transaction: notifications, advisory locks, sequence advances, XID
   * allocation, session mutation, remote I/O.
   *
   * Optional for the same reason as {@link StatementClassification.function_effects}
   * and treated the same way: absent means "not known", which is not safe.
   */
  side_effects?: SideEffectKind[];
}

/** Tracks one in-flight request. */
export interface InFlightRequest {
  request_id: string;
  db_alias: string;
  /** PG backend PID for this request. Used by canceller. */
  pid: number;
  /** When the request started (epoch ms). */
  started_at: number;
  /** The originating message, when the caller supplies it. */
  message?: AgentMessage;
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
