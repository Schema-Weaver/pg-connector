import type { DbEntry } from '../config/db-config';
import type { FunctionEffectResolver } from '../execution/function-effects';
import type { InFlightRequest, StatementClassification } from '../execution/types';
import type {
  QueryPayload,
  QueryResultPayload,
  StreamChunkPayload,
  StreamEndPayload,
  StreamQueryPayload,
} from '../protocol/messages';

export type { DbType } from './config-shape';

/** Options a classifier may understand. Only PostgreSQL uses them today. */
export interface DriverClassifyOptions {
  /**
   * PostgreSQL only: resolve every function reference against `pg_proc`.
   *
   * Absent means "not analysable", which the classifier reports as a side
   * effect; statements that call functions are then escalated rather than
   * trusted. MySQL denies stored functions by name, and MongoDB has no
   * function-call surface, so both ignore this option.
   */
  resolveFunctionEffects?: FunctionEffectResolver;
}

export type StatementClassifier = (
  sql: string,
  options?: DriverClassifyOptions,
) => Promise<StatementClassification>;

/** What a driver can do beyond the query path. */
export interface DriverCapabilities {
  query: boolean;
  stream: boolean;
  introspect: boolean;
  migration: boolean;
  /** Whether the driver can signal the server to stop an in-flight query. */
  server_cancel: boolean;
}

export interface DriverConnectionInfo {
  version: string;
  database: string;
  user: string;
}

/**
 * The context handed to a driver's execution methods.
 *
 * This is deliberately the same shape the existing PostgreSQL `QueryRunner`
 * accepts, so the Postgres driver is a thin adapter rather than a second
 * execution path. It lives here to keep the driver contract independent of the
 * query-runner implementation.
 */
export interface DriverQueryContext {
  dbEntry: DbEntry;
  request_id: string;
  /**
   * True when the resolved permission level is `read_only`.
   *
   * Drivers use this for the session-level posture
   * (`SET SESSION TRANSACTION READ ONLY` on MySQL). It is separate from
   * `classification` because a statement can be a read at any permission level
   * and because a write at `read_only` must fail at the database even if the
   * classifier missed it.
   */
  readOnlySession?: boolean;
  onChunk?: (chunk: StreamChunkPayload) => Promise<void>;
  onEnd?: (end: StreamEndPayload) => void | Promise<void>;
  waitForDrain?: () => Promise<void>;
  abortSignal?: AbortSignal;
  classification?: StatementClassification;
  registerInFlight?: (req: InFlightRequest) => void;
  unregisterInFlight?: (request_id: string) => void;
}

/**
 * The common contract every database driver implements.
 *
 * Two rules make this interface the security boundary it is meant to be:
 *
 *   - `classify` must fail closed. A statement the parser cannot represent, a
 *     method outside the allow-list, or an input with an unexpected shape is an
 *     error — never a lexical guess and never a default of `read`.
 *   - `runOneShot`/`runStreaming` must establish the engine's read-only posture
 *     before executing caller-supplied input. Classification is the first
 *     gate; the database is the second, and neither is optional.
 */
export interface DatabaseDriver {
  readonly type: import('./config-shape').DbType;
  readonly display_name: string;
  readonly default_port: number;
  readonly capabilities: DriverCapabilities;
  readonly classify: StatementClassifier;

  /** Open a connection, prove it is alive, and report the server identity. */
  testConnection(entry: DbEntry): Promise<DriverConnectionInfo>;

  runOneShot(payload: QueryPayload, ctx: DriverQueryContext): Promise<QueryResultPayload>;

  runStreaming(payload: StreamQueryPayload, ctx: DriverQueryContext): Promise<void>;

  /** Close the pooled client for one alias, if any. */
  close(alias: string): Promise<void>;

  /** Close every pooled client this driver owns. */
  closeAll(): Promise<void>;

  /**
   * A driver-specific view of an entry with every credential removed.
   *
   * `db list --json` uses this so adding a driver cannot accidentally add a
   * field that leaks a secret.
   */
  redactConfig(entry: DbEntry): Record<string, unknown>;
}
