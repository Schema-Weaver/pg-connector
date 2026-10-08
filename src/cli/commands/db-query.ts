import * as readline from 'readline';
import * as path from 'path';
import { Pool, PoolConfig } from 'pg';
import { findDbEntry, DbEntry } from '../../config/db-config';
import { buildSslConfig } from '../../execution/pool';
import { DEFAULTS } from '../../protocol/constants';
import { classifyStatement } from '../../execution/statement-classifier';
import { initSqlParser } from '../../execution/sql-parser';
import { createFunctionEffectResolver } from '../../execution/function-effects';
import type { FunctionEffectResolver, FunctionEffectQueryable } from '../../execution/function-effects';
import type { StatementClassification } from '../../execution/types';
import { PermissionChecker } from '../../permissions/checker';
import { PlanRegistry } from '../../permissions/plan-registry';
import { AutoUpgradeChecker } from '../../permissions/auto-upgrade';
import { ManualApprovalHandler } from '../../permissions/manual-approval';
import type { PermissionLevel } from '../../permissions/types';
import type { Role } from '../../protocol/envelope';
import { previewStatement, fingerprintStatement } from '../../audit/redact';
import { AuditSink } from '../../audit/sink';
import { LocalAuditWriter } from '../../audit/local-writer';
import { CloudAuditWriter } from '../../audit/cloud-writer';
import { machineConfigExists, loadMachineConfig } from '../../config/machine-config';
import { getSwAgentDir } from '../../config/paths';
import { isReplMode } from '../prompt';
import { C, S, renderTable, clearScreen, createSpinner, terminalWidth, truncateAnsi } from '../ui';

/* ------------------------------------------------------------------ */
/* Local SQL policy                                                    */
/* ------------------------------------------------------------------ */

/**
 * Identity recorded for SQL submitted from the local CLI or the `db connect`
 * REPL. There is no cloud user in this path: the request comes from a process
 * that already holds the database credentials, so it is recorded under a
 * distinct actor id rather than being folded into a browser role.
 */
export const LOCAL_OPERATOR_ID = 'local-operator';

/**
 * Role the local operator is recorded as.
 *
 * The capability matrix is not the control here — the entry's effective
 * permission level is. A local operator holds the credentials and can always
 * use `psql` instead; pretending a shell is a lesser role would be theatre. The
 * audit record keeps the level (`permission_level`) and the actor
 * (`user_id: 'local-operator'`) so the distinction stays visible.
 */
export const LOCAL_OPERATOR_ROLE: Role = 'admin';

/** Statement timeout applied to every local query. Bounded, never caller-settable. */
export const LOCAL_STATEMENT_TIMEOUT_MS = DEFAULTS.QUERY_TIMEOUT_MS;

/** Hard cap on rows returned to the terminal, enforced while rows are fetched. */
export const LOCAL_MAX_ROWS = DEFAULTS.MAX_QUERY_ROWS;

/** Rows fetched per FETCH round trip on the cursor path. */
const FETCH_BATCH = 500;

/** `lock_timeout` for local statements, so a blocked write fails fast. */
const LOCAL_LOCK_TIMEOUT_MS = 10_000;

export class LocalPermissionDeniedError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'LocalPermissionDeniedError';
  }
}

export class LocalAuditUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalAuditUnavailableError';
  }
}

export class LocalRowCapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalRowCapError';
  }
}

/* ------------------------------------------------------------------ */
/* Injectable seams                                                    */
/* ------------------------------------------------------------------ */

export interface LocalQueryResult {
  rows: LocalRow[];
  fields: Array<{ name: string }>;
  rowCount: number | null;
  command: string;
}

/** A result row as produced by node-postgres. */
export type LocalRow = Record<string, unknown>;

/** The shape `asQueryResult` accepts, so no caller needs an `any`. */
interface RawQueryResult {
  rows?: LocalRow[];
  fields?: Array<{ name: string }>;
  rowCount?: number | null;
  command?: string;
}

export interface LocalClient {
  query(config: string | { text: string; values?: unknown[] }): Promise<LocalQueryResult>;
  release(): void;
}

export interface LocalPool {
  connect(): Promise<LocalClient>;
  end(): Promise<void>;
}

export type LocalPoolFactory = (entry: DbEntry) => LocalPool | Promise<LocalPool>;

/** The subset of `AuditSink` the local path depends on. */
export interface LocalAuditRecorder {
  logSync(event: Record<string, unknown>): Promise<void>;
  flush(): Promise<void>;
}

export interface LocalSqlDeps {
  poolFactory: LocalPoolFactory;
  audit: LocalAuditRecorder;
  checker: PermissionChecker;
  /** Effective permission level for this database entry. */
  permissionLevel: PermissionLevel;
  /** Advisory cap; defaults to {@link LOCAL_MAX_ROWS}. */
  maxRows?: number;
  /** Advisory statement timeout in ms; defaults to {@link LOCAL_STATEMENT_TIMEOUT_MS}. */
  timeoutMs?: number;
  /** `true` when the resolved level is `read_only`. */
  readOnlySession: boolean;
}

export interface LocalSqlRequest {
  entry: DbEntry;
  sql: string;
  /** Audit action label. */
  action: 'query' | 'introspect';
}

/* ------------------------------------------------------------------ */
/* Permission + audit                                                  */
/* ------------------------------------------------------------------ */

const INTENT_BY_CLASSIFICATION: Partial<
  Record<StatementClassification['type'], 'read' | 'write' | 'ddl'>
> = {
  read: 'read',
  write: 'write',
  ddl: 'ddl',
};

/**
 * Classify a statement and map it onto a permission-checker `intent`.
 *
 * `PermissionChecker` compares the claimed intent against the classification it
 * derives itself, and only `read | write | ddl` are expressible. A statement
 * the classifier reports as `utility` or `unknown` therefore cannot be
 * authorised through this pipeline at all, and is refused rather than being
 * relabelled as something weaker.
 */
async function authoriseLocalSql(
  deps: LocalSqlDeps,
  req: LocalSqlRequest,
  resolveFunctionEffects?: FunctionEffectResolver,
): Promise<{ classification: StatementClassification; allowed: boolean; reason: string }> {
  // Idempotent. Without it the CLI would refuse every statement, because the
  // parser is fail-closed when it has not been loaded.
  await initSqlParser();

  const classification = await classifyStatement(req.sql, { resolveFunctionEffects });
  const intent = INTENT_BY_CLASSIFICATION[classification.type];

  if (!intent) {
    return {
      classification,
      allowed: false,
      reason:
        `Statement class '${classification.type}' (${classification.kind}) cannot be authorised on the ` +
        'local SQL path. Only read, write and DDL statements are classified into an ' +
        'authorisable intent; session/transaction utilities and unrecognised ' +
        'statements must not be relabelled. Use a direct PostgreSQL client if you ' +
        'need them.',
    };
  }

  const decision = await deps.checker.check(
    {
      role: LOCAL_OPERATOR_ROLE,
      permission_level: deps.permissionLevel,
      sql: req.sql,
      intent,
      message_type: req.action,
      request_id: `local-${Date.now().toString(36)}`,
      db_alias: req.entry.db_alias,
      project: req.entry.project_name,
      user: { id: LOCAL_OPERATOR_ID, role: LOCAL_OPERATOR_ROLE },
    },
    undefined,
    resolveFunctionEffects,
  );

  return { classification, allowed: decision.allowed, reason: decision.reason };
}

/**
 * A function-effect resolver over the caller's pool, or `undefined`.
 *
 * WHY THIS IS HERE. `PermissionChecker.check` re-classifies the statement
 * itself, so a resolver has to reach it as an argument — the daemon passes one
 * from `dispatcher.ts`. This path passed none, which meant every function
 * reference came back `unknown_effect` and was escalated to `ddl`: at
 * `read_only`, `SELECT count(*) FROM x` was refused even though `count` is
 * `IMMUTABLE` in `pg_proc`. Without a database to ask, that refusal is the
 * correct fail-closed answer, so a failure to open one falls back to no
 * resolver at all rather than to a permissive verdict.
 *
 * LAZY. `acquire()` runs only when `analyseFunctionEffects` has a cache miss,
 * so `SELECT 1` and already-seen function names never open a connection. The
 * connection is held until {@link dispose} — which the caller must run once the
 * decision is made — so one client serves both the classifier's own analysis
 * and the checker's re-classification.
 */
async function localFunctionEffectResolver(
  deps: LocalSqlDeps,
  entry: DbEntry,
): Promise<{ resolver?: FunctionEffectResolver; dispose: () => Promise<void> }> {
  let pool: LocalPool | undefined;
  let client: LocalClient | undefined;

  const acquire = async () => {
    if (!client) {
      pool = await deps.poolFactory(entry);
      client = await pool.connect();
    }
    return { client: client as unknown as FunctionEffectQueryable, release: () => undefined };
  };

  return {
    resolver: createFunctionEffectResolver({ acquire }, { dbKey: entry.db_alias ?? '' }),
    dispose: async () => {
      client?.release();
      client = undefined;
      const closing = pool;
      pool = undefined;
      if (closing) await closing.end();
    },
  };
}

async function appendLocalAudit(
  deps: LocalSqlDeps,
  req: LocalSqlRequest,
  fields: {
    decision: 'allow' | 'deny';
    outcome: 'success' | 'error' | 'n/a';
    classification: StatementClassification;
    reason?: string;
    durationMs?: number;
    rowsReturned?: number;
    errorCode?: string;
  },
): Promise<void> {
  const event = {
    project: req.entry.project_name,
    user_id: LOCAL_OPERATOR_ID,
    // No cloud asserted this request: recording it as `user` would write the
    // local shell into the audit trail as a cloud principal holding `admin`.
    actor: 'local',
    role: LOCAL_OPERATOR_ROLE,
    action: req.action,
    decision: fields.decision,
    outcome: fields.outcome,
    permission_level: deps.permissionLevel,
    statement_preview: previewStatement(req.sql),
    statement_fingerprint: fingerprintStatement(req.sql),
    denial_reason: fields.reason,
    error_code: fields.errorCode,
    duration_ms: fields.durationMs,
    rows_returned: fields.rowsReturned,
  };

  // MANDATORY. If the audit append does not complete, the statement does not run.
  // An unlogged local write is indistinguishable from no control at all.
  try {
    await deps.audit.logSync(event);
  } catch (err) {
    throw new LocalAuditUnavailableError(
      'Refusing to execute: the audit record could not be written to ' +
        `${path.join(getSwAgentDir(), 'audit', 'audit.jsonl')}. ` +
        `Refusing to run unlogged SQL. (${err instanceof Error ? err.message : String(err)})`,
    );
  }
}

/* ------------------------------------------------------------------ */
/* Execution                                                           */
/* ------------------------------------------------------------------ */

function asQueryResult(res: RawQueryResult): LocalQueryResult {
  return {
    rows: res?.rows ?? [],
    fields: res?.fields ?? [],
    rowCount: res?.rowCount ?? null,
    command: res?.command ?? '',
  };
}

function cursorNameFor(requestId: string): string {
  return `sw_local_${requestId.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 32)}`;
}

async function hardenLocalSession(client: LocalClient, deps: LocalSqlDeps): Promise<void> {
  // RESET ALL clears every session GUC a previous pooled connection may have
  // left behind, so the posture below is the only thing in effect.
  await client.query('RESET ALL');
  // PostgreSQL itself enforces read_only; the classifier is not the boundary.
  await client.query(
    deps.readOnlySession
      ? 'SET default_transaction_read_only = on'
      : 'SET default_transaction_read_only = off',
  );
  // Session-level, not SET LOCAL: outside a transaction block SET LOCAL is a
  // silent no-op, which is how local queries used to run with no timeout at all.
  const timeoutMs = Math.max(1, Math.floor(deps.timeoutMs ?? LOCAL_STATEMENT_TIMEOUT_MS));
  await client.query(`SET statement_timeout = ${timeoutMs}`);
  await client.query(`SET lock_timeout = ${LOCAL_LOCK_TIMEOUT_MS}`);
  await client.query(`SET idle_in_transaction_session_timeout = ${timeoutMs}`);
}

async function executeOnClient(
  client: LocalClient,
  sql: string,
  classification: StatementClassification,
  maxRows: number,
  requestId: string,
): Promise<LocalQueryResult> {
  if (classification.type !== 'read') {
    const out = asQueryResult(await client.query({ text: sql }));
    if (out.rows.length > maxRows) {
      throw new LocalRowCapError(
        `Statement returned ${out.rows.length} rows, above the local ceiling of ${maxRows}. ` +
          'Narrow the result set or aggregate server-side.',
      );
    }
    return out;
  }

  // Read path: a cursor, so the ceiling binds WHILE rows are produced instead of
  // after the whole result has been buffered.
  const cursor = cursorNameFor(requestId);
  const rows: LocalRow[] = [];
  let fields: Array<{ name: string }> = [];
  let command = '';
  let truncated = false;

  await client.query('BEGIN');
  try {
    const declared = asQueryResult(
      await client.query({ text: `DECLARE ${cursor} CURSOR FOR ${sql}` }),
    );
    command = declared.command;

    for (;;) {
      const batch = asQueryResult(
        await client.query({ text: `FETCH ${FETCH_BATCH} FROM ${cursor}` }),
      );
      if (fields.length === 0 && batch.fields.length > 0) {
        fields = batch.fields;
      }
      if (batch.rows.length === 0) break;
      for (const row of batch.rows) {
        if (rows.length >= maxRows) {
          truncated = true;
          break;
        }
        rows.push(row);
      }
      if (truncated) break;
    }

    await client.query(`CLOSE ${cursor}`);

    if (truncated) {
      // Rolled back rather than committed: the ceiling aborted the read, so the
      // transaction has no completion to record.
      throw new LocalRowCapError(
        `Result exceeds the local ceiling of ${maxRows} rows. ` +
          'Narrow the result set or aggregate server-side.',
      );
    }

    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // connection is being returned
    }
    throw err;
  }

  return { rows, fields, rowCount: rows.length, command: command || 'SELECT' };
}

/**
 * Classify, authorise, audit, and run a single local statement.
 *
 * Order is deliberate and fail-closed:
 *   1. classify with the PostgreSQL parser
 *   2. authorise through `PermissionChecker` at the entry's resolved level
 *   3. append the audit record — mandatory; a failed append refuses execution
 *   4. apply `statement_timeout`, `lock_timeout` and the read_only posture
 *   5. execute with a row ceiling that binds during fetch
 *   6. append the outcome record
 */
export async function executeLocalSql(
  req: LocalSqlRequest,
  deps: LocalSqlDeps,
): Promise<LocalQueryResult> {
  const maxRows = deps.maxRows ?? LOCAL_MAX_ROWS;
  const requestId = `local-${Date.now().toString(36)}`;

  let authorisation: { classification: StatementClassification; allowed: boolean; reason: string };
  const effects = await localFunctionEffectResolver(deps, req.entry);
  try {
    authorisation = await authoriseLocalSql(deps, req, effects.resolver);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const denied: StatementClassification = {
      type: 'unknown',
      kind: 'UNCLASSIFIED',
      transactional: true,
      verb: '',
      statement_count: 0,
      parse_ok: false,
      read_violations: ['parse_error'],
    };
    await appendLocalAudit(deps, req, {
      decision: 'deny',
      outcome: 'n/a',
      classification: denied,
      reason: 'classification_failed',
    }).catch(() => undefined);
    throw new LocalPermissionDeniedError(
      `Statement could not be verified and was refused: ${message}`,
      'classification_failed',
    );
  } finally {
    await effects.dispose().catch(() => undefined);
  }

  if (!authorisation.allowed) {
    await appendLocalAudit(deps, req, {
      decision: 'deny',
      outcome: 'n/a',
      classification: authorisation.classification,
      reason: authorisation.reason,
    });
    throw new LocalPermissionDeniedError(authorisation.reason, 'permission_denied');
  }

  // Mandatory audit of the attempt, before anything touches the database.
  await appendLocalAudit(deps, req, {
    decision: 'allow',
    outcome: 'n/a',
    classification: authorisation.classification,
  });

  const startedAt = Date.now();
  const pool = await deps.poolFactory(req.entry);
  let client: LocalClient | undefined;
  try {
    client = await pool.connect();
    await hardenLocalSession(client, deps);

    const result = await executeOnClient(
      client,
      req.sql,
      authorisation.classification,
      maxRows,
      requestId,
    );

    await deps.audit.logSync({
      project: req.entry.project_name,
      user_id: LOCAL_OPERATOR_ID,
      actor: 'local',
      role: LOCAL_OPERATOR_ROLE,
      action: req.action,
      decision: 'allow',
      outcome: 'success',
      permission_level: deps.permissionLevel,
      statement_preview: previewStatement(req.sql),
      statement_fingerprint: fingerprintStatement(req.sql),
      duration_ms: Date.now() - startedAt,
      rows_returned: result.rows.length,
    });

    return result;
  } catch (err) {
    await deps.audit.logSync({
      project: req.entry.project_name,
      user_id: LOCAL_OPERATOR_ID,
      actor: 'local',
      role: LOCAL_OPERATOR_ROLE,
      action: req.action,
      decision: 'allow',
      outcome: 'error',
      permission_level: deps.permissionLevel,
      statement_preview: previewStatement(req.sql),
      statement_fingerprint: fingerprintStatement(req.sql),
      duration_ms: Date.now() - startedAt,
      error_code: (err as { code?: string })?.code,
    });
    throw err;
  } finally {
    client?.release();
    await pool.end();
  }
}

/* ------------------------------------------------------------------ */
/* Default wiring                                                      */
/* ------------------------------------------------------------------ */

function defaultPoolFactory(entry: DbEntry): LocalPool {
  return createDbPool(entry) as unknown as LocalPool;
}

/**
 * Audit sink for local CLI activity.
 *
 * Writes to the same `~/.sw-agent/audit/` chain the daemon uses, so a local
 * statement and a cloud statement land in one ordered log. The cloud writer is
 * disabled: nothing in this path transmits anything.
 */
export function createLocalAuditRecorder(): LocalAuditRecorder {
  let agentId = 'local';
  try {
    if (machineConfigExists()) {
      agentId = loadMachineConfig().agent_id;
    }
  } catch {
    agentId = 'local';
  }

  const sink = new AuditSink({
    agentId,
    localWriter: new LocalAuditWriter({
      dir: path.join(getSwAgentDir(), 'audit'),
    }),
    cloudWriter: new CloudAuditWriter({ enabled: false, agent_token: '' }),
  });
  return sink as unknown as LocalAuditRecorder;
}

export function createLocalPermissionChecker(audit: LocalAuditRecorder): PermissionChecker {
  const planRegistry = new PlanRegistry();
  return new PermissionChecker({
    autoUpgradeChecker: new AutoUpgradeChecker({ planRegistry }),
    manualApprovalHandler: new ManualApprovalHandler({
      // There is no relay session in the local path, so an approval can never
      // arrive. The handler is unreachable: `manual` is resolved away before
      // the checker is called.
      send: async () => {
        throw new Error('No approval channel is available for local SQL.');
      },
      timeoutMs: DEFAULTS.APPROVAL_TIMEOUT_MS,
      auditSink: audit as unknown as AuditSink,
    }),
    planRegistry,
  });
}

/**
 * Effective permission level for a database entry: the entry's override if it
 * has one, otherwise the machine default, otherwise `read_only`.
 */
export function resolveLocalPermissionLevel(entry: DbEntry): PermissionLevel {
  if (entry.permission_override) return entry.permission_override;
  try {
    if (machineConfigExists()) {
      return loadMachineConfig().default_permission;
    }
  } catch {
    // fall through to the fail-closed default
  }
  return 'read_only';
}

/**
 * Build the default dependency set for a database entry.
 *
 * `manual` is resolved to `read_only` before the checker runs: the approval flow
 * requires the browser relay, and a local shell has no way to answer it.
 */
export function createLocalSqlDeps(entry: DbEntry): LocalSqlDeps {
  const audit = createLocalAuditRecorder();
  const resolved = resolveLocalPermissionLevel(entry);
  const permissionLevel: PermissionLevel = resolved === 'manual' ? 'read_only' : resolved;

  return {
    poolFactory: defaultPoolFactory,
    audit,
    checker: createLocalPermissionChecker(audit),
    permissionLevel,
    maxRows: LOCAL_MAX_ROWS,
    timeoutMs: LOCAL_STATEMENT_TIMEOUT_MS,
    readOnlySession: permissionLevel === 'read_only',
  };
}

/** Narrow a resolved level to what the local path can actually enforce. */
export function localPermissionLevelFor(entry: DbEntry): PermissionLevel {
  const resolved = resolveLocalPermissionLevel(entry);
  return resolved === 'manual' ? 'read_only' : resolved;
}

export function createDbPool(entry: DbEntry): Pool {
  const password =
    entry.password_stored || (entry.password_env ? process.env[entry.password_env] : undefined);

  if (!password) {
    throw new Error(
      `Password not available for "${entry.db_alias}". ` +
        (entry.password_env
          ? `Env var "${entry.password_env}" is not set.`
          : 'No stored password.'),
    );
  }

  const poolConfig: PoolConfig = {
    host: entry.host,
    port: entry.port,
    database: entry.database,
    user: entry.user,
    password,
    // One session per local command: the posture applied below is per-session
    // and must not leak between statements.
    max: 1,
    connectionTimeoutMillis: 5000,
  };

  const ssl = buildSslConfig(entry.ssl_mode, entry.ssl_root_cert);
  if (ssl) {
    poolConfig.ssl = ssl;
  }

  return new Pool(poolConfig);
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

export async function runDbQuery(args: string[]): Promise<void> {
  const isJson = args.includes('--json') || args.includes('-j');
  const cleanArgs = args.filter((a) => a !== '--json' && a !== '-j');

  const alias = cleanArgs[0];
  const sql = cleanArgs.slice(1).join(' ').trim();

  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db query <alias> "<SQL>"\n')}`);
    exit_(1);
  }

  if (!sql) {
    // If no query provided, redirect to db connect interactive mode
    return runDbConnect([alias]);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}\n`);
    exit_(1);
  }

  const deps = createLocalSqlDeps(entry);
  const preview = previewStatement(sql);
  if (!isJson) {
    console.log();
    console.log(
      `  ${C.dim('Permission:')} ${C.white(deps.permissionLevel)}  ${C.dim(`(actor ${LOCAL_OPERATOR_ID})`)}`,
    );
    console.log(
      `  ${C.dim('Preview:')}    ${C.white(truncateAnsi(preview, Math.max(40, terminalWidth() - 16)))}`,
    );
    console.log();
  }

  const spinner = createSpinner();
  if (!isJson) {
    spinner.start(`Executing query on ${C.cyan(alias)}…`);
  }

  const startedAt = Date.now();
  let result: LocalQueryResult;
  try {
    result = await executeLocalSql({ entry, sql, action: 'query' }, deps);
  } catch (err: unknown) {
    if (!isJson) spinner.stop();
    console.log();
    if (err instanceof LocalPermissionDeniedError) {
      console.log(`  ${C.red(S.cross)} ${C.red('Refused:')} ${err.message}`);
      console.log(
        `  ${C.dim('This statement is not permitted for a local operator at the resolved permission level.')}`,
      );
    } else if (err instanceof LocalAuditUnavailableError) {
      console.log(`  ${C.red(S.cross)} ${C.red(err.message)}`);
    } else if (err instanceof LocalRowCapError) {
      console.log(`  ${C.red(S.cross)} ${C.red(err.message)}`);
    } else if (
      /statement timeout|canceling statement due to statement timeout/i.test(errMessage(err))
    ) {
      console.log(
        `  ${C.red(S.cross)} Query exceeded the ${LOCAL_STATEMENT_TIMEOUT_MS}ms local statement timeout and was cancelled by PostgreSQL.`,
      );
    } else {
      console.log(`  ${C.red(S.cross)} Query error: ${C.red(errMessage(err))}`);
      const position = (err as { position?: unknown } | null)?.position;
      if (position !== undefined) {
        console.log(`  ${C.dim('Position:')} ${String(position)}`);
      }
    }
    console.log();
    exit_(1);
  }
  const duration = Date.now() - startedAt;

  if (!isJson) {
    spinner.stop();
  }

  if (isJson) {
    console.log(
      JSON.stringify(
        {
          alias,
          actor: LOCAL_OPERATOR_ID,
          permission_level: deps.permissionLevel,
          command: result.command,
          rowCount: result.rowCount,
          durationMs: duration,
          rowLimit: deps.maxRows ?? LOCAL_MAX_ROWS,
          rows: result.rows,
        },
        null,
        2,
      ),
    );
    exit_(0);
  }

  console.log();
  const fieldNames =
    result.fields.length > 0 ? result.fields.map((f) => f.name) : inferFieldNames(result.rows);
  if (result.rows.length > 0 && fieldNames.length > 0) {
    renderSqlResult(result.rows, fieldNames);
    console.log();
    console.log(
      `  ${C.dim(`(${result.rows.length} row${result.rows.length === 1 ? '' : 's'} in ${duration}ms)`)}`,
    );
  } else {
    console.log(`  ${C.green(S.check)} Query executed successfully (${C.dim(`${duration}ms`)})`);
    if (result.rowCount !== null && result.rowCount !== undefined) {
      console.log(
        `  ${C.dim('Command:')} ${C.white(result.command)}  ${C.dim('Rows affected:')} ${C.white(String(result.rowCount))}`,
      );
    }
  }
  console.log();

  exit_(0);
}

function inferFieldNames(rows: LocalRow[]): string[] {
  const first = rows[0];
  if (first && typeof first === 'object' && !Array.isArray(first)) {
    return Object.keys(first);
  }
  return rows.length > 0 ? ['value'] : [];
}

export async function runDbConnect(args: string[]): Promise<void> {
  const alias = args[0];
  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db connect <alias>')}\n`);
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}\n`);
    exit_(1);
  }

  const deps = createLocalSqlDeps(entry);
  console.log();
  console.log(
    `  ${C.bold('Database Console')}  ${C.dim(`[permission ${deps.permissionLevel}, actor ${LOCAL_OPERATOR_ID}]`)}`,
  );
  console.log(
    `  ${C.dim(`Host:`)} ${C.white(entry.host)}:${C.white(String(entry.port))}  ${C.dim('DB:')} ${C.white(entry.database)}  ${C.dim('User:')} ${C.white(entry.user)}`,
  );
  console.log(
    `  ${C.dim('Every statement is classified, permission-checked, timed out, row-capped, and audited.')}`,
  );
  console.log(
    `  ${C.dim('Type SQL to run, or')} ${C.cyan('\\dt')} ${C.dim('(tables),')} ${C.cyan('\\dn')} ${C.dim('(schemas),')} ${C.cyan('\\l')} ${C.dim('(databases),')} ${C.cyan('exit')} ${C.dim('to quit.')}`,
  );
  console.log();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `sw-agent (${C.cyan(alias)}) > `,
  });

  rl.prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      continue;
    }

    if (input === 'exit' || input === 'quit' || input === '\\q') {
      break;
    }

    if (input === 'clear') {
      clearScreen();
      rl.prompt();
      continue;
    }

    if (input === 'help' || input === '\\?') {
      console.log();
      console.log(`  ${C.bold('Console Commands:')}`);
      console.log(`    ${C.cyan('\\dt')}          List tables`);
      console.log(`    ${C.cyan('\\dn')}          List schemas`);
      console.log(`    ${C.cyan('\\l')}           List databases`);
      console.log(`    ${C.cyan('clear')}        Clear console screen`);
      console.log(`    ${C.cyan('exit')}         Quit database console`);
      console.log();
      console.log(
        `  ${C.dim('Every statement is recorded to')} ${C.cyan('~/.sw-agent/audit/audit.jsonl')} ${C.dim(`as ${LOCAL_OPERATOR_ID}.`)}`,
      );
      console.log();
      rl.prompt();
      continue;
    }

    const sql = expandConsoleCommand(input);

    const t0 = Date.now();
    try {
      const res = await executeLocalSql({ entry, sql, action: 'query' }, deps);
      const elapsed = Date.now() - t0;
      console.log();
      const fieldNames =
        res.fields.length > 0 ? res.fields.map((f) => f.name) : inferFieldNames(res.rows);
      if (res.rows.length > 0 && fieldNames.length > 0) {
        renderSqlResult(res.rows, fieldNames);
        console.log();
        console.log(
          `  ${C.dim(`(${res.rows.length} row${res.rows.length === 1 ? '' : 's'} in ${elapsed}ms)`)}`,
        );
      } else {
        console.log(
          `  ${C.green(S.check)} Query executed (${C.dim(`${elapsed}ms`)})${res.rowCount !== null ? ` - ${res.rowCount} rows affected` : ''}`,
        );
      }
      console.log();
    } catch (err: unknown) {
      console.log();
      if (err instanceof LocalPermissionDeniedError) {
        console.log(`  ${C.red(S.cross)} ${C.red('Refused:')} ${err.message}`);
      } else if (err instanceof LocalAuditUnavailableError || err instanceof LocalRowCapError) {
        console.log(`  ${C.red(S.cross)} ${C.red(err.message)}`);
      } else if (
        /statement timeout|canceling statement due to statement timeout/i.test(errMessage(err))
      ) {
        console.log(
          `  ${C.red(S.cross)} Statement exceeded the ${LOCAL_STATEMENT_TIMEOUT_MS}ms local timeout and was cancelled.`,
        );
      } else {
        console.log(`  ${C.red(S.cross)} ${C.red(errMessage(err))}`);
      }
      console.log();
    }

    rl.prompt();
  }

  rl.close();
  await deps.audit.flush().catch(() => undefined);
  console.log(`  ${C.dim('Connection closed.')}\n`);
  exit_(0);
}

function expandConsoleCommand(input: string): string {
  switch (input) {
    case '\\dt':
      return `
        SELECT table_schema AS schema, table_name AS table, table_type AS type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY table_schema, table_name;
      `;
    case '\\dn':
      return `
        SELECT schema_name AS schema, schema_owner AS owner
        FROM information_schema.schemata
        ORDER BY schema_name;
      `;
    case '\\l':
      return `
        SELECT datname AS database, pg_encoding_to_char(encoding) AS encoding
        FROM pg_database
        WHERE datistemplate = false
        ORDER BY datname;
      `;
    default:
      return input;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

function renderSqlResult(rows: LocalRow[], fieldNames: string[]): void {
  const maxW = Math.max(40, terminalWidth() - 4);
  const formattedRows = rows.map((r) => {
    const rowObj: Record<string, string> = {};
    for (const f of fieldNames) {
      const val = r[f];
      if (val === null || val === undefined) {
        rowObj[f] = C.dim('NULL');
      } else if (typeof val === 'boolean') {
        rowObj[f] = val ? C.green('true') : C.red('false');
      } else if (typeof val === 'object') {
        rowObj[f] = truncateAnsi(JSON.stringify(val), 40);
      } else {
        rowObj[f] = String(val);
      }
    }
    return rowObj;
  });

  const columns = fieldNames.map((name) => ({
    key: name,
    header: name.toUpperCase(),
    minWidth: Math.min(6, name.length),
    maxWidth: Math.max(12, Math.floor(maxW / fieldNames.length)),
    priority: 1,
  }));

  console.log(renderTable(formattedRows, { columns, maxWidth: maxW }));
}
