/**
 * Real PostgreSQL parser (libpg_query, compiled to WASM).
 *
 * This module owns the WASM lifecycle and exposes a small, typed AST helper
 * surface. It replaces the previous token-based classifier that decided
 * whether a statement was a read or a write by looking at the first
 * whitespace-delimited word.
 *
 * Design rules:
 *   - The WASM module is loaded exactly once, at startup, and awaited.
 *   - Any failure to load is fatal to SQL execution: `assertParserReady()`
 *     throws so callers fail CLOSED rather than falling back to heuristics.
 *   - A PostgreSQL syntax error THROWS `SqlParseError`. There is no
 *     "best-effort" parse: an input the grammar rejects has no classification.
 *   - No native compilation (WASM), so `node:*-alpine` images work with no
 *     build toolchain.
 */
import { loadModule, parseSync } from 'pgsql-parser';

/* eslint-disable @typescript-eslint/no-explicit-any */

let ready = false;
let initPromise: Promise<void> | null = null;

export class SqlParserUnavailableError extends Error {
  constructor(cause?: unknown) {
    super(
      'PostgreSQL parser is not available; refusing to classify SQL. ' +
        'Start the agent via runAgent()/initSqlParser() so the parser can load.',
    );
    this.name = 'SqlParserUnavailableError';
    this.cause = cause;
  }
}

export class SqlParseError extends Error {
  /** libpg_query error code, e.g. 'syntax_error'. */
  public readonly pgCode: string;
  /** 1-based cursor position from PostgreSQL, 0 if unknown. */
  public readonly cursorPosition: number;
  constructor(message: string, pgCode = 'syntax_error', cursorPosition = 0) {
    super(message);
    this.name = 'SqlParseError';
    this.pgCode = pgCode;
    this.cursorPosition = cursorPosition;
  }
}

/** Load the WASM parser. Idempotent and safe to call concurrently. */
export function initSqlParser(): Promise<void> {
  if (ready) return Promise.resolve();
  if (!initPromise) {
    initPromise = Promise.resolve(loadModule())
      .then(() => {
        ready = true;
      })
      .catch((err) => {
        initPromise = null;
        throw new SqlParserUnavailableError(err);
      });
  }
  return initPromise;
}

/** True once the WASM module is loaded and parsing is possible. */
export function isSqlParserReady(): boolean {
  return ready;
}

/** Throws unless the parser is loaded. Use at the top of any SQL path. */
export function assertParserReady(): void {
  if (!ready) throw new SqlParserUnavailableError();
}

/**
 * Parse one or more SQL statements into libpg_query raw parse nodes.
 *
 * @throws {SqlParserUnavailableError} if the WASM module is not loaded
 * @throws {SqlParseError} on a PostgreSQL syntax/semantic error
 */
export function parseSql(sql: string): RawParseResult {
  assertParserReady();
  if (typeof sql !== 'string') {
    throw new SqlParseError('SQL must be a string', 'invalid_sql', 0);
  }
  // libpg_query treats an empty/comment-only input as 0 statements, which is
  // valid. Callers decide what to do with an empty statement list.
  try {
    const result = parseSync(sql) as RawParseResult;
    return result;
  } catch (err: unknown) {
    throw toSqlParseError(err);
  }
}

function toSqlParseError(err: unknown): SqlParseError {
  const e = err as { message?: string; cursorPosition?: number; funcname?: string };
  const raw = typeof e?.message === 'string' ? e.message : String(err);
  // libpg_query formats errors as:
  //   {"message":"syntax error at or near \"x\"","funcname":"jsonErrorParse","detail":...}
  // or a plain "syntax error at or near ..." string depending on build.
  let message = raw;
  let code = 'syntax_error';
  let position = 0;
  try {
    const start = raw.indexOf('{');
    if (start !== -1 && raw.endsWith('}')) {
      const parsed = JSON.parse(raw.slice(start)) as {
        message?: string;
        funcname?: string;
        cursorPosition?: number;
      };
      if (parsed.message) message = parsed.message;
      if (parsed.cursorPosition) position = parsed.cursorPosition;
      if (parsed.funcname === 'jsonErrorParse') code = 'syntax_error';
    }
  } catch {
    // keep the raw message
  }
  return new SqlParseError(message, code, position);
}

/* ------------------------------------------------------------------ */
/* Raw parse tree types (the subset libpg_query emits that we consume) */
/* ------------------------------------------------------------------ */

export interface RawParseResult {
  version: number;
  stmts: RawStmt[];
}

export interface RawStmt {
  stmt: Record<string, any>;
  stmt_location?: number;
  stmt_len?: number;
}

/**
 * Root node type of a statement (e.g. 'SelectStmt', 'DropStmt').
 * Returns 'none' for an empty node.
 */
export function rootNodeType(stmt: RawStmt | undefined): string {
  if (!stmt || !stmt.stmt || typeof stmt.stmt !== 'object') return 'none';
  const keys = Object.keys(stmt.stmt);
  return keys.length > 0 ? keys[0] : 'none';
}

/**
 * The root node payload for a statement — i.e. the value of the single root
 * key, not the `{ NodeName: {...} }` wrapper. Callers that want to walk the
 * whole tree should use `walkAst(stmt.stmt, …)` instead.
 */
export function rootNode(stmt: RawStmt | undefined): any {
  const wrapper = stmt?.stmt;
  if (!wrapper || typeof wrapper !== 'object') return undefined;
  const keys = Object.keys(wrapper);
  return keys.length === 1 ? wrapper[keys[0]] : wrapper;
}

/** Keys that carry positional metadata, never a child node. */
const NON_NODE_KEYS: ReadonlySet<string> = new Set([
  'nodeType',
  'location',
  'stmt_location',
  'stmt_len',
]);

/**
 * Depth-first walk over every node in a parse tree, invoking `visit` on each
 * node. libpg_query marks nodes two ways depending on level: raw parse trees
 * wrap each node in a single-key object (e.g. `{ SelectStmt: {...} }`), while
 * `nodeType`-tagged trees use `{ nodeType: 'SelectStmt' }`. We support both.
 *
 * The node name is read from the *key* that holds the child, never from the
 * child's own keys. A wrapper can sit directly inside a list — e.g.
 * `fromClause[0].RangeFunction.functions[0].List.items[0].FuncCall` — and a
 * walk that only recognises a wrapper when it is the sole key of a *nested*
 * object silently misses every node in that position. That omission is a
 * security bug here: it made `SELECT * FROM pg_read_file('/etc/passwd') AS
 * t(contents)` collect zero function names and classify as a read.
 */
export function walkAst(node: unknown, visit: (type: string, payload: any) => void): void {
  if (node === null || node === undefined || typeof node !== 'object') return;

  if (Array.isArray(node)) {
    for (const child of node) walkAst(child, visit);
    return;
  }

  const obj = node as Record<string, any>;

  if (typeof obj.nodeType === 'string') {
    visit(obj.nodeType, obj);
  }

  for (const key of Object.keys(obj)) {
    if (NON_NODE_KEYS.has(key)) continue;
    const value = obj[key];
    if (value === null || typeof value !== 'object') continue;
    // `{ FuncCall: {...} }`: the key names the node, the value is the node.
    if (isNodeKey(key)) visit(key, value);
    walkAst(value, visit);
  }
}

/** Keys that look like libpg_query node names (CamelCase, ends in a node suffix). */
const NODE_SUFFIXES = [
  'Stmt',
  'Clause',
  'Expr',
  'Call',
  'Ref',
  'Spec',
  'Range',
  'Target',
  'Alias',
  'Object',
  'Def',
  'Elem',
  'Item',
  'List',
  'Res',
  'With',
  'Case',
  'A_Expr',
  'TypeName',
  'SortBy',
  'Locking',
  'Partition',
  'Constraint',
  'Action',
  'Trigger',
  'Rule',
  'Cmd',
  'Option',
  'Table',
  'Index',
  'Column',
  'Func',
  'Role',
  'Grant',
];

function isNodeKey(key: string): boolean {
  if (!/^[A-Z]/.test(key)) return false;
  if (key === 'String' || key === 'Integer' || key === 'Float' || key === 'Boolean') return false;
  return NODE_SUFFIXES.some((s) => key.endsWith(s)) || key.endsWith('Options');
}

/**
 * Extract every function name referenced anywhere in the statement, lower-cased
 * and dot-joined so both `pg_read_file` and `pg_catalog.pg_read_file` are
 * recognised. PostgreSQL folds unquoted identifiers to lower case; folding
 * quoted ones too (`"PG_READ_FILE"`) only ever makes the match set larger,
 * which is the safe direction.
 */
export function collectFunctionNames(stmt: RawStmt): string[] {
  const names = new Set<string>();
  walkAst(stmt.stmt, (type, payload) => {
    if (type !== 'FuncCall' || !payload || typeof payload !== 'object') return;
    const funcname = (payload as { funcname?: any[] }).funcname;
    if (!Array.isArray(funcname)) return;
    const parts: string[] = [];
    for (const part of funcname) {
      const sval =
        part?.String?.sval ??
        part?.A_Const?.sval?.sval ??
        part?.sval?.sval ??
        (typeof part === 'string' ? part : undefined);
      if (typeof sval === 'string') parts.push(sval.toLowerCase());
    }
    if (parts.length > 0) names.add(parts.join('.'));
  });
  return [...names];
}

/**
 * True when the SELECT contains a data-modifying CTE
 * (`WITH x AS (INSERT …) SELECT …`). PostgreSQL executes those even though the
 * outer statement is a SELECT.
 */
export function hasWritableCte(selectNode: any): boolean {
  const ctes = selectNode?.withClause?.ctes;
  if (!Array.isArray(ctes)) return false;
  for (const entry of ctes) {
    const cte = entry?.CommonTableExpr ?? entry;
    const query = cte?.ctequery;
    const root = rootNodeType({ stmt: query } as RawStmt);
    if (WRITE_ROOTS.has(root)) return true;
    if (root === 'SelectStmt' && hasWritableCte(rootNode({ stmt: query } as RawStmt))) return true;
  }
  return false;
}

/** SELECT … INTO <table> creates and populates a table. */
export function getSelectInto(selectNode: any): any | null {
  return selectNode?.intoClause ?? null;
}

/** Row-level locking clauses (FOR UPDATE / FOR SHARE / FOR NO KEY UPDATE …). */
export function getLockingClauses(selectNode: any): any[] {
  const lc = selectNode?.lockingClause;
  return Array.isArray(lc) ? lc : [];
}

/** Side effects a `SELECT` envelope can carry, anywhere in the statement. */
export interface ReadSideEffects {
  /** `SELECT … INTO <table>` creates and populates a table. */
  selectsInto: boolean;
  /** Row-level locking clauses: FOR UPDATE / SHARE / NO KEY UPDATE / KEY SHARE. */
  lockingClauses: any[];
  /** A data-modifying CTE (`WITH x AS (DELETE …) SELECT …`). */
  writableCte: boolean;
}

/**
 * Find every read-shaped side effect in a statement.
 *
 * This walks *all* `SelectStmt` nodes rather than only the outermost one: a
 * locking clause or a data-modifying CTE in a sub-select or CTE body takes the
 * same locks and performs the same writes as one at the top level.
 */
export function findReadSideEffects(stmt: RawStmt): ReadSideEffects {
  const effects: ReadSideEffects = { selectsInto: false, lockingClauses: [], writableCte: false };
  walkAst(stmt.stmt, (type, payload) => {
    if (type !== 'SelectStmt' || !payload || typeof payload !== 'object') return;
    if (getSelectInto(payload)) effects.selectsInto = true;
    const locks = getLockingClauses(payload);
    if (locks.length > 0) effects.lockingClauses.push(...locks);
    if (hasWritableCte(payload)) effects.writableCte = true;
  });
  return effects;
}

/**
 * True for `EXPLAIN ANALYZE`, which EXECUTES the statement it explains.
 *
 * libpg_query does not expose an `analyze` flag on `ExplainStmt`; the option is
 * a `DefElem` with `defname: 'analyze'` in the `options` list, so reading a
 * boolean field (as an earlier version did) always reported false.
 */
export function explainExecutesStatement(node: any): boolean {
  const options: any[] = Array.isArray(node?.options) ? node.options : [];
  return options.some((option: any) => {
    const elem = option?.DefElem ?? option;
    return String(elem?.defname ?? '').toLowerCase() === 'analyze';
  });
}

/**
 * Root nodes that are session/transaction utilities rather than schema changes.
 * They still require elevated capability (utility maps to `ddl` in the role
 * policy) but they are not DDL for audit purposes. Note that PostgreSQL's
 * ANALYZE also parses as `VacuumStmt`, so it is covered here.
 */
export const UTILITY_ROOTS: ReadonlySet<string> = new Set([
  'CheckPointStmt',
  'ClosePortalStmt',
  'ClusterStmt',
  'ConstraintsSetStmt',
  'DeallocateStmt',
  'DeclareCursorStmt',
  'DiscardStmt',
  'ExecuteStmt',
  'ListenStmt',
  'LoadStmt',
  'LockStmt',
  'NotifyStmt',
  'PrepareStmt',
  'TransactionStmt',
  'UnlistenStmt',
  'VacuumStmt',
  'VariableSetStmt',
]);

/** Statements whose root node performs row modifications. */
export const WRITE_ROOTS: ReadonlySet<string> = new Set([
  'InsertStmt',
  'UpdateStmt',
  'DeleteStmt',
  'MergeStmt',
]);

/**
 * Root nodes that are acceptable as "read only".
 *
 * This is an ALLOWLIST, not a denylist. Anything not listed here is not a
 * read. That is the entire point: adding a new PostgreSQL statement type
 * cannot accidentally make it readable.
 */
export const READ_ROOTS: ReadonlySet<string> = new Set(['SelectStmt', 'VariableShowStmt']);

/**
 * Root nodes that modify schema, roles, or persistent database state.
 * Anything not in READ_ROOTS or WRITE_ROOTS and not here is `utility`.
 */
export const DDL_ROOTS: ReadonlySet<string> = new Set([
  'AlterTableStmt',
  'AlterTableCmd',
  'AlterDomainStmt',
  'AlterEnumStmt',
  'AlterFamilyStmt',
  'AlterFdwStmt',
  'AlterFunctionStmt',
  'AlterObjectDependsStmt',
  'AlterObjectSchemaStmt',
  'AlterOperatorStmt',
  'AlterPolicyStmt',
  'AlterRoleStmt',
  'AlterRoleSetStmt',
  'AlterSubscriptionStmt',
  'AlterSystemStmt',
  'AlterTableMoveAllStmt',
  'AlterTSDictionaryStmt',
  'AlterTSConfigurationStmt',
  'AlterUserMappingStmt',
  'AlterDatabaseStmt',
  'AlterDatabaseRefreshCollStmt',
  'AlterDatabaseSetStmt',
  'ClusterStmt',
  'CommentStmt',
  'CompositeTypeStmt',
  'CreateAmStmt',
  'CreateCastStmt',
  'CreateConversionStmt',
  'CreateDomainStmt',
  'CreateEnumStmt',
  'CreateEventTrigStmt',
  'CreateExtensionStmt',
  'CreateExtensionContentsStmt',
  'CreateFdwStmt',
  'CreateForeignServerStmt',
  'CreateForeignTableStmt',
  'CreateFunctionStmt',
  'CreateMappingStmt',
  'CreatePolicyStmt',
  'CreatePLangFunctionStmt',
  'CreateRangeStmt',
  'CreateRoleStmt',
  'CreateRuleStmt',
  'CreateSchemaStmt',
  'CreateSeqStmt',
  'CreateStatsStmt',
  'CreateSubscriptionStmt',
  'CreateTableAsStmt',
  'CreateTableSpaceStmt',
  'CreateTransformStmt',
  'CreateTrigStmt',
  'CreateUserMappingStmt',
  'CreateStmt',
  'DefineStmt',
  'DropOwnedStmt',
  'DropRoleStmt',
  'DropStmt',
  'DropTableSpaceStmt',
  'DropUserStmt',
  'GrantRoleStmt',
  'GrantStmt',
  'IndexStmt',
  'LockStmt',
  'ReassignOwnedStmt',
  'RefreshMatViewStmt',
  'ReindexStmt',
  'RenameStmt',
  'RuleStmt',
  'SecLabelStmt',
  'TruncateStmt',
  'ViewStmt',
]);

/**
 * Root nodes that cannot run inside a transaction block.
 * Used by the migration strategy detector, which previously mis-classified
 * `DROP INDEX CONCURRENTLY` and `ALTER SYSTEM` as transactional.
 */
export const NON_TRANSACTIONAL_ROOTS: ReadonlySet<string> = new Set([
  'AlterDatabaseStmt',
  'AlterDatabaseSetStmt',
  'AlterSubscriptionStmt',
  'AlterSystemStmt',
  'CheckPointStmt',
  'ClusterStmt',
  'ClosePortalStmt',
  'CopyStmt',
  'CreateDatabaseStmt',
  'CreateSubscriptionStmt',
  'DiscardStmt',
  'DoStmt',
  'DropSubscriptionStmt',
  'IndexStmt',
  'ListenStmt',
  'LoadStmt',
  'NotifyStmt',
  'ReindexStmt',
  'RefreshMatViewStmt',
  'VacuumStmt',
  'ClusterStmt',
  'PrepareStmt',
  'ExecuteStmt',
  'DeclareCursorStmt',
]);

/** Roots that can execute arbitrary code or reach outside the database. */
export const EXECUTABLE_ROOTS: ReadonlySet<string> = new Set([
  'DoStmt',
  'CallStmt',
  'ExecuteStmt',
  'CreatePLangFunctionStmt',
]);

/**
 * Functions that must never be reachable from a statement classified as a
 * read, because they mutate state, read server files, reach other systems, or
 * produce a side effect that escapes the transaction.
 * Matched case-insensitively against the fully-qualified name *and* against
 * the bare name, so `pg_catalog.pg_read_file` and `pg_read_file` both match.
 *
 * This list is NOT a security boundary and must not be presented as one. It is
 * defence in depth in front of the control that is: every function a statement
 * references is resolved against `pg_proc` and only `IMMUTABLE`, non-`SECURITY
 * DEFINER` calls count as a read
 * (`statement-classifier.ts` → `classifySelect`, `function-effects.ts`). That
 * control is name-independent, which is what closes the class this list cannot:
 * an operator's own `SECURITY DEFINER` helper around `pg_read_file`, or any
 * VOLATILE function that INSERTs, parses as a plain `SELECT` and appears on no
 * list at all.
 *
 * The claim that used to sit here — that a miss "cannot reach the host" because
 * the connection is read-only — was FALSE. `default_transaction_read_only`
 * constrains writes to relations and nothing else, and it does not span a
 * second connection opened inside a function body. A read of a server file, a
 * `NOTIFY` delivered on commit, an XID allocation, or a `dblink` round trip all
 * succeed at `read_only`; only the write arm of a VOLATILE function is blocked.
 * `RECOMMENDED_PG_ROLE` in `src/permissions/role-policy.ts` (the EXECUTE
 * revokes, plus the default-privileges row that stops them decaying) is what a
 * miss cannot get past.
 */
export const DENIED_READ_FUNCTIONS: ReadonlySet<string> = new Set([
  // server filesystem
  'pg_read_file',
  'pg_read_binary_file',
  'pg_read_server_file',
  'pg_ls_dir',
  'pg_stat_file',
  'pg_ls_logdir',
  'pg_ls_waldir',
  'pg_ls_tmpdir',
  'pg_ls_archive_statusdir',
  // large objects
  'lo_import',
  'lo_export',
  'lo_unlink',
  'lo_truncate',
  'lo_create',
  'lo_open',
  'lo_close',
  'lo_from_bytea',
  'lo_get',
  'lo_put',
  // sequences / catalogs
  'setval',
  'nextval',
  'currval',
  'lastval',
  'set_config',
  'pg_advisory_lock',
  'pg_advisory_lock_shared',
  'pg_advisory_xact_lock',
  'pg_try_advisory_lock',
  'pg_try_advisory_xact_lock',
  'pg_advisory_unlock',
  'pg_advisory_unlock_all',
  // Notification and transaction-identity allocation.
  //
  // `pg_notify` is delivered when the enclosing transaction commits and is NOT
  // rolled back with it, and PostgreSQL permits it inside a read-only
  // transaction, so it is an exfiltration and message-injection channel that no
  // write restriction covers. The `txid_*` / `pg_snapshot_*` /
  // `pg_current_xact_id*` functions allocate or expose a real transaction id,
  // which advances WAL and burns xid space — and `txid_current()` is the
  // cheapest XID oracle there is. `pg_snapshot_xip` and `pg_snapshot_xmax` are
  // pure readers of a snapshot, and are listed with their family rather than on
  // their own merits. `pg_snapshot_time` is deliberately NOT listed: it was
  // removed in PostgreSQL 13 and in every release that still has it, it is an
  // IMMUTABLE function that only extracts a timestamp from its argument.
  'pg_notify',
  'pg_notify_async',
  'txid_current',
  'txid_current_snapshot',
  'pg_snapshot_xip',
  'pg_snapshot_xmax',
  'pg_current_xact_id',
  'pg_current_xact_id_if_assigned',
  'pg_current_snapshot',
  // session / server control
  'pg_terminate_backend',
  'pg_cancel_backend',
  'pg_reload_conf',
  'pg_rotate_logfile',
  'pg_create_physical_replication_slot',
  'pg_create_logical_replication_slot',
  'pg_drop_replication_slot',
  'pg_export_snapshot',
  'pg_import_snapshot',
  'pg_log_backend_memory_contexts',
  // replication, failover and WAL — cluster-wide, non-transactional effects
  'pg_promote',
  'pg_backup_start',
  'pg_backup_stop',
  'pg_switch_wal',
  'pg_create_restore_point',
  'pg_logical_emit_message',
  'pg_logical_slot_get_changes',
  'pg_logical_slot_peek_changes',
  'pg_replication_slot_advance',
  'pg_replication_origin_create',
  'pg_replication_origin_drop',
  'pg_replication_origin_advance',
  'pg_wal_replay_pause',
  'pg_wal_replay_resume',
  'pg_resetwal',
  // statistics / server state
  'pg_stat_reset',
  'pg_stat_reset_single_table_counters',
  // remote execution
  'dblink',
  'dblink_exec',
  'postgres_fdw',
  'file_fdw',
  'sqlite_fdw',
  // extension / object creation reachable from an expression context
  'pg_tempfile',
  'pg_file_write',
  'pg_logdir_ls',
  // time / resource abuse is handled by statement_timeout, listed for clarity
  'pg_sleep',
  'pg_sleep_for',
  'pg_sleep_until',
  'pg_sleep_background',
]);

/**
 * Name prefixes denied for the same reason as {@link DENIED_READ_FUNCTIONS}.
 *
 * Families are matched on the bare function name so `dblink_fetch_result` and
 * `postgres_fdw_validator` cannot be used to walk around the explicit list.
 * Prefix rules are cheaper than enumerating every member of a function family
 * and cannot be evaded by picking a sibling we forgot to write down.
 *
 * `txid_`, `pg_advisory_` and `pg_snapshot_` are here because the families
 * grow: `pg_advisory_xact_lock_shared` and `txid_current_if_assigned` exist on
 * some releases and not others.
 */
export const DENIED_READ_FUNCTION_PREFIXES: readonly string[] = [
  'dblink',
  'dblink_',
  'postgres_fdw',
  'file_fdw',
  'sqlite_fdw',
  'mysql_fdw',
  'pg_read_',
  'pg_ls_',
  'pg_stat_file',
  'pg_stat_reset',
  'pg_notify',
  'pg_advisory_',
  'txid_',
  'pg_snapshot_',
  'pg_current_xact_id',
  'pg_current_snapshot',
  'lo_',
];

/**
 * Name suffixes denied for the same reason as {@link DENIED_READ_FUNCTIONS}.
 *
 * A prefix cannot express "every function whose name ends this way", and the
 * families that matter are named by their suffix: `dblink_exec`,
 * `dblink_send_query`, `postgres_fdw_disconnect`, `mysql_fdw_connect_u`. They
 * are matched on the bare function name, exactly as the prefixes are.
 *
 * This costs generality, not safety: a function called `x_disconnect` that does
 * nothing is refused as a read, which is the correct direction for a control
 * that has to be conservative about names it cannot resolve.
 */
export const DENIED_READ_FUNCTION_SUFFIXES: readonly string[] = [
  '_exec',
  '_connect_u',
  '_connect',
  '_disconnect',
  '_send_query',
];

/** True when a (lower-cased, dot-joined) function name is denied in a read. */
export function isDeniedReadFunction(name: string): boolean {
  const full = name.toLowerCase();
  const bare = full.includes('.') ? full.slice(full.lastIndexOf('.') + 1) : full;
  if (DENIED_READ_FUNCTIONS.has(full) || DENIED_READ_FUNCTIONS.has(bare)) return true;
  if (DENIED_READ_FUNCTION_PREFIXES.some((prefix) => bare.startsWith(prefix))) return true;
  return DENIED_READ_FUNCTION_SUFFIXES.some((suffix) => bare.endsWith(suffix));
}

/** Every denylisted function a statement references. */
export function findDeniedReadFunction(fnNames: Iterable<string>): string[] {
  const hits: string[] = [];
  for (const full of fnNames) {
    if (isDeniedReadFunction(full)) hits.push(full);
  }
  return hits;
}

/**
 * Node-level transactionality that the root-node set cannot express.
 * libpg_query uses a `concurrent` boolean on IndexStmt and DropStmt.
 */
export function isNonTransactionalNode(rootType: string, node: any): boolean {
  if (rootType === 'IndexStmt' || rootType === 'DropStmt') {
    return node?.concurrent === true;
  }
  return NON_TRANSACTIONAL_ROOTS.has(rootType);
}
