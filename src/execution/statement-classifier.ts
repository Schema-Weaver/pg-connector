/**
 * Statement classification, driven by the real PostgreSQL grammar.
 *
 * The previous implementation split the SQL on whitespace and looked at the
 * first token. That is unsound: it classified `SELECT 1; DROP TABLE users` as a
 * read, and it classified `SELECT * INTO t ...` as a read even though it
 * creates a table. Both were reachable from the cloud and both executed.
 *
 * This implementation parses with libpg_query (WASM) and classifies from the
 * AST. The guarantee it provides, and its exact limits:
 *
 *   - The number of statements is COUNTED by PostgreSQL's own grammar, so
 *     multi-statement smuggling is structural rather than lexical: a `;` inside
 *     a string literal, a dollar-quoted body, a quoted identifier or a comment
 *     cannot split a statement, and a real second statement always is visible.
 *     `statement_count !== 1` is never a read.
 *   - Classification is ALLOWLIST-based on the root node: a statement type this
 *     module does not recognise is `unknown`, which is not a read.
 *   - `SELECT` is treated as a command envelope, not a read-only assertion.
 *     `SELECT … INTO`, row-locking clauses, data-modifying CTEs, executable
 *     blocks and denylisted volatile/privileged functions are detected anywhere
 *     in the statement and demote it out of `read`.
 *   - A parse failure and an unavailable parser both FAIL CLOSED: they throw,
 *     and no lexical heuristic is ever consulted as a fallback. An
 *     authorization decision must never be made from this module's guesswork.
 *   - A function reference is a claim that has to be PROVED. Every function the
 *     statement calls is resolved against `pg_proc` on the caller's connection
 *     (`function-effects.ts`), and only `provolatile = 'i' AND prosecdef =
 *     false` counts as a read. A VOLATILE or SECURITY DEFINER function, an
 *     unknown one, and — deliberately — one the catalogue could not be asked
 *     about all carry `side_effect` and are never a provable read. With no
 *     resolver supplied every statement that calls anything is escalated; see
 *     {@link ClassifyOptions.resolveFunctionEffects}.
 *
 * It is still not a substitute for PostgreSQL's own enforcement. The database
 * is the authority on what a statement does, and the agent's read-only
 * guarantee is `default_transaction_read_only = on` on the connection — which
 * constrains WRITES only, and therefore does not constrain a function that
 * reads a file, notifies a channel, or allocates a transaction id. Those are
 * why the function-effect analysis above is a control in its own right rather
 * than an optimisation of the deny-list in `sql-parser.ts`.
 */
import {
  DDL_ROOTS,
  EXECUTABLE_ROOTS,
  UTILITY_ROOTS,
  READ_ROOTS,
  WRITE_ROOTS,
  SqlParseError,
  SqlParserUnavailableError,
  collectFunctionNames,
  explainExecutesStatement,
  findDeniedReadFunction,
  findReadSideEffects,
  isNonTransactionalNode,
  parseSql,
  rootNode,
  rootNodeType,
  walkAst,
} from './sql-parser';
import type { RawStmt } from './sql-parser';
import { unresolvedRecord } from './function-effects';
import type { FunctionEffectAnalysis, FunctionEffectRecord, FunctionEffectResolver } from './function-effects';
import type { SideEffectKind } from './function-effects';
import type { StatementClassification } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Reasons a syntactically valid SELECT is still not a safe read. */
export type ReadViolation =
  | 'selects_into'
  | 'row_locking'
  | 'writable_cte'
  | 'denied_function'
  | 'side_effect'
  | 'multiple_statements'
  | 'executable_block'
  | 'parse_error'
  | 'parser_unavailable';

/**
 * Violations that mean "this parsed as a read but it is not one".
 *
 * A statement carrying any of these is never reported as a provable read, and
 * the permission layer treats it as a privileged operation rather than a
 * `query_read`.
 */
export const READ_ESCAPE_VIOLATIONS: ReadonlySet<ReadViolation> = new Set<ReadViolation>([
  'selects_into',
  'row_locking',
  'writable_cte',
  'denied_function',
  'side_effect',
  'executable_block',
]);

/**
 * Options for a classification that can consult a database.
 *
 * `resolveFunctionEffects` is optional and its absence is meaningful: without
 * it this module cannot prove any function call is effect-free, so it reports
 * `side_effect` for every one of them and the statement is escalated. That is
 * the fail-closed direction, and it is required — the alternative (treating an
 * absent catalogue verdict as "safe") is the vulnerability being fixed.
 */
export interface ClassifyOptions {
  resolveFunctionEffects?: FunctionEffectResolver;
}

/** An analysis that says nothing, used when there is nothing to say. */
const NO_FUNCTION_EFFECTS: FunctionEffectAnalysis = { records: [], analysed: true };

export class StatementClassificationError extends Error {
  constructor(
    message: string,
    public readonly code: ReadViolation | 'unknown_statement',
  ) {
    super(message);
    this.name = 'StatementClassificationError';
  }
}

function base(
  type: StatementClassification['type'],
  kind: string,
  transactional: boolean,
  verb: string,
  extra: Partial<StatementClassification> = {},
  effects: FunctionEffectAnalysis = NO_FUNCTION_EFFECTS,
): StatementClassification {
  return {
    type,
    kind,
    transactional,
    verb,
    statement_count: 1,
    parse_ok: true,
    read_violations: [],
    function_effects: effects.records,
    side_effects: uniqueSideEffects(effects.records),
    ...extra,
  };
}

function uniqueSideEffects(records: readonly FunctionEffectRecord[]): SideEffectKind[] {
  const kinds = new Set<SideEffectKind>();
  for (const record of records) {
    for (const kind of record.side_effects) kinds.add(kind);
  }
  return [...kinds];
}

/**
 * Classify a SQL string using the PostgreSQL parser.
 *
 * @throws {SqlParserUnavailableError} if the parser has not been initialised
 * @throws {SqlParseError} if PostgreSQL cannot parse the input
 */
export async function classifyStatement(
  sql: string,
  options: ClassifyOptions = {},
): Promise<StatementClassification> {
  const { stmts } = parseSql(sql);
  return classifyStatements(stmts, options);
}

/**
 * Classify a parsed statement list, resolving every function the statements
 * reference against `pg_proc` in ONE batched read.
 *
 * The names of every statement in the list are collected before the lookup, so
 * a migration plan of twenty statements still costs one catalogue query.
 */
export async function classifyStatements(
  stmts: RawStmt[],
  options: ClassifyOptions = {},
): Promise<StatementClassification> {
  const names = stmts.flatMap((stmt) => collectFunctionNames(stmt));
  const effects =
    names.length === 0
      ? NO_FUNCTION_EFFECTS
      : await (options.resolveFunctionEffects
          ? options.resolveFunctionEffects(names)
          : Promise.resolve(unanalysedAnalysis(names)));
  return classifyParsedStatementsWith(stmts, effects);
}

/**
 * An analysis for names nothing could be asked about.
 *
 * `resolved: false` and `effect: 'unknown'` for each, which is what makes
 * `isProvableRead()` refuse the statement. The records are still emitted so the
 * audit trail names the functions that could not be cleared.
 */
function unanalysedAnalysis(names: readonly string[]): FunctionEffectAnalysis {
  return {
    records: names.map((name) => unresolvedRecord(name)),
    analysed: false,
  };
}

/**
 * Classify using an already-parsed statement list (sync; parser must be ready).
 *
 * No catalogue is consulted here, so any statement that calls a function is
 * escalated. Callers that hold a connection should use {@link classifyStatements}
 * (or `classifyStatement`) with a resolver instead.
 */
export function classifyParsedStatements(stmts: RawStmt[]): StatementClassification {
  const names = stmts.flatMap((stmt) => collectFunctionNames(stmt));
  return classifyParsedStatementsWith(
    stmts,
    names.length === 0 ? NO_FUNCTION_EFFECTS : unanalysedAnalysis(names),
  );
}

function classifyParsedStatementsWith(
  stmts: RawStmt[],
  effects: FunctionEffectAnalysis,
): StatementClassification {
  const statementCount = stmts.length;

  if (statementCount === 0) {
    return base('unknown', 'EMPTY', true, '', {
      statement_count: 0,
      read_violations: ['parse_error'],
    });
  }

  if (statementCount > 1) {
    // Classify by the MOST dangerous statement present. Never let a leading
    // SELECT launder a trailing DROP.
    let worst: StatementClassification = base('read', 'SELECT', true, 'SELECT', {
      statement_count: statementCount,
      read_violations: ['multiple_statements'],
    });
    const violations: string[] = ['multiple_statements'];
    let sawNonRead = false;
    for (const stmt of stmts) {
      const one = classifySingleStatement(stmt, effects);
      for (const v of one.read_violations) {
        if (!violations.includes(v)) violations.push(v);
      }
      if (one.type !== 'read') sawNonRead = true;
      if (severity(one.type) > severity(worst.type)) worst = one;
    }
    if (sawNonRead) {
      // Keep `worst`'s kind/verb, but report it as a multi-statement payload
      // with every violation the individual statements carried.
      return {
        ...worst,
        statement_count: statementCount,
        kind: `${worst.kind} + ${statementCount - 1} more statement(s)`,
        read_violations: violations,
      };
    }
    // Every statement parsed as a read; the payload is still refused because
    // more than one statement would be executed in a single round trip.
    return {
      ...worst,
      statement_count: statementCount,
      kind: `${statementCount} statements`,
      read_violations: violations,
    };
  }

  return classifySingleStatement(stmts[0], effects);
}

function severity(t: StatementClassification['type']): number {
  switch (t) {
    case 'read':
      return 0;
    case 'utility':
      return 1;
    case 'write':
      return 2;
    case 'ddl':
      return 3;
    default:
      return 4;
  }
}

function classifySingleStatement(
  stmt: RawStmt,
  effects: FunctionEffectAnalysis,
): StatementClassification {
  const rootType = rootNodeType(stmt);
  const node = rootNode(stmt);
  const verb = deriveVerb(rootType, node);

  // ---- allowlisted reads -------------------------------------------------
  if (READ_ROOTS.has(rootType)) {
    if (rootType === 'SelectStmt') return classifySelect(stmt, effects);
    // VariableShowStmt (SHOW) has no expression context, so there is nothing
    // for a function call to hide in.
    return base('read', rootType, true, verb, {}, effects);
  }

  if (rootType === 'ExplainStmt') {
    // EXPLAIN is transparent to the statement it wraps, so classify the inner
    // statement with the same rules. EXPLAIN ANALYZE additionally EXECUTES it,
    // which is only sound when the wrapped statement is itself a provable read.
    const analyze = explainExecutesStatement(node);
    const inner = classifySingleStatement({ stmt: node?.query } as RawStmt, effects);
    if (inner.type === 'read' && inner.read_violations.length === 0) {
      return base('read', analyze ? 'EXPLAIN ANALYZE' : 'EXPLAIN', true, 'EXPLAIN');
    }
    if (analyze) {
      return {
        ...inner,
        kind: `EXPLAIN ANALYZE ${inner.kind}`,
        read_violations: [
          ...inner.read_violations,
          ...(inner.read_violations.includes('executable_block')
            ? []
            : (['executable_block'] as ReadViolation[])),
        ],
      };
    }
    return { ...inner, kind: `EXPLAIN ${inner.kind}` };
  }

  // ---- writes ------------------------------------------------------------
  if (WRITE_ROOTS.has(rootType)) {
    return base('write', rootType.replace(/Stmt$/, ''), true, verb, {}, effects);
  }

  // Checked before the DDL and utility tables because two of these roots are
  // listed there as well (`ExecuteStmt`, `CreatePLangFunctionStmt`). Matching
  // them first is what makes `EXECUTE` and a PL/pgSQL `CREATE FUNCTION` carry
  // `executable_block`, which is the signal auto-upgrade refuses on: both run
  // code whose body was never classified.
  if (EXECUTABLE_ROOTS.has(rootType)) {
    return base('ddl', rootType.replace(/Stmt$/, ''), true, verb, {
      read_violations: ['executable_block'],
    });
  }

  if (rootType === 'CopyStmt') {
    // COPY FROM writes rows. COPY TO PROGRAM runs a command on the server;
    // COPY TO 'file' writes the server's filesystem. Only COPY … TO STDOUT is a
    // read, and it is the only form the classifier will ever call one.
    const isFrom = node?.is_from === true;
    const hasProgram = Boolean(node?.is_program);
    if (isFrom) return base('write', 'COPY FROM', true, verb);
    if (hasProgram) {
      return base('ddl', 'COPY TO PROGRAM', true, verb, {
        read_violations: ['executable_block'],
      });
    }
    if (copyDestinationFile(node) !== null) {
      return base('ddl', 'COPY TO FILE', true, verb);
    }
    return base('read', 'COPY TO STDOUT', true, verb);
  }

  // ---- schema / role / persistent state ---------------------------------
  if (DDL_ROOTS.has(rootType)) {
    return base(
      'ddl',
      rootType.replace(/Stmt$/, ''),
      !isNonTransactionalNode(rootType, node),
      verb,
      {},
      effects,
    );
  }

  // ---- session / transaction utilities -----------------------------------
  if (UTILITY_ROOTS.has(rootType)) {
    if (rootType === 'VariableSetStmt') return classifyVariableSet(node, verb);
    return base(
      'utility',
      rootType.replace(/Stmt$/, ''),
      !isNonTransactionalNode(rootType, node),
      verb,
      {},
      effects,
    );
  }

  // Unknown root node: NOT a read. Fail closed by requiring DDL capability.
  return base('unknown', 'UNKNOWN', true, verb, {
    read_violations: ['executable_block'],
  });
}

/**
 * The destination file of a `COPY … TO 'path'`, or `null` for `STDOUT` and
 * `PROGRAM`. `pgsql-parser` normalises the path to a plain string; the wrapped
 * `{ String: { sval } }` form is accepted too so a change in that library's
 * shape cannot silently turn every `COPY TO` into a read.
 */
function copyDestinationFile(node: any): string | null {
  const filename = node?.filename;
  const sval = typeof filename === 'string' ? filename : filename?.String?.sval;
  return typeof sval === 'string' && sval.length > 0 ? sval : null;
}

/**
 * Classify a `SELECT` envelope.
 *
 * `SELECT` is not a read-only assertion in PostgreSQL, so everything that can
 * mutate state or reach outside the database is looked for across the whole
 * statement — including sub-selects, CTEs and set-returning functions in FROM.
 *
 * The third source of demotion is the function catalogue: a call is only a read
 * when `pg_proc` says `IMMUTABLE` and not `SECURITY DEFINER`. This is what
 * catches a function no deny-list can name, because it does not depend on the
 * name at all.
 */
function classifySelect(stmt: RawStmt, effects: FunctionEffectAnalysis): StatementClassification {
  const violations: ReadViolation[] = [];
  const shape = findReadSideEffects(stmt);

  if (shape.selectsInto) violations.push('selects_into');
  if (shape.lockingClauses.length > 0) violations.push('row_locking');
  if (shape.writableCte) violations.push('writable_cte');

  const names = collectFunctionNames(stmt);
  const denied = findDeniedReadFunction(names);
  if (denied.length > 0) violations.push('denied_function');

  // Only this statement's own references, so a plan entry does not inherit the
  // verdicts of its neighbours.
  const referenced = new Set(names.map((name) => name.toLowerCase()));
  const records = effects.records.filter((record) => referenced.has(record.name.toLowerCase()));
  const unsafe = records.filter((record) => record.effect !== 'immutable' || !record.resolved);
  if (records.length > 0 && unsafe.length > 0) violations.push('side_effect');

  if (violations.length > 0) {
    const named = denied[0] ?? unsafe[0]?.name;
    const kind = named ? `SELECT (${named})` : `SELECT (${violations.join(', ')})`;
    // Not a read. Reported as `write` so it can never satisfy a `query_read`
    // check, and so it is visible as a mutation attempt in the audit trail.
    return base(
      'write',
      kind,
      true,
      'SELECT',
      { read_violations: violations },
      { records, analysed: effects.analysed },
    );
  }

  return base('read', 'SELECT', true, 'SELECT', {}, { records, analysed: effects.analysed });
}

/**
 * `SET` / `RESET` classification.
 *
 * Most GUCs are harmless session tuning, but a handful change who the session
 * is or what it is allowed to do. Those are privilege changes, not utilities,
 * and must require the `ddl` capability.
 */
function classifyVariableSet(node: any, verb: string): StatementClassification {
  const name = String(node?.name ?? '').toLowerCase();
  const kind = String(node?.kind ?? 'VAR_SET_VALUE').toUpperCase();

  const PRIVILEGE_GUCS = new Set([
    'role',
    'session_authorization',
    'session_replication_role',
    'transaction_read_only',
    'default_transaction_read_only',
  ]);

  if (PRIVILEGE_GUCS.has(name) || makesTransactionWritable(node)) {
    return base('ddl', `SET ${name.toUpperCase()}`, true, verb, {
      read_violations: ['executable_block'],
    });
  }

  return base('utility', `SET ${kind}`, true, verb);
}

/**
 * True when the statement opens a writable transaction — `SET TRANSACTION READ
 * WRITE` or `SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE`.
 *
 * `default_transaction_read_only = on` is not by itself sufficient: PostgreSQL
 * lets a transaction override it with an explicit `READ WRITE`, so a statement
 * that does this in the middle of a request is a request to leave read-only
 * mode, not session tuning. The parse tree spells it as a `DefElem` with
 * `defname: 'transaction_read_only'` whose argument is the boolean, where
 * `false` means `READ WRITE`.
 */
function makesTransactionWritable(node: any): boolean {
  const args: any[] = Array.isArray(node?.args) ? node.args : [];
  for (const arg of args) {
    const elem = arg?.DefElem ?? arg;
    const defname = String(elem?.defname ?? '').toLowerCase();
    if (defname === 'transaction_read_only' || defname === 'default_transaction_read_only') {
      if (isFalseArgument(elem)) return true;
    }
  }
  return false;
}

/**
 * True when a `DefElem` argument is the boolean `false`.
 *
 * libpg_query's JSON encoding omits zero-valued protobuf fields, so `false`
 * arrives either as an absent `ival`, as an empty `ival` object or as
 * `ival: 0`, while `true` always arrives as `ival: { ival: 1 }`.
 */
function isFalseArgument(elem: any): boolean {
  const constant = elem?.arg?.A_Const;
  if (constant === undefined || constant === null) return true;
  if (constant.sval !== undefined) return false;
  const ival = constant.ival;
  if (ival === undefined) return true;
  return ival.ival === undefined || ival.ival === 0;
}

function deriveVerb(rootType: string, node: any): string {
  switch (rootType) {
    case 'SelectStmt':
      return 'SELECT';
    case 'InsertStmt':
      return 'INSERT';
    case 'UpdateStmt':
      return 'UPDATE';
    case 'DeleteStmt':
      return 'DELETE';
    case 'MergeStmt':
      return 'MERGE';
    case 'CreateStmt':
      return 'CREATE';
    case 'IndexStmt':
      return 'CREATE INDEX';
    case 'CreateTableAsStmt':
      return 'CREATE TABLE AS';
    case 'ViewStmt':
      return 'CREATE VIEW';
    case 'AlterTableStmt':
      return 'ALTER';
    case 'DropStmt':
      return 'DROP';
    case 'TruncateStmt':
      return 'TRUNCATE';
    case 'GrantStmt':
      return String(node?.is_grant === false ? 'REVOKE' : 'GRANT');
    case 'GrantRoleStmt':
      return String(node?.is_grant === false ? 'REVOKE ROLE' : 'GRANT ROLE');
    case 'VariableSetStmt':
      return 'SET';
    case 'VariableShowStmt':
      return 'SHOW';
    case 'TransactionStmt':
      return String(node?.kind ?? 'BEGIN').toUpperCase();
    case 'ExplainStmt':
      return 'EXPLAIN';
    case 'CopyStmt':
      return 'COPY';
    case 'VacuumStmt':
      return 'VACUUM';
    case 'ReindexStmt':
      return 'REINDEX';
    case 'ClusterStmt':
      return 'CLUSTER';
    case 'DoStmt':
      return 'DO';
    case 'CallStmt':
      return 'CALL';
    case 'ExecuteStmt':
      return 'EXECUTE';
    case 'LockStmt':
      return 'LOCK';
    case 'AlterSystemStmt':
      return 'ALTER SYSTEM';
    case 'CreateRoleStmt':
      return 'CREATE ROLE';
    case 'AlterRoleStmt':
      return 'ALTER ROLE';
    case 'RefreshMatViewStmt':
      return 'REFRESH MATERIALIZED VIEW';
    case 'DeclareCursorStmt':
      return 'DECLARE';
    case 'CommentStmt':
      return 'COMMENT';
    default:
      return rootType.replace(/Stmt$/, '').toUpperCase();
  }
}

/*
 * There are deliberately no `isReadOnly` / `isTransactional` / `extractVerb`
 * wrappers here any more.
 *
 * They each parsed the SQL and then read a field off the classification the
 * caller could already have, and nothing in production called them — the only
 * references were tests written to exercise them, which made them look covered
 * while shipping nothing. Every rule they named is enforced, in production, by
 * the thing that actually needs it:
 *
 *   - "is this a provable read?" is `isProvableRead` in
 *     `permissions/role-policy.ts`, the predicate `PermissionChecker.check` uses
 *     for the `read_only`, `auto_upgrade` and `manual` levels and for the
 *     capability a classification requires. It is the identical rule
 *     (`type === 'read' && parse_ok && statement_count === 1 && no read
 *     violations && every referenced function proved IMMUTABLE by pg_proc`);
 *     keeping a second copy here invited the two to drift.
 *   - "can this run inside a transaction?" is `classification.transactional`,
 *     which `execution/non-tx-detector.ts` and the migration runner read, and
 *     `aggregateClassification` in `permissions/checker.ts` combines.
 *   - "what is the verb?" is `classification.verb`, interpolated into the
 *     intent-mismatch reason in `permissions/checker.ts` and into the
 *     auto-upgrade refusal reasons in `permissions/auto-upgrade.ts`.
 */

/**
 * Classify and throw instead of returning, for call sites that must fail
 * closed on anything they cannot prove is a read.
 */
export async function assertSingleReadStatement(
  sql: string,
  options: ClassifyOptions = {},
): Promise<StatementClassification> {
  let classification: StatementClassification;
  try {
    classification = await classifyStatement(sql, options);
  } catch (err: unknown) {
    if (err instanceof SqlParserUnavailableError) throw err;
    if (err instanceof SqlParseError) {
      throw new StatementClassificationError(
        `PostgreSQL rejected the statement: ${err.message}`,
        'parse_error',
      );
    }
    throw err;
  }

  if (!classification.parse_ok) {
    throw new StatementClassificationError('Statement could not be parsed.', 'parse_error');
  }
  if (classification.statement_count !== 1) {
    throw new StatementClassificationError(
      `Expected exactly one statement, found ${classification.statement_count}. ` +
        'Multi-statement execution is not permitted.',
      'multiple_statements',
    );
  }
  return classification;
}

export { SqlParseError, SqlParserUnavailableError };
export { walkAst };
