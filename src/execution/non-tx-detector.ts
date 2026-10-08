import {
  SqlParseError,
  SqlParserUnavailableError,
  parseSql,
  rootNode,
  rootNodeType,
} from './sql-parser';

export interface NonTxCheckResult {
  has_non_transactional: boolean;
  /** Indices of statements that can't run in a transaction. */
  non_tx_indices: number[];
  /** Human-readable summary. */
  summary: string;
  /** Indices of statements that could not be parsed at all. */
  unparseable_indices: number[];
  /** Indices of statements whose transactionality could not be proven. */
  ambiguous_indices: number[];
}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** A statement whose transactionality is decided by a node flag, not the root type. */
interface NodeRule {
  root: string;
  label: string;
  /** True when this specific statement is non-transactional. */
  match: (node: any) => boolean;
}

function concurrent(node: any): boolean {
  return node?.concurrent === true;
}

/** `REINDEX ... CONCURRENTLY` carries the flag as a DefElem in `params`. */
function reindexConcurrently(node: any): boolean {
  const params = node?.params;
  if (!Array.isArray(params)) return false;
  return params.some(
    (param: any) => param?.DefElem?.defname === 'concurrently' || param?.defname === 'concurrently',
  );
}

/** Moving a relation between tablespaces is `ALTER TABLE ... SET TABLESPACE`. */
function altersTablespace(node: any): boolean {
  const cmds = node?.cmds;
  if (!Array.isArray(cmds)) return false;
  return cmds.some((cmd: any) => cmd?.AlterTableCmd?.subtype === 'AT_SetTableSpace');
}

/**
 * Every statement PostgreSQL refuses inside a transaction block, keyed by the
 * parse-tree root node libpg_query produces for it.
 *
 * Explicit and enumerated on purpose. The previous detector inferred
 * transactionality from token overlap with a verb list, which reported
 * `DROP INDEX CONCURRENTLY` and `ALTER SYSTEM` as transactional and could not
 * see `VACUUM`/`ANALYZE` at all.
 *
 * A root type that appears in neither this table nor {@link TRANSACTIONAL_ROOTS}
 * is treated as non-transactional: an unrecognised statement must not be
 * assumed safe to wrap in a transaction.
 */
const NON_TRANSACTIONAL_ROOTS: ReadonlyMap<string, string> = new Map([
  ['AlterDatabaseSetStmt', 'ALTER DATABASE'],
  ['AlterDatabaseStmt', 'ALTER DATABASE ... SET TABLESPACE'],
  ['AlterSubscriptionStmt', 'ALTER SUBSCRIPTION'],
  ['AlterSystemStmt', 'ALTER SYSTEM'],
  ['AlterTableMoveAllStmt', 'ALTER TABLE ... SET TABLESPACE'],
  ['CheckPointStmt', 'CHECKPOINT'],
  ['ClusterStmt', 'CLUSTER'],
  ['ClosePortalStmt', 'CLOSE'],
  ['CreatedbStmt', 'CREATE DATABASE'],
  ['CreateSubscriptionStmt', 'CREATE SUBSCRIPTION'],
  ['DiscardStmt', 'DISCARD'],
  ['DoStmt', 'DO'],
  ['DropdbStmt', 'DROP DATABASE'],
  ['DropSubscriptionStmt', 'DROP SUBSCRIPTION'],
  ['LoadStmt', 'LOAD'],
  ['LockStmt', 'LOCK'],
  ['PrepareStmt', 'PREPARE'],
  ['TransactionStmt', 'transaction control'],
  ['VacuumStmt', 'VACUUM / ANALYZE'],
]);

/** Root types whose transactionality depends on a field of the node. */
const NON_TRANSACTIONAL_NODE_RULES: readonly NodeRule[] = [
  { root: 'IndexStmt', label: 'CREATE INDEX CONCURRENTLY', match: concurrent },
  { root: 'DropStmt', label: 'DROP INDEX CONCURRENTLY', match: concurrent },
  { root: 'ReindexStmt', label: 'REINDEX CONCURRENTLY', match: reindexConcurrently },
  {
    root: 'RefreshMatViewStmt',
    label: 'REFRESH MATERIALIZED VIEW CONCURRENTLY',
    match: concurrent,
  },
  { root: 'CreateTableSpaceStmt', label: 'CREATE TABLESPACE', match: () => true },
  { root: 'DropTableSpaceStmt', label: 'DROP TABLESPACE', match: () => true },
  { root: 'AlterTableStmt', label: 'ALTER TABLE ... SET TABLESPACE', match: altersTablespace },
];

/**
 * Root types known to run inside a transaction block. Anything not listed here
 * is treated as non-transactional, so adding a new PostgreSQL statement cannot
 * silently make it "transactional".
 */
const TRANSACTIONAL_ROOTS: ReadonlySet<string> = new Set([
  'AlterDomainStmt',
  'AlterEnumStmt',
  'AlterExtensionStmt',
  'AlterFamilyStmt',
  'AlterFdwStmt',
  'AlterFunctionStmt',
  'AlterObjectDependsStmt',
  'AlterObjectSchemaStmt',
  'AlterOperatorStmt',
  'AlterPolicyStmt',
  'AlterRoleSetStmt',
  'AlterSeqStmt',
  'AlterTableCmd',
  'AlterTableStmt',
  'AlterTSDictionaryStmt',
  'AlterTSConfigurationStmt',
  'AlterUserMappingStmt',
  'CommentStmt',
  'CompositeTypeStmt',
  'CreateAmStmt',
  'CreateCastStmt',
  'CreateConversionStmt',
  'CreateDomainStmt',
  'CreateEnumStmt',
  'CreateEventTrigStmt',
  'CreateExtensionContentsStmt',
  'CreateExtensionStmt',
  'CreateFdwStmt',
  'CreateForeignServerStmt',
  'CreateForeignTableStmt',
  'CreateFunctionStmt',
  'CreateMappingStmt',
  'CreateOpClassStmt',
  'CreateOpFamilyStmt',
  'CreatePolicyStmt',
  'CreateRangeStmt',
  'CreateRoleStmt',
  'CreateSchemaStmt',
  'CreateSeqStmt',
  'CreateStatsStmt',
  'CreateStmt',
  'CreateTableAsStmt',
  'CreateTransformStmt',
  'CreateTrigStmt',
  'CreateUserMappingStmt',
  'DefineStmt',
  'DeleteStmt',
  'DropOwnedStmt',
  'DropRoleStmt',
  'DropStmt',
  'DropUserStmt',
  'GrantRoleStmt',
  'GrantStmt',
  'InsertStmt',
  'IndexStmt',
  'MergeStmt',
  'ReassignOwnedStmt',
  'RefreshMatViewStmt',
  'ReindexStmt',
  'RenameStmt',
  'RuleStmt',
  'SecLabelStmt',
  'SelectStmt',
  'TruncateStmt',
  'UpdateStmt',
  'VariableSetStmt',
  'VariableShowStmt',
  'ViewStmt',
]);

function nonTransactionalLabel(root: string, node: any): string | null {
  const fixed = NON_TRANSACTIONAL_ROOTS.get(root);
  if (fixed !== undefined) return fixed;
  for (const rule of NON_TRANSACTIONAL_NODE_RULES) {
    if (rule.root !== root) continue;
    if (rule.match(node)) return rule.label;
    return null;
  }
  return null;
}

/**
 * Detects whether a migration plan contains statements that cannot run inside a
 * transaction block, or that cannot be parsed.
 *
 * Transactionality is a table lookup on the PostgreSQL parse tree, never an
 * inference from token overlap. Unknown statement forms fail SAFE: they are
 * reported as non-transactional so the caller is forced to choose
 * `per_statement` rather than having a statement the agent cannot reason about
 * silently wrapped in `BEGIN`/`COMMIT`.
 */
export async function detectNonTransactional(statements: string[]): Promise<NonTxCheckResult> {
  const non_tx_indices: number[] = [];
  const unparseable_indices: number[] = [];
  const ambiguous_indices: number[] = [];
  const summaries: string[] = [];

  for (let idx = 0; idx < statements.length; idx++) {
    const stmt = statements[idx];
    let stmts;
    try {
      stmts = parseSql(stmt).stmts;
    } catch (err: unknown) {
      if (err instanceof SqlParseError) {
        unparseable_indices.push(idx);
        summaries.push(`Statement ${idx + 1}: could not be parsed (${err.message})`);
        continue;
      }
      if (err instanceof SqlParserUnavailableError) {
        unparseable_indices.push(idx);
        summaries.push(`Statement ${idx + 1}: the PostgreSQL parser is unavailable`);
        continue;
      }
      throw err;
    }

    if (stmts.length !== 1) {
      ambiguous_indices.push(idx);
      summaries.push(
        `Statement ${idx + 1}: contains ${stmts.length} statements; each migration entry must be exactly one statement`,
      );
      continue;
    }

    const root = rootNodeType(stmts[0]);
    const node = rootNode(stmts[0]);
    const label = nonTransactionalLabel(root, node);

    if (label !== null) {
      non_tx_indices.push(idx);
      summaries.push(`Statement ${idx + 1}: ${label} cannot run inside a transaction`);
      continue;
    }

    if (!TRANSACTIONAL_ROOTS.has(root)) {
      ambiguous_indices.push(idx);
      summaries.push(
        `Statement ${idx + 1}: ${root} is not a statement the agent can prove runs inside a transaction`,
      );
    }
  }

  return {
    has_non_transactional:
      non_tx_indices.length > 0 || unparseable_indices.length > 0 || ambiguous_indices.length > 0,
    non_tx_indices,
    unparseable_indices,
    ambiguous_indices,
    summary: summaries.join(', ') || 'All statements are transactional',
  };
}
