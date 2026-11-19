/**
 * MySQL statement classification, driven by a MySQL grammar.
 *
 * WHY A SECOND PARSER
 * -------------------
 * The PostgreSQL classifier is built on libpg_query. Feeding MySQL SQL to it
 * would either fail or, worse, accept a statement with different semantics than
 * the server that executes it. MySQL has its own grammar, its own statement
 * surface and its own ways to escape a read: `SELECT … INTO OUTFILE`, row
 * locking, `:=` assignments, and stored functions called from a SELECT.
 *
 * RULES
 * -----
 *   - Parse with `node-sql-parser`'s MySQL dialect. A parse failure is a
 *     refusal; there is no lexical fallback anywhere in this file.
 *   - Exactly one statement per request. A multi-statement payload is never a
 *     read, even when every statement in it is.
 *   - Only `SELECT`, `DESCRIBE` and `EXPLAIN` can be reads. `SHOW` is a utility
 *     (it can expose other sessions), writes are `write`, and schema changes are
 *     `ddl`.
 *   - A `SELECT` is demoted to `write` when it contains `INTO`, a locking
 *     clause, an assignment (`:=`) or a function call this module cannot prove
 *     is a pure built-in. Stored functions — anything schema-qualified, or any
 *     name outside the built-in allow-list — are refused.
 *
 * The database is still the authority. The executor opens a
 * `START TRANSACTION READ ONLY` for every classified read, so a miss in this
 * classifier is stopped by MySQL for a write to a table. `SELECT … INTO
 * OUTFILE` is not a table write, which is why the classifier removes it before
 * execution rather than relying on the transaction.
 */
import { Parser } from 'node-sql-parser';
import type { FunctionEffectRecord, SideEffectKind } from '../execution/function-effects';
import type { StatementClassification } from '../execution/types';
import { DriverParseError } from './errors';

/* eslint-disable @typescript-eslint/no-explicit-any */

const parser = new Parser();

/**
 * Refuse MySQL and MariaDB executable comments before the parser can hide them.
 *
 * `/*!50000 … *\/` is a comment to `node-sql-parser` — it is stripped from the
 * AST entirely — but MySQL splices its contents into the statement. A statement
 * that parses as a plain `SELECT` can therefore carry `INTO OUTFILE`, a locking
 * clause or a stored-function call that the classifier never saw. MariaDB's
 * `/*M!…*\/` form behaves the same way on MariaDB servers.
 *
 * There is no safe way to classify hidden SQL without re-implementing the
 * server's version gating, so the construct is refused outright. Optimizer
 * hints (`/*+ … *\/`) are not executable and are left alone.
 *
 * The scan follows MySQL's own lexical rules rather than using a substring
 * search, so a literal that happens to contain `/*!` is not refused and a
 * comment hidden behind a non-comment `--x` is still found.
 *
 * @throws {DriverParseError} for an executable comment or an unterminated
 *   quoted run/block comment.
 */
function assertNoExecutableComments(sql: string): void {
  // The raw token is authoritative: MySQL only executes a comment when these
  // exact bytes appear, and no quoting mode can change that. Checking the
  // substring first makes the refusal independent of every lexer assumption,
  // including a session running `NO_BACKSLASH_ESCAPES`, where a backslash-
  // escaped quote can otherwise move the string boundary the scan uses.
  //
  // The cost is a false positive for a literal that contains `/*!` or `/*M!`.
  // That is the correct direction for a fail-closed classifier, and the scan
  // below still provides precise errors for unterminated input.
  if (sql.includes('/*!') || sql.includes('/*M!')) {
    throw new DriverParseError(
      'MySQL executable comments (/*! … */ and /*M! … */) are refused: their contents ' +
        'run on the server but are invisible to the parser.',
    );
  }

  const n = sql.length;
  let i = 0;

  const skipQuoted = (start: number, delim: string): number => {
    let j = start + 1;
    while (j < n) {
      if (sql[j] === '\\') {
        j += 2;
        continue;
      }
      if (sql[j] === delim) {
        if (sql[j + 1] === delim) {
          j += 2;
          continue;
        }
        return j + 1;
      }
      j++;
    }
    throw new DriverParseError('MySQL could not parse the statement: unterminated quoted run.');
  };

  while (i < n) {
    const ch = sql[i];

    if (ch === "'" || ch === '"' || ch === '`') {
      i = skipQuoted(i, ch);
      continue;
    }

    if (ch === '#') {
      const nl = sql.indexOf('\n', i + 1);
      i = nl === -1 ? n : nl;
      continue;
    }

    // MySQL requires whitespace (or end of input) after `--`; `1--2` is an
    // arithmetic expression, not a comment, so its text must still be scanned.
    if (ch === '-' && sql[i + 1] === '-' && (i + 2 >= n || /\s/.test(sql[i + 2]))) {
      const nl = sql.indexOf('\n', i + 2);
      i = nl === -1 ? n : nl;
      continue;
    }

    if (ch === '/' && sql[i + 1] === '*') {
      if (sql[i + 2] === '!' || (sql[i + 2] === 'M' && sql[i + 3] === '!')) {
        throw new DriverParseError(
          'MySQL executable comments (/*! … */ and /*M! … */) are refused: their contents ' +
            'run on the server but are invisible to the parser.',
        );
      }
      const close = sql.indexOf('*/', i + 2);
      if (close === -1) {
        throw new DriverParseError(
          'MySQL could not parse the statement: unterminated block comment.',
        );
      }
      i = close + 2;
      continue;
    }

    i++;
  }
}

const WRITE_ROOTS = new Set([
  'insert',
  'update',
  'delete',
  'replace',
  'load',
  'load_data',
  'import',
  'do',
]);
const DDL_ROOTS = new Set([
  'create',
  'alter',
  'drop',
  'truncate',
  'rename',
  'grant',
  'revoke',
  'call',
  'prepare',
  'execute',
  'deallocate',
]);
const UTILITY_ROOTS = new Set(['set', 'transaction', 'use', 'show', 'lock', 'unlock']);

/**
 * Built-in MySQL functions that are read-only, have no session effect and do
 * not reach outside the server.
 *
 * This is an ALLOW-LIST. Anything absent — including every stored function and
 * every schema-qualified call — is treated as unproven and demotes the
 * statement out of `read`. That is deliberately more conservative than a
 * deny-list: MySQL lets an operator create a function with any name, and a
 * deny-list cannot enumerate names that do not exist yet.
 */
const READ_FUNCTIONS = new Set(
  [
    // Aggregates
    'avg',
    'bit_and',
    'bit_or',
    'bit_xor',
    'count',
    'group_concat',
    'json_arrayagg',
    'json_objectagg',
    'max',
    'min',
    'std',
    'stddev',
    'stddev_pop',
    'stddev_samp',
    'sum',
    'var_pop',
    'var_samp',
    'variance',
    'any_value',
    // Window functions
    'row_number',
    'rank',
    'dense_rank',
    'percent_rank',
    'cume_dist',
    'ntile',
    'lag',
    'lead',
    'first_value',
    'last_value',
    'nth_value',
    // String
    'ascii',
    'bin',
    'bit_length',
    'char',
    'char_length',
    'character_length',
    'concat',
    'concat_ws',
    'elt',
    'export_set',
    'field',
    'find_in_set',
    'format',
    'from_base64',
    'hex',
    'insert',
    'instr',
    'lcase',
    'left',
    'length',
    'locate',
    'lower',
    'lpad',
    'ltrim',
    'make_set',
    'mid',
    'oct',
    'octet_length',
    'ord',
    'position',
    'quote',
    'repeat',
    'replace',
    'reverse',
    'right',
    'rpad',
    'rtrim',
    'soundex',
    'space',
    'strcmp',
    'substr',
    'substring',
    'substring_index',
    'to_base64',
    'trim',
    'ucase',
    'unhex',
    'upper',
    'weight_string',
    'regexp_like',
    'regexp_instr',
    'regexp_replace',
    'regexp_substr',
    // Numeric
    'abs',
    'acos',
    'asin',
    'atan',
    'atan2',
    'ceil',
    'ceiling',
    'conv',
    'cos',
    'cot',
    'crc32',
    'degrees',
    'exp',
    'floor',
    'ln',
    'log',
    'log10',
    'log2',
    'mod',
    'pi',
    'pow',
    'power',
    'radians',
    'rand',
    'round',
    'sign',
    'sin',
    'sqrt',
    'tan',
    'truncate',
    // Date/time
    'adddate',
    'addtime',
    'convert_tz',
    'curdate',
    'current_date',
    'current_time',
    'current_timestamp',
    'curtime',
    'date',
    'date_add',
    'date_format',
    'date_sub',
    'datediff',
    'day',
    'dayname',
    'dayofmonth',
    'dayofweek',
    'dayofyear',
    'extract',
    'from_days',
    'from_unixtime',
    'hour',
    'last_day',
    'localtime',
    'localtimestamp',
    'makedate',
    'maketime',
    'microsecond',
    'minute',
    'month',
    'monthname',
    'now',
    'period_add',
    'period_diff',
    'quarter',
    'sec_to_time',
    'second',
    'str_to_date',
    'subdate',
    'subtime',
    'sysdate',
    'time',
    'time_format',
    'time_to_sec',
    'timediff',
    'timestamp',
    'timestampadd',
    'timestampdiff',
    'to_days',
    'to_seconds',
    'unix_timestamp',
    'utc_date',
    'utc_time',
    'utc_timestamp',
    'week',
    'weekday',
    'weekofyear',
    'year',
    'yearweek',
    // JSON
    'json_array',
    'json_array_append',
    'json_array_insert',
    'json_contains',
    'json_contains_path',
    'json_depth',
    'json_extract',
    'json_insert',
    'json_keys',
    'json_length',
    'json_merge_patch',
    'json_merge_preserve',
    'json_object',
    'json_overlaps',
    'json_pretty',
    'json_quote',
    'json_remove',
    'json_replace',
    'json_search',
    'json_set',
    'json_storage_free',
    'json_storage_size',
    'json_type',
    'json_unquote',
    'json_valid',
    'json_value',
    // Identity / server metadata
    'database',
    'schema',
    'user',
    'current_user',
    'session_user',
    'system_user',
    'version',
    'connection_id',
    'found_rows',
    'row_count',
    'charset',
    'collation',
    'coercibility',
    // Conditional
    'if',
    'ifnull',
    'nullif',
    'coalesce',
    'isnull',
    'greatest',
    'least',
    'exists',
    // Hashing / encoding
    'md5',
    'sha1',
    'sha2',
    'aes_encrypt',
    'aes_decrypt',
    'compress',
    'uncompress',
    'encode',
    'decode',
    'random_bytes',
    'uuid',
    // Network address helpers
    'inet_aton',
    'inet_ntoa',
    'inet6_aton',
    'inet6_ntoa',
    'is_ipv4',
    'is_ipv6',
  ].map((name) => name.toLowerCase()),
);

/**
 * Functions that are on the deny-list by name. The allow-list already refuses
 * anything not named here, so this exists to give the refusal a useful reason
 * and a concrete side-effect family rather than "unknown function".
 */
const DENIED_FUNCTION_EFFECTS: Readonly<Record<string, SideEffectKind[]>> = {
  load_file: ['remote_io'],
  sleep: ['unknown_effect'],
  benchmark: ['unknown_effect'],
  get_lock: ['advisory_lock'],
  release_lock: ['advisory_lock'],
  release_all_locks: ['advisory_lock'],
  is_free_lock: ['advisory_lock'],
  is_used_lock: ['advisory_lock'],
  master_pos_wait: ['remote_io'],
  source_pos_wait: ['remote_io'],
  wait_for_executed_gtid_set: ['remote_io'],
  wait_until_sql_thread_after_gtids: ['remote_io'],
  last_insert_id: ['session_mutation'],
  uuid_short: ['session_mutation'],
  sys_exec: ['remote_io'],
  sys_eval: ['remote_io'],
  sys_get: ['remote_io'],
  sys_set: ['remote_io'],
};

interface FunctionRef {
  name: string;
  qualified: boolean;
}

interface Walked {
  functions: FunctionRef[];
  assignments: number;
  intoOutfile: boolean;
  lockingRead: boolean;
  nestedSelectFacts: Array<{ intoOutfile: boolean; lockingRead: boolean }>;
}

function walk(node: unknown, acc: Walked): void {
  if (Array.isArray(node)) {
    for (const item of node) walk(item, acc);
    return;
  }
  if (typeof node !== 'object' || node === null) return;

  const record = node as Record<string, any>;

  if (record.type === 'function') {
    const nameNode = record.name;
    const parts: string[] = Array.isArray(nameNode?.name)
      ? nameNode.name
          .map((part: any) => (typeof part?.value === 'string' ? part.value : ''))
          .filter((part: string) => part.length > 0)
      : [];
    const schema = typeof nameNode?.schema?.value === 'string' ? nameNode.schema.value : '';
    const name = parts.join('.');
    if (name.length > 0) {
      acc.functions.push({ name, qualified: schema.length > 0 });
    }
  } else if (record.type === 'aggr_func') {
    const name = typeof record.name === 'string' ? record.name : '';
    if (name.length > 0) acc.functions.push({ name, qualified: false });
  } else if (record.type === 'assign') {
    acc.assignments++;
  }

  if (record.type === 'select') {
    if (record.into && record.into.keyword) acc.intoOutfile = true;
    if (record.locking_read) acc.lockingRead = true;
  }

  for (const [key, value] of Object.entries(record)) {
    if (key === 'name' || key === 'schema') {
      // Function names are handled above; walking the name node itself would
      // find no functions, but skipping keeps the traversal cheap.
      if (record.type === 'function') continue;
    }
    walk(value, acc);
  }
}

function inspect(ast: any): Walked {
  const acc: Walked = {
    functions: [],
    assignments: 0,
    intoOutfile: false,
    lockingRead: false,
    nestedSelectFacts: [],
  };
  walk(ast, acc);
  return acc;
}

function effectsFor(refs: readonly FunctionRef[]): {
  records: FunctionEffectRecord[];
  unsafe: string[];
} {
  const byName = new Map<string, FunctionEffectRecord>();
  const unsafe: string[] = [];

  for (const ref of refs) {
    const normalized = ref.name.toLowerCase();
    const key = ref.qualified ? `qualified:${normalized}` : normalized;
    if (byName.has(key)) continue;

    const denied = DENIED_FUNCTION_EFFECTS[normalized];
    if (ref.qualified || denied || !READ_FUNCTIONS.has(normalized)) {
      const record: FunctionEffectRecord = {
        name: ref.name,
        effect: denied ? 'volatile' : 'unknown',
        side_effects: denied ?? ['unknown_effect'],
        resolved: denied !== undefined,
      };
      byName.set(key, record);
      unsafe.push(ref.name);
      continue;
    }

    byName.set(key, {
      name: ref.name,
      effect: 'immutable',
      side_effects: [],
      resolved: true,
    });
  }

  return { records: [...byName.values()], unsafe };
}

function sideEffectsOf(records: readonly FunctionEffectRecord[]): SideEffectKind[] {
  const kinds = new Set<SideEffectKind>();
  for (const record of records) {
    for (const kind of record.side_effects) kinds.add(kind);
  }
  return [...kinds];
}

function base(
  type: StatementClassification['type'],
  kind: string,
  transactional: boolean,
  verb: string,
  extra: Partial<StatementClassification> = {},
  records: readonly FunctionEffectRecord[] = [],
): StatementClassification {
  return {
    type,
    kind,
    transactional,
    verb,
    statement_count: 1,
    parse_ok: true,
    read_violations: [],
    function_effects: [...records],
    side_effects: sideEffectsOf(records),
    ...extra,
  };
}

function rootType(ast: any): string {
  return typeof ast?.type === 'string' ? ast.type.toLowerCase() : '';
}

function verbFor(root: string): string {
  switch (root) {
    case 'select':
      return 'SELECT';
    case 'insert':
      return 'INSERT';
    case 'update':
      return 'UPDATE';
    case 'delete':
      return 'DELETE';
    case 'replace':
      return 'REPLACE';
    case 'create':
      return 'CREATE';
    case 'alter':
      return 'ALTER';
    case 'drop':
      return 'DROP';
    case 'truncate':
      return 'TRUNCATE';
    case 'rename':
      return 'RENAME';
    case 'grant':
      return 'GRANT';
    case 'revoke':
      return 'REVOKE';
    case 'call':
      return 'CALL';
    case 'desc':
      return 'DESCRIBE';
    case 'explain':
      return 'EXPLAIN';
    case 'show':
      return 'SHOW';
    case 'set':
      return 'SET';
    case 'transaction':
      return 'TRANSACTION';
    case 'use':
      return 'USE';
    case 'lock':
      return 'LOCK';
    case 'unlock':
      return 'UNLOCK';
    default:
      return root.replace(/_/g, ' ').toUpperCase();
  }
}

/**
 * Classify one MySQL statement.
 *
 * @throws {DriverParseError} when MySQL's grammar (via node-sql-parser) cannot
 *   represent the input. Callers must treat that as a refusal.
 */
export async function classifyMysqlStatement(sql: string): Promise<StatementClassification> {
  assertNoExecutableComments(sql);

  let parsed: any;
  try {
    parsed = parser.astify(sql, { database: 'mysql' });
  } catch (err: unknown) {
    throw new DriverParseError(
      `MySQL could not parse the statement: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (parsed === undefined || parsed === null) {
    throw new DriverParseError('MySQL could not parse the statement: the parser returned no AST.');
  }

  const statements: any[] = Array.isArray(parsed) ? parsed : [parsed];
  if (statements.length === 0) {
    return base('unknown', 'EMPTY', true, '', {
      statement_count: 0,
      read_violations: ['parse_error'],
    });
  }

  if (statements.length > 1) {
    // Classify by the most dangerous statement, but never let the leading one
    // hide the rest. The permission layer refuses any count other than one.
    let worst = classifyOne(statements[0]);
    for (const statement of statements.slice(1)) {
      const next = classifyOne(statement);
      if (severity(next.type) > severity(worst.type)) worst = next;
    }
    return {
      ...worst,
      statement_count: statements.length,
      kind: `${statements.length} statements`,
      read_violations: [...new Set([...worst.read_violations, 'multiple_statements'])],
    };
  }

  return classifyOne(statements[0]);
}

function severity(type: StatementClassification['type']): number {
  switch (type) {
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

function classifyOne(ast: any): StatementClassification {
  const root = rootType(ast);
  const verb = verbFor(root);

  if (root === 'select') return classifySelect(ast, verb);
  if (root === 'desc') return base('read', 'DESCRIBE', true, verb);
  if (root === 'explain') {
    const inner = ast?.expr;
    if (inner && rootType(inner) === 'select') {
      const classified = classifySelect(inner, verb);
      if (classified.type === 'read' && classified.read_violations.length === 0) {
        return base('read', 'EXPLAIN', true, verb);
      }
      return { ...classified, kind: `EXPLAIN ${classified.kind}` };
    }
    return base('utility', 'EXPLAIN', true, verb);
  }

  if (WRITE_ROOTS.has(root)) return base('write', verb, false, verb);
  if (DDL_ROOTS.has(root)) {
    const executable = root === 'call' || root === 'prepare' || root === 'execute';
    return base('ddl', verb, false, verb, executable ? { read_violations: ['executable_block'] } : {});
  }
  if (UTILITY_ROOTS.has(root)) return base('utility', verb, true, verb);

  // Unknown root: NOT a read. Requiring DDL capability is the fail-closed
  // direction, and `executable_block` makes auto-upgrade refuse it too.
  return base('unknown', verb || 'UNKNOWN', true, verb, {
    read_violations: ['executable_block'],
  });
}

function classifySelect(ast: any, verb: string): StatementClassification {
  const facts = inspect(ast);
  const { records, unsafe } = effectsFor(facts.functions);
  const violations: string[] = [];

  if (facts.intoOutfile) violations.push('selects_into');
  if (facts.lockingRead) violations.push('row_locking');
  if (facts.assignments > 0) violations.push('executable_block');
  if (unsafe.length > 0) violations.push('denied_function');

  if (violations.length > 0) {
    const named = unsafe[0];
    const kind = named ? `SELECT (${named})` : `SELECT (${violations.join(', ')})`;
    // Reported as `write` so it can never satisfy a `query_read` check and so
    // the audit trail shows the statement as a mutation attempt.
    return base('write', kind, true, verb, { read_violations: violations }, records);
  }

  return base('read', 'SELECT', true, verb, {}, records);
}
