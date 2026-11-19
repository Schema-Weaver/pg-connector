/**
 * MongoDB command parsing and validation.
 *
 * MongoDB is not queried with SQL. The connector's wire payload is still a
 * string (`payload.sql`), so the document form is a JSON object:
 *
 *   {"collection":"users","method":"find","filter":{"active":true},
 *    "options":{"limit":50,"sort":{"created_at":-1}}}
 *
 * The method allow-list is the classification boundary:
 *
 *   find | aggregate | count | distinct  -> read
 *   anything else                        -> refused
 *
 * There is intentionally no `runCommand` method. A command passthrough would
 * make every server-side operator reachable and would turn the allow-list into
 * decoration.
 *
 * PIPELINES ARE A DENY-LIST, NOT AN ALLOW-LIST
 * --------------------------------------------
 * The useful aggregation stage set is large and grows with server versions, so
 * the contract blocks the stages whose effect escapes a read:
 *
 *   $out, $merge                writes a collection
 *   $where, $function,          executes JavaScript supplied by the caller
 *   $accumulator
 *   $changeStream               unbounded server-side stream
 *
 * `$out` and `$merge` are checked recursively, so a stage nested inside
 * `$facet`, `$unionWith` or `$lookup` cannot hide one.
 */
import { DriverParseError } from './errors';

export type MongoReadMethod = 'find' | 'aggregate' | 'count' | 'distinct';

export const MONGO_READ_METHODS: readonly MongoReadMethod[] = [
  'find',
  'aggregate',
  'count',
  'distinct',
];

/**
 * Stages and operators that are never part of a read.
 *
 * `$out`/`$merge` are the write stages. The JavaScript operators are denied
 * because their body is not visible to the classifier — the same reason MySQL
 * stored functions are refused.
 */
const BLOCKED_MONGO_KEYS: ReadonlyMap<string, string> = new Map([
  ['$out', 'writes its result to a collection'],
  ['$merge', 'merges its result into a collection'],
  ['$where', 'executes JavaScript supplied by the caller'],
  ['$function', 'executes JavaScript supplied by the caller'],
  ['$accumulator', 'executes JavaScript supplied by the caller'],
  ['$changeStream', 'opens an unbounded server-side change stream'],
]);

const TOP_LEVEL_KEYS = new Set([
  'collection',
  'method',
  'filter',
  'pipeline',
  'field',
  'options',
]);

const OPTION_KEYS: Readonly<Record<MongoReadMethod, ReadonlySet<string>>> = {
  find: new Set([
    'limit',
    'skip',
    'sort',
    'projection',
    'maxTimeMS',
    'hint',
    'collation',
    'comment',
    'batchSize',
  ]),
  aggregate: new Set([
    'maxTimeMS',
    'allowDiskUse',
    'batchSize',
    'collation',
    'hint',
    'comment',
  ]),
  count: new Set(['limit', 'skip', 'maxTimeMS', 'hint', 'collation', 'comment']),
  distinct: new Set(['maxTimeMS', 'collation', 'comment']),
};

export interface MongoQuery {
  collection: string;
  method: MongoReadMethod;
  filter?: Record<string, unknown>;
  pipeline?: Array<Record<string, unknown>>;
  field?: string;
  options: Record<string, unknown>;
}

function fail(message: string): never {
  throw new DriverParseError(`MongoDB command refused: ${message}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Reject blocked operators anywhere in a filter, pipeline or option document.
 *
 * Iterative so a deeply nested pipeline cannot overflow the stack; a depth
 * ceiling also stops a pathological document from consuming the process.
 */
function assertNoBlockedOperators(value: unknown, path: string): void {
  const stack: Array<{ value: unknown; path: string; depth: number }> = [
    { value, path, depth: 0 },
  ];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.depth > 100) {
      fail(`'${current.path}' is nested too deeply`);
    }
    if (Array.isArray(current.value)) {
      for (let i = 0; i < current.value.length; i++) {
        stack.push({
          value: current.value[i],
          path: `${current.path}[${String(i)}]`,
          depth: current.depth + 1,
        });
      }
      continue;
    }
    if (!isPlainObject(current.value)) continue;
    assertSafeForeignNamespaces(current.value, current.path);

    for (const [key, nested] of Object.entries(current.value)) {
      const blocked = BLOCKED_MONGO_KEYS.get(key);
      if (blocked) {
        fail(`'${key}' ${blocked} and is not permitted in a read command`);
      }
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        fail(`'${key}' is not a valid document key`);
      }
      stack.push({
        value: nested,
        path: `${current.path}.${key}`,
        depth: current.depth + 1,
      });
    }
  }
}

/**
 * Refuse a foreign namespace that leaves the configured database or reaches a
 * server-owned collection.
 *
 * A main `collection` is checked by {@link validateCollection}, but `$lookup`,
 * `$graphLookup` and `$unionWith` can name a second collection inside the
 * aggregation. Without this check `system.users` or another database would be
 * reachable through a pipeline while the top-level collection was safe.
 */
function assertSafeNamespace(value: unknown, path: string): void {
  if (typeof value === 'string') {
    if (value.includes('\u0000') || value.includes('$') || value.startsWith('system.')) {
      fail(`'${path}' must not name a server collection or another database`);
    }
    return;
  }
  if (isPlainObject(value)) {
    if (value.db !== undefined) {
      fail(`'${path}' must not name another database`);
    }
    assertSafeNamespace(value.coll, `${path}.coll`);
    return;
  }
  fail(`'${path}' must be a collection name`);
}

function assertSafeForeignNamespaces(document: Record<string, unknown>, path: string): void {
  const lookup = document.$lookup;
  if (isPlainObject(lookup) && lookup.from !== undefined) {
    assertSafeNamespace(lookup.from, `${path}.$lookup.from`);
  }
  const graph = document.$graphLookup;
  if (isPlainObject(graph) && graph.from !== undefined) {
    assertSafeNamespace(graph.from, `${path}.$graphLookup.from`);
  }
  const union = document.$unionWith;
  if (typeof union === 'string') {
    assertSafeNamespace(union, `${path}.$unionWith`);
  } else if (isPlainObject(union) && union.coll !== undefined) {
    assertSafeNamespace(union.coll, `${path}.$unionWith.coll`);
  }
}

function validateCollection(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 120) {
    fail('"collection" must be a non-empty string of at most 120 characters');
  }
  if (value.includes('\u0000') || value.includes('$')) {
    fail('"collection" must not contain NUL or "$"');
  }
  if (value.startsWith('system.')) {
    fail('system collections are not readable through this connector');
  }
  return value;
}

function validateFilter(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  if (!isPlainObject(value)) fail('"filter" must be a JSON object');
  assertNoBlockedOperators(value, 'filter');
  return value;
}

function validatePipeline(value: unknown): Array<Record<string, unknown>> | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) fail('"pipeline" must be a JSON array of stages');
  for (const stage of value) {
    if (!isPlainObject(stage)) fail('every pipeline stage must be a JSON object');
  }
  assertNoBlockedOperators(value, 'pipeline');
  return value as Array<Record<string, unknown>>;
}

function validateField(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.length > 200) {
    fail('"field" must be a non-empty string of at most 200 characters');
  }
  if (value.startsWith('$') || value.includes('\u0000')) {
    fail('"field" must name a field, not an operator');
  }
  return value;
}

function validateOptions(
  value: unknown,
  method: MongoReadMethod,
): Record<string, unknown> {
  if (value === undefined) return {};
  if (!isPlainObject(value)) fail('"options" must be a JSON object');

  const allowed = OPTION_KEYS[method];
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail(`option "${key}" is not permitted for method "${method}"`);
    }
  }

  for (const key of ['limit', 'skip', 'maxTimeMS', 'batchSize']) {
    const number = value[key];
    if (number === undefined) continue;
    if (typeof number !== 'number' || !Number.isInteger(number) || number < 0) {
      fail(`option "${key}" must be a non-negative integer`);
    }
  }
  if (value.limit === 0) {
    // MongoDB treats limit: 0 as "no limit", which is not what a caller that
    // asked for zero rows should get.
    fail('option "limit" must be greater than zero');
  }
  if (value.maxTimeMS === 0) fail('option "maxTimeMS" must be greater than zero');

  for (const key of ['sort', 'projection', 'collation']) {
    if (value[key] !== undefined && !isPlainObject(value[key])) {
      fail(`option "${key}" must be a JSON object`);
    }
  }
  if (
    value.hint !== undefined &&
    typeof value.hint !== 'string' &&
    !isPlainObject(value.hint)
  ) {
    fail('option "hint" must be a string or a JSON object');
  }
  if (value.allowDiskUse !== undefined && value.allowDiskUse !== false) {
    fail('option "allowDiskUse" must be false; a read must not spill to disk');
  }

  assertNoBlockedOperators(value, 'options');
  return value;
}

/** Parse and validate a MongoDB command. Always throws on anything unproven. */
export function parseMongoQuery(text: string): MongoQuery {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: unknown) {
    throw new DriverParseError(
      `MongoDB command must be valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!isPlainObject(parsed)) {
    fail('the payload must be a JSON object');
  }

  for (const key of Object.keys(parsed)) {
    if (!TOP_LEVEL_KEYS.has(key)) {
      fail(`unknown field "${key}"`);
    }
  }

  const method = parsed.method;
  if (typeof method !== 'string' || !MONGO_READ_METHODS.includes(method as MongoReadMethod)) {
    fail(
      `"method" must be one of ${MONGO_READ_METHODS.join(', ')}; ` +
        'every other MongoDB operation is refused',
    );
  }
  const readMethod = method as MongoReadMethod;

  const collection = validateCollection(parsed.collection);
  const filter = validateFilter(parsed.filter);
  const pipeline = validatePipeline(parsed.pipeline);
  const field = validateField(parsed.field);
  const options = validateOptions(parsed.options, readMethod);

  if (readMethod === 'find') {
    if (pipeline !== undefined) fail('"pipeline" is only valid for method "aggregate"');
    if (field !== undefined) fail('"field" is only valid for method "distinct"');
  } else if (readMethod === 'aggregate') {
    if (pipeline === undefined) fail('method "aggregate" requires "pipeline"');
    if (field !== undefined) fail('"field" is only valid for method "distinct"');
  } else if (readMethod === 'count') {
    if (pipeline !== undefined) fail('"pipeline" is only valid for method "aggregate"');
    if (field !== undefined) fail('"field" is only valid for method "distinct"');
  } else {
    if (pipeline !== undefined) fail('"pipeline" is only valid for method "aggregate"');
    if (field === undefined) fail('method "distinct" requires "field"');
  }

  return {
    collection,
    method: readMethod,
    ...(filter ? { filter } : {}),
    ...(pipeline ? { pipeline } : {}),
    ...(field ? { field } : {}),
    options,
  };
}
