/**
 * Function-effect analysis, answered by PostgreSQL's own catalogue.
 *
 * WHY THIS EXISTS
 * ---------------
 * `isProvableRead()` used to be "one statement, parsed, `type === 'read'`, no
 * read violations", and `read_violations` was populated from a NAME deny-list.
 * That made the class of attack trivially reachable: an operator-written
 * `SECURITY DEFINER` wrapper around `pg_read_file`, or any `VOLATILE` function
 * that INSERTs, is called from a `SELECT`, is on no deny-list, and was therefore
 * a *provable read* for every role at every permission level. `viewer` read
 * `/etc/passwd` from the database host even with
 * `default_transaction_read_only = on`, because that setting constrains WRITES,
 * not reads.
 *
 * A deny-list cannot close that class: the names are not enumerable. The
 * `pg_proc` row, however, states what PostgreSQL itself believes about every
 * function in the database — `provolatile` and `prosecdef` — and the rule we
 * need is a property of the function, not of its spelling. Only
 * `provolatile = 'i' AND prosecdef = false` is a call with no effect at all.
 *
 * THE RULE
 * --------
 * `immutable`      provolatile = 'i' AND prosecdef = false -> no side effect
 * `volatile`       provolatile = 'v' -> may do anything the role may do
 * `stable`         provolatile = 's' -> snapshot/time dependent, not a provable read
 * `security_definer` prosecdef = true -> runs as the owner, whatever its volatility
 * `unknown`        not in pg_proc, or the catalogue could not be read -> NOT a read
 *
 * Everything that is not `immutable` — including `unknown`, including "the
 * catalogue was not reachable" — is refused by `isProvableRead()`. That is the
 * fail-closed direction and it is the whole point: an unresolved function must
 * not be treated as safe.
 *
 * OVERLOADS AND SCHEMAS
 * ---------------------
 * A bare name can resolve to many overloads in many schemas. PostgreSQL picks
 * one through `search_path`, and `pg_function_is_visible()` reports exactly that
 * choice, so an unqualified reference is judged on the visible overloads. A
 * `schema.name` reference is judged on that schema only. When a bare name
 * matches nothing visible, the reference cannot be pinned down at all, so every
 * same-named function in the cluster is treated as a candidate and the MOST
 * CONSERVATIVE verdict wins: one unsafe overload is enough.
 *
 * COST
 * ----
 * One batched `pg_proc` read per classification, cached per (database, name)
 * with a short TTL, and never issued at all when the statement references no
 * function. The cache is a latency optimisation only: expiring it early can
 * only make the analysis stricter (a re-read finds the same or a worse
 * verdict), never laxer.
 */
import type { QueryConfig, QueryResult } from 'pg';
import { extendedQuery } from './types';

/* eslint-disable @typescript-eslint/no-explicit-any */

/** What PostgreSQL's catalogue says a function call can do. */
export type FunctionEffect =
  /** provolatile = 'i' AND prosecdef = false. No effect at all. */
  | 'immutable'
  /** provolatile = 'v'. May do anything the calling role may do. */
  | 'volatile'
  /** provolatile = 's'. Snapshot/time dependent; not a provable read. */
  | 'stable'
  /** prosecdef = true. Runs with the owner's rights, whatever its volatility. */
  | 'security_definer'
  /** Absent from pg_proc, or the catalogue could not be read. */
  | 'unknown';

/**
 * A recorded effect that escapes the transaction.
 *
 * `NOTIFY`, advisory locks, sequence advances and XID allocation all commit or
 * take effect OUTSIDE the transaction that issued them, so a rollback — and
 * therefore `default_transaction_read_only` on the writes it does cover — is
 * not a control over any of them. They are recorded explicitly so the audit
 * trail shows a mutation attempt rather than a read.
 */
export type SideEffectKind =
  | 'notified'
  | 'advisory_lock'
  | 'xid_allocated'
  | 'sequence'
  | 'session_mutation'
  | 'remote_io'
  | 'unknown_effect';

/** One referenced function and the catalogue's verdict on it. */
export interface FunctionEffectRecord {
  /** The name exactly as {@link collectFunctionNames} produced it. */
  name: string;
  /** `schema.name`, when the statement qualified the reference. */
  qualified_name?: string;
  /** Schema the verdict came from, when it could be pinned to one. */
  schema?: string;
  /** Verdict for the whole reference (worst overload, when ambiguous). */
  effect: FunctionEffect;
  /** Side effects recorded for this reference. Empty only for `immutable`. */
  side_effects: SideEffectKind[];
  /** False when pg_proc did not answer, or answered "no such function". */
  resolved: boolean;
}

/**
 * The analysis of one statement's function references.
 *
 * `analysed: false` means "no catalogue verdict was obtained". Callers must
 * treat that as unsafe: the statement is not a provable read.
 */
export interface FunctionEffectAnalysis {
  records: FunctionEffectRecord[];
  analysed: boolean;
}

/**
 * Resolver injected by the caller that owns the connection.
 *
 * It is deliberately an *argument* rather than something the classifier reaches
 * for: classification happens in several places (permission check, local CLI
 * surface, migrations) and only some of them have a live client. A caller
 * without one must get `analysed: false`, not a silent pass.
 */
export type FunctionEffectResolver = (
  names: readonly string[],
) => Promise<FunctionEffectAnalysis>;

/** The minimum a `pg` client has to provide to answer the catalogue query. */
export interface FunctionEffectQueryable {
  query(config: QueryConfig): Promise<Pick<QueryResult<any>, 'rows'>>;
}

/**
 * A source that lends a connection per lookup, so the caller is not asked to
 * hold a pool slot across the whole permission decision (which can include a
 * human approval that takes minutes).
 */
export interface FunctionEffectConnectionSource {
  acquire(): Promise<{ client: FunctionEffectQueryable; release: () => void }>;
}

/** Either an already-held client or something that can lend one. */
export type FunctionEffectSource = FunctionEffectQueryable | FunctionEffectConnectionSource;

/* ------------------------------------------------------------------ */
/* Catalogue query                                                     */
/* ------------------------------------------------------------------ */

/**
 * One batched read of `pg_proc` for every name in the statement.
 *
 * `pg_function_is_visible()` is evaluated on the connection that will run the
 * statement, so it reflects the same `search_path` the call itself will resolve
 * through. The join is on `proname` alone and the narrowing happens in
 * {@link verdictFor}, because which candidates are relevant depends on whether
 * the statement qualified the name.
 */
const CATALOG_QUERY =
  'SELECT n.nspname AS schema, p.proname AS name, p.provolatile AS provolatile, ' +
  'p.prosecdef AS prosecdef, ' +
  'pg_catalog.pg_function_is_visible(p.oid) AS visible ' +
  'FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace ' +
  'WHERE p.proname = ANY($1::text[])';

interface ProcRow {
  schema: string;
  name: string;
  provolatile: string;
  prosecdef: boolean;
  visible: boolean;
}

/* ------------------------------------------------------------------ */
/* Name families (belt and braces)                                     */
/* ------------------------------------------------------------------ */

/**
 * Side-effect families recognised BY NAME.
 *
 * This is a supplement to the catalogue verdict, never a substitute for it: it
 * catches nothing the `pg_proc` read does not already catch, and it exists so
 * that a name which is dangerous for a reason the volatility attribute cannot
 * express — NOTIFY, remote I/O, session mutation — is recorded as such in the
 * audit trail even when the function turns out to be `STABLE`.
 *
 * Families are matched on the bare function name, so a schema-qualified or
 * case-folded reference cannot pick a sibling.
 */
interface SideEffectFamily {
  kind: SideEffectKind;
  exact?: readonly string[];
  prefixes?: readonly string[];
}

const SIDE_EFFECT_FAMILIES: readonly SideEffectFamily[] = [
  // Delivered non-transactionally even inside a read-only transaction.
  { kind: 'notified', prefixes: ['pg_notify'] },
  { kind: 'advisory_lock', prefixes: ['pg_advisory_'] },
  {
    kind: 'xid_allocated',
    prefixes: ['txid_current', 'pg_snapshot_', 'pg_current_xact_id', 'pg_current_snapshot'],
  },
  { kind: 'sequence', exact: ['nextval', 'setval', 'currval', 'lastval'] },
  {
    kind: 'session_mutation',
    exact: [
      'set_config',
      'pg_reload_conf',
      'pg_rotate_logfile',
      'pg_terminate_backend',
      'pg_cancel_backend',
    ],
    prefixes: ['pg_logical_emit_message', 'pg_logical_'],
  },
  {
    kind: 'remote_io',
    exact: [
      'pg_file_write',
      'pg_export_snapshot',
      'pg_import_snapshot',
      'pg_sleep',
      'pg_stat_file',
      'pg_tempfile',
      'pg_read_file',
      'pg_read_binary_file',
      'pg_read_server_file',
    ],
    prefixes: [
      'dblink',
      'postgres_fdw',
      'file_fdw',
      'sqlite_fdw',
      'mysql_fdw',
      'pg_read_',
      'pg_ls_',
      'lo_',
      'pg_sleep',
    ],
  },
];

/** Side-effect kinds implied by a function's bare name alone. */
function nameSideEffects(bare: string): SideEffectKind[] {
  const kinds: SideEffectKind[] = [];
  for (const family of SIDE_EFFECT_FAMILIES) {
    if (family.exact?.includes(bare)) {
      if (!kinds.includes(family.kind)) kinds.push(family.kind);
      continue;
    }
    if (family.prefixes?.some((prefix) => bare.startsWith(prefix))) {
      if (!kinds.includes(family.kind)) kinds.push(family.kind);
    }
  }
  return kinds;
}

/**
 * Ordering used when one name resolves to several overloads: the LEAST safe
 * verdict in the set is the verdict for the reference.
 */
const EFFECT_SEVERITY: Record<FunctionEffect, number> = {
  immutable: 0,
  stable: 1,
  unknown: 2,
  volatile: 3,
  security_definer: 4,
};

/** Map one `pg_proc` row onto an effect, `prosecdef` winning over volatility. */
function effectFromRow(row: ProcRow): FunctionEffect {
  if (row.prosecdef) return 'security_definer';
  switch (row.provolatile) {
    case 'i':
      return 'immutable';
    case 'v':
      return 'volatile';
    case 's':
      return 'stable';
    default:
      return 'unknown';
  }
}

/**
 * Split a collected reference into `[schema, bare]` when it is qualified.
 *
 * `collectFunctionNames` lower-cases and dot-joins the raw parse-tree parts, so
 * `a11_helper.read_any_file` arrives as two parts. A quoted identifier may
 * itself contain a dot (`"my.func"()`), which is indistinguishable here — it
 * resolves as an unknown schema and therefore as an unresolved name, which is
 * the safe direction.
 */
function splitReference(name: string): { schema?: string; bare: string } {
  const dot = name.indexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { bare: name };
  const schema = name.slice(0, dot);
  const bare = name.slice(dot + 1);
  if (schema.includes('.') || bare.includes('.')) return { bare: name };
  return { schema, bare };
}

/** A reference with no catalogue answer: unknown, and therefore unsafe. */
function unresolvedRecord(name: string): FunctionEffectRecord {
  const { schema, bare } = splitReference(name);
  return {
    name,
    ...(schema !== undefined ? { qualified_name: `${schema}.${bare}`, schema } : {}),
    effect: 'unknown',
    side_effects: [...nameSideEffects(bare), 'unknown_effect'],
    resolved: false,
  };
}

/**
 * The verdict for one reference, given every `pg_proc` row matching its bare
 * name. See the module comment for the overload and schema rules.
 */
function verdictFor(name: string, rows: ProcRow[]): FunctionEffectRecord {
  const { schema, bare } = splitReference(name);
  let candidates = rows.filter((row) => row.name === bare);

  if (schema !== undefined) {
    // The statement named the schema, so that is the function it will call.
    candidates = candidates.filter((row) => row.schema === schema);
    if (candidates.length === 0) return unresolvedRecord(name);
  } else {
    const visible = candidates.filter((row) => row.visible);
    // Visible means "what an unqualified call resolves to on this connection".
    // Nothing visible means the reference cannot be pinned down, so every
    // same-named function in the cluster stays a candidate.
    if (visible.length > 0) candidates = visible;
  }

  if (candidates.length === 0) return unresolvedRecord(name);

  let effect: FunctionEffect = 'immutable';
  const sideEffects = new Set<SideEffectKind>();
  for (const row of candidates) {
    const rowEffect = effectFromRow(row);
    if (EFFECT_SEVERITY[rowEffect] > EFFECT_SEVERITY[effect]) effect = rowEffect;
    if (rowEffect !== 'immutable') sideEffects.add('unknown_effect');
    for (const kind of nameSideEffects(row.name)) sideEffects.add(kind);
  }

  const pickedSchema = schema ?? candidates.map((row) => row.schema).sort()[0];
  return {
    name,
    qualified_name: `${pickedSchema}.${bare}`,
    schema: pickedSchema,
    effect,
    side_effects: [...sideEffects],
    resolved: true,
  };
}

/* ------------------------------------------------------------------ */
/* Cache                                                               */
/* ------------------------------------------------------------------ */

interface CacheEntry {
  record: FunctionEffectRecord;
  storedAt: number;
}

/**
 * Verdicts cached per (database, name).
 *
 * The key includes the database because OIDs — and therefore which overload
 * exists where — are only meaningful inside one catalogue. `dbKey` is the
 * caller's stable identifier for it (the db alias), and an empty key is a
 * caller that did not supply one, which keeps those verdicts in their own
 * namespace instead of borrowing another database's answer.
 */
const VERDICT_CACHE = new Map<string, CacheEntry>();

/**
 * Ceiling on cached verdicts. Bounded because the key space includes every
 * function name a caller can spell, and a long-running daemon should not grow
 * without limit. Eviction is least-recently-inserted first, which is enough:
 * a miss only costs one batched query.
 */
const MAX_CACHE_ENTRIES = 4096;

/**
 * How long a verdict may be reused.
 *
 * The catalogue is not immutable — `CREATE OR REPLACE FUNCTION` can turn an
 * `IMMUTABLE` function into a `VOLATILE` one — so the cache is time-bounded as
 * well as size-bounded. A short window keeps the stale-safe direction
 * bounded, and `invalidateFunctionEffectCache()` lets a caller drop the whole
 * namespace the moment it knows the catalogue moved (pool close, config
 * change, or a statement it just executed that was not a read).
 */
const CACHE_TTL_MS = readTtlFromEnv();

function readTtlFromEnv(): number {
  const raw = process.env.SW_AGENT_FUNCTION_EFFECT_TTL_MS;
  if (!raw) return 60_000;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) return 60_000;
  return Math.min(parsed, 3_600_000);
}

function cacheKey(dbKey: string, name: string): string {
  return `${dbKey}\u0000${name.toLowerCase()}`;
}

function cacheGet(dbKey: string, name: string, now: number): FunctionEffectRecord | undefined {
  const key = cacheKey(dbKey, name);
  const hit = VERDICT_CACHE.get(key);
  if (!hit) return undefined;
  if (now - hit.storedAt > CACHE_TTL_MS) {
    VERDICT_CACHE.delete(key);
    return undefined;
  }
  return hit.record;
}

function cachePut(dbKey: string, name: string, record: FunctionEffectRecord, now: number): void {
  if (VERDICT_CACHE.size >= MAX_CACHE_ENTRIES) {
    const oldest = VERDICT_CACHE.keys().next();
    if (!oldest.done) VERDICT_CACHE.delete(oldest.value);
  }
  VERDICT_CACHE.set(cacheKey(dbKey, name), { record, storedAt: now });
}

/**
 * Drop cached verdicts so the next classification re-reads `pg_proc`.
 *
 * Call it when the catalogue may have changed underneath the cache: a pool
 * closing, a db entry being re-pointed, or a statement that was not a read
 * having just executed. Dropping an entry can only make the next verdict equal
 * to the catalogue or stricter, so it is always safe to call.
 *
 * @param dbKey Only this database's verdicts when supplied; all of them
 *   otherwise.
 */
export function invalidateFunctionEffectCache(dbKey?: string): void {
  if (dbKey === undefined) {
    VERDICT_CACHE.clear();
    return;
  }
  const prefix = `${dbKey}\u0000`;
  for (const key of [...VERDICT_CACHE.keys()]) {
    if (key.startsWith(prefix)) VERDICT_CACHE.delete(key);
  }
}

/** Number of cached verdicts. Diagnostics and tests only. */
export function functionEffectCacheSize(): number {
  return VERDICT_CACHE.size;
}

/* ------------------------------------------------------------------ */
/* Analysis                                                            */
/* ------------------------------------------------------------------ */

function isQueryable(source: FunctionEffectSource): source is FunctionEffectQueryable {
  return typeof (source as FunctionEffectQueryable).query === 'function';
}

async function readCatalog(
  source: FunctionEffectSource,
  bareNames: readonly string[],
): Promise<ProcRow[] | null> {
  const run = async (queryable: FunctionEffectQueryable): Promise<ProcRow[]> => {
    // ONE placeholder for the whole name list. Passing the names as separate
    // bind parameters would send a scalar to `$1::text[]` and PostgreSQL would
    // reject the whole statement — which the fail-closed path below would turn
    // into "no verdict", silently escalating every query that calls a function.
    const res = await queryable.query(
      extendedQuery(CATALOG_QUERY, [bareNames]) as unknown as QueryConfig,
    );
    const rows: ProcRow[] = [];
    for (const raw of res.rows as unknown[]) {
      const row = raw as Record<string, unknown>;
      rows.push({
        schema: String(row.schema),
        name: String(row.name),
        provolatile: String(row.provolatile),
        prosecdef: row.prosecdef === true || row.prosecdef === 'true',
        visible: row.visible === true || row.visible === 'true',
      });
    }
    return rows;
  };

  try {
    if (isQueryable(source)) return await run(source);
    const { client, release } = await source.acquire();
    try {
      return await run(client);
    } finally {
      release();
    }
  } catch {
    // A catalogue read that fails must not be mistaken for "no such function"
    // with no effect. The caller gets `analysed: false` and refuses.
    return null;
  }
}

/**
 * Resolve every function a statement references against `pg_proc`.
 *
 * Contract:
 *   - No names in, `analysed: true` and no records: there is nothing to prove,
 *     so `SELECT 1` is unaffected.
 *   - No connection, or a failed catalogue read: `analysed: false` and every
 *     unresolved name reported as `unknown`. The caller must then refuse the
 *     statement. This is the required fail-closed direction.
 *   - One batched query per call, whatever the number of names.
 */
export async function analyseFunctionEffects(
  names: Iterable<string>,
  source?: FunctionEffectSource | null,
  options: { dbKey?: string; now?: () => number } = {},
): Promise<FunctionEffectAnalysis> {
  const dbKey = options.dbKey ?? '';
  const now = options.now ?? Date.now;

  const requested: string[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    requested.push(name);
  }
  if (requested.length === 0) return { records: [], analysed: true };

  const records = new Map<string, FunctionEffectRecord>();
  const misses: string[] = [];
  for (const name of requested) {
    const hit = cacheGet(dbKey, name, now());
    if (hit) records.set(name.toLowerCase(), hit);
    else misses.push(name);
  }

  if (misses.length > 0) {
    if (!source) {
      for (const name of misses) records.set(name.toLowerCase(), unresolvedRecord(name));
      return { records: orderedRecords(requested, records), analysed: false };
    }

    const bareNames = [...new Set(misses.map((name) => splitReference(name).bare.toLowerCase()))];
    const rows = await readCatalog(source, bareNames);
    if (rows === null) {
      for (const name of misses) records.set(name.toLowerCase(), unresolvedRecord(name));
      return { records: orderedRecords(requested, records), analysed: false };
    }

    for (const name of misses) {
      const record = verdictFor(name, rows);
      // A verdict that is not `immutable` may change on the next read and is
      // cheap to re-derive; caching it costs one query either way. Only an
      // `immutable` verdict — the one a caller will actually rely on — is
      // worth remembering, and it is bounded by TTL and size regardless.
      if (record.effect === 'immutable') cachePut(dbKey, name, record, now());
      records.set(name.toLowerCase(), record);
    }
  }

  return { records: orderedRecords(requested, records), analysed: true };
}

function orderedRecords(
  requested: readonly string[],
  byLowerName: Map<string, FunctionEffectRecord>,
): FunctionEffectRecord[] {
  const out: FunctionEffectRecord[] = [];
  for (const name of requested) {
    const record = byLowerName.get(name.toLowerCase());
    if (record) out.push(record);
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Resolver factories                                                  */
/* ------------------------------------------------------------------ */

/**
 * Build a resolver bound to one connection source.
 *
 * Pass this into `PermissionChecker.check` (and therefore into
 * `classifyStatement`). Omit it and every statement that references a function
 * is refused, which is the intended behaviour for a caller with no database to
 * consult — see {@link analyseFunctionEffects}.
 */
export function createFunctionEffectResolver(
  source?: FunctionEffectSource | null,
  options: { dbKey?: string } = {},
): FunctionEffectResolver {
  const dbKey = options.dbKey ?? '';
  return (names: readonly string[]) => analyseFunctionEffects(names, source, { dbKey });
}

/**
 * A resolver over a `PoolManager`-shaped object.
 *
 * Exists so a caller that owns a pool but not a connection can wire the
 * analysis in one line, and so the pool slot is held for the duration of the
 * catalogue query only — the permission decision itself can block on a human
 * approval, and holding a connection across that would exhaust the pool.
 *
 * Typed structurally rather than against `PoolManager` so this module does not
 * depend on the connection layer.
 */
export function functionEffectResolverForPool(
  pool: { acquire(dbEntry: any): Promise<{ client: FunctionEffectQueryable; release: () => void }> },
  dbEntry: unknown,
  options: { dbKey?: string } = {},
): FunctionEffectResolver {
  const dbKey = options.dbKey ?? '';
  return async (names: readonly string[]) => {
    let client: FunctionEffectQueryable;
    let release: () => void;
    try {
      ({ client, release } = await pool.acquire(dbEntry));
    } catch {
      // No usable connection — a missing password, an unreachable host, an
      // exhausted pool. This resolver must never throw: its contract is "report
      // what the catalogue says, or report nothing", and a thrown error here
      // would escape the permission decision and turn a fail-closed refusal
      // into an `internal_error`. `analysed: false` is the fail-closed verdict.
      return {
        records: names.map((name) => unresolvedRecord(name.toLowerCase())),
        analysed: false,
      };
    }
    try {
      return await analyseFunctionEffects(names, client, { dbKey });
    } finally {
      release();
    }
  };
}

/**
 * A resolver that answers from a fixed verdict table, for callers and tests
 * that have no database to consult. Same contract as the real thing: anything
 * not in the table is `unknown`, and therefore refused.
 *
 * NOT for a production execution path. It can only be as strict as the table it
 * is handed, so wiring it in place of the catalogue read would reintroduce
 * exactly the gap this module closes. It is here so the unit suite can drive
 * the composed classifier without a server, and so a caller that genuinely has
 * no database gets the fail-closed verdict explicitly instead of by omission.
 */
export function createStaticFunctionEffectResolver(
  verdicts: Readonly<Record<string, FunctionEffect | 'unresolved'>>,
  options: { analysed?: boolean } = {},
): FunctionEffectResolver {
  const analysed = options.analysed ?? true;
  return async (names: readonly string[]) => {
    const records: FunctionEffectRecord[] = [];
    for (const raw of names) {
      const name = raw.toLowerCase();
      const bare = splitReference(name).bare;
      const looked = verdicts[name] ?? verdicts[bare];
      if (looked === undefined || looked === 'unresolved') {
        records.push(unresolvedRecord(name));
        continue;
      }
      const sideEffects = new Set<SideEffectKind>(nameSideEffects(bare));
      if (looked !== 'immutable') sideEffects.add('unknown_effect');
      records.push({
        name: raw,
        qualified_name: `${splitReference(name).schema ?? 'pg_catalog'}.${bare}`,
        schema: splitReference(name).schema ?? 'pg_catalog',
        effect: looked,
        side_effects: [...sideEffects],
        resolved: true,
      });
    }
    return { records, analysed };
  };
}