/**
 * `search_path` composition and verification.
 *
 * WHY THIS IS A SEPARATE MODULE
 * -----------------------------
 * This was a *seam* defect. `resolveSearchPath()` produced a correct
 * intermediate string (`'analytics, public'`), `quoteSearchPath()` re-split that
 * string on `,` **without trimming**, and the two halves disagreed about what a
 * component was:
 *
 *     config   "analytics, public"
 *       -> resolveSearchPath  ->  "analytics, public"      (looks right)
 *       -> quoteSearchPath    ->  SET search_path = "analytics", " public"
 *
 * The second component is a schema literally named `" public"` — a name that
 * does not exist — so the real `public` schema silently left the resolution
 * path and every unqualified name resolved to whichever schema came first. The
 * post-condition guard at `pool.ts` then passed, because it asked
 * `actualPath.toLowerCase().includes('public')` and `" public"` contains
 * `public`. The control written to catch this was defeated by the same defect
 * it was checking for.
 *
 * The fix is structural rather than a patch: there is now **no string
 * round-trip at all**. A list of schema names is resolved once, rendered once,
 * and the post-condition compares that same list against what PostgreSQL reports
 * — component by component, in order. A component can never acquire or lose a
 * space, a quote or a comma between "what we intended" and "what the server
 * was told", because it is a string element the whole way through and the only
 * place a separator appears is where the renderer and the verifier each derive
 * it independently from the same array.
 *
 * Everything here is pure: no database, no pool, no I/O. That is deliberate —
 * the unit suite asserts the *composed statement* here rather than the
 * intermediate value, which is precisely the seam the previous test missed.
 */
import type { DbEntry } from '../config/db-config';

/**
 * `search_path` a pooled session is pinned to when a database entry does not
 * name one, and the component that is always kept last so unqualified names keep
 * resolving. `pg_temp` is deliberately excluded: a temporary object of the same
 * name would otherwise shadow a permanent table for the whole session.
 */
export const DEFAULT_SEARCH_PATH = 'public';

/**
 * The schema PostgreSQL implicitly searches first whenever it is not named
 * explicitly in `search_path`. See {@link resolveSearchPath} for why it is
 * hoisted rather than appended unconditionally.
 */
export const PG_CATALOG_SCHEMA = 'pg_catalog';

/**
 * The implicit schema for session-local temporary objects. Never pinned: a temp
 * object of the same name would shadow a permanent table for the whole session,
 * which is a session-poisoning primitive any principal with `CREATE TEMP
 * TABLE` can reach.
 */
export const PG_TEMP_SCHEMA = 'pg_temp';

/** PostgreSQL's NAMEDATALEN - 1. A longer name cannot exist on the server. */
const MAX_IDENTIFIER_LENGTH = 63;

/**
 * A PostgreSQL identifier we are willing to interpolate into `SET search_path`.
 * Deliberately narrow: letters, digits, underscore and `$`, never starting
 * with a digit. Anything else is **discarded or refused**, never escaped —
 * see {@link quoteSchemaIdentifier}.
 */
const SCHEMA_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_$]*$/;

/**
 * Whether a string may be used as one `search_path` component at all.
 *
 * Used both as the gate in {@link resolveSearchPathComponents} (discard a
 * component the operator got wrong) and as the gate in
 * {@link quoteSchemaIdentifier} (refuse to emit one we did not validate). The
 * same predicate in both places is the point: there is no second, laxer path
 * into the emitted statement.
 */
export function isBareSchemaIdentifier(name: string): boolean {
  return name.length > 0 && name.length <= MAX_IDENTIFIER_LENGTH && SCHEMA_IDENTIFIER.test(name);
}

/**
 * The three component names the connector reasons about by identity rather than
 * by text: the always-last fallback, the implicitly-first system catalog, and
 * the session-local temp schema.
 *
 * They are matched case-insensitively because PostgreSQL folds unquoted
 * identifiers, and — more importantly — because this module emits every
 * component *quoted*. Without case-insensitive matching, a configured
 * `search_path: 'app, PUBLIC'` would render `"PUBLIC"`, which is a *different*
 * schema from `"public"`, and the always-last invariant would silently not hold.
 * Matching folds that config back onto the canonical `public` the entry promised.
 */
function reservedRole(name: string): 'pg_temp' | 'pg_catalog' | 'public' | null {
  const folded = name.toLowerCase();
  if (folded === PG_TEMP_SCHEMA) return 'pg_temp';
  if (folded === PG_CATALOG_SCHEMA) return 'pg_catalog';
  if (folded === DEFAULT_SEARCH_PATH) return 'public';
  return null;
}

/**
 * Render one component as a double-quoted identifier.
 *
 * Refuses anything that is not a bare identifier instead of escaping it. The
 * distinction matters: doubling an embedded quote (`a"b` -> `"a""b"`) is the
 * *correct* PostgreSQL rendering, but it is also how a value that was never a
 * schema name turns into a schema name. Rejecting keeps "what the operator
 * wrote" and "what the session searches" the same set of names, which is the
 * property  destroyed.
 *
 * @throws when the component is not a validated identifier.
 */
function quoteSchemaIdentifier(name: string): string {
  if (!isBareSchemaIdentifier(name)) {
    throw new Error(
      `refusing to emit search_path component ${JSON.stringify(truncateForMessage(name))}: ` +
        'not a bare schema identifier',
    );
  }
  return `"${name}"`;
}

function truncateForMessage(value: string): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > 64 ? `${flat.slice(0, 64)}...` : flat;
}

/**
 * The ordered, de-duplicated list of schemas a session for this entry searches.
 *
 * Rules, in order:
 *
 * 1. No configured value, or no component that survives validation, yields the
 *    single component `['public']`.
 * 2. A component is trimmed and then kept only if {@link isBareSchemaIdentifier}
 *    accepts it, so `'a," public"'` contributes `['a']` and never a schema named
 *    `" public"`. Nothing is escaped into existence, and whitespace *inside* a
 *    component is a rejection rather than a rename — the two rules together are
 *    what make it impossible to emit a component with a leading space.
 * 3. `pg_temp` is dropped (temp objects must not shadow permanent ones), matched
 *    case-insensitively.
 * 4. `pg_catalog` is hoisted to the front if it appears anywhere.
 *    PostgreSQL already searches `pg_catalog` first *unless* it is named
 *    explicitly, in which case it is searched at the named position — so a
 *    configured `'app, pg_catalog, public'` would let a customer schema shadow
 *    built-ins such as `pg_class`. Hoisting restores the implicit-first behaviour
 *    the operator was already relying on, without adding a component they did
 *    not ask for.
 * 5. `public` is always last, unconditionally — it is appended even when the
 *    config never named it — so unqualified names keep resolving against the
 *    schema the entry promises. That unconditional append is the property 
 *    destroyed and the reason a post-condition guard existed at all.
 *    First-occurrence order is otherwise kept, and ordinary duplicates are
 *    removed.
 *
 * The returned array is the single source of truth for both the emitted
 * `SET search_path` and the post-condition comparison; it is never joined into
 * a string and re-split.
 */
export function resolveSearchPathComponents(entry: DbEntry): string[] {
  const configured = (entry as DbEntry & { search_path?: unknown }).search_path;
  if (typeof configured !== 'string') return [DEFAULT_SEARCH_PATH];

  const catalog: string[] = [];
  const body: string[] = [];
  const seen = new Set<string>();

  for (const raw of configured.split(',')) {
    const component = raw.trim();
    if (!isBareSchemaIdentifier(component)) continue;

    const role = reservedRole(component);
    if (role === 'pg_temp') continue;
    // Fold the three reserved names onto their canonical spelling. Everything
    // else keeps the operator's exact text, so `Billing` is still `Billing` and
    // is not conflated with a hypothetical `billing`.
    const canonical = role === null ? component : role;
    if (seen.has(canonical)) continue;
    seen.add(canonical);

    if (role === 'pg_catalog') catalog.push(canonical);
    else if (role !== 'public') body.push(canonical);
  }

  // `public` is appended unconditionally, not merely kept if it was named. That
  // is the property  destroyed and the reason the old substring guard was
  // worth writing: an entry that names only `a` still needs `public` as the
  // fallback, so its absence from the config must not remove it from the path.
  return [...catalog, ...body, DEFAULT_SEARCH_PATH];
}

/**
 * Render the `SET search_path` statement for a resolved component list.
 *
 * The output is the *statement*, not a fragment: the defect this function
 * exists to make impossible was a caller composing a value from one string and
 * a separator from another. Producing the whole statement means the tests can
 * assert exactly what goes over the wire.
 *
 * @throws when a component is not a validated bare identifier, or the list is
 * empty — both are unrecoverable and must fail closed.
 */
export function renderSearchPathSet(components: readonly string[]): string {
  if (components.length === 0) {
    throw new Error('refusing to render an empty search_path');
  }
  const rendered = components.map((component) => quoteSchemaIdentifier(component));
  return `SET search_path = ${rendered.join(', ')}`;
}

/**
 * Split the value PostgreSQL reports for `SHOW search_path` into components.
 *
 * Two things make a naive `value.split(',')` wrong here, and both were observed
 * against a live PostgreSQL 16.2:
 *
 * - **Quoting.** `SET search_path = "Weird Schema", "public"` comes back as
 *   `"Weird Schema", public`. Comparing that text to the expected list fails
 *   even though the path is correct, so quoted components are unquoted
 *   (including `""` -> `"`).
 * - **Commas inside a quoted identifier.** `"a,b"` is one component, not two,
 *   so the split is quote-aware.
 *
 * The load-bearing detail is that **whitespace inside a quoted identifier is
 * significant and whitespace outside it is not**. `analytics, " public"`
 * unquotes to a component named `" public"` — with the leading space — which is
 * NOT `public`. Trimming after unquoting would turn the  payload back into
 * a passing match, which is precisely the mistake the old substring guard made:
 * the corruption was invisible because the comparison ignored the space. So
 * each character is trimmed only while it is outside quotes.
 *
 * Components are lower-cased because unquoted identifiers are folded by
 * PostgreSQL, so `PUBLIC` and `public` are the same schema and the comparison
 * must not fail on case alone. Empty components are **kept** as `''` rather than
 * filtered: a path with a hole in it is not the list we set.
 */
export function parseSearchPathSetting(value: string): string[] {
  interface Piece {
    ch: string;
    quoted: boolean;
  }

  const components: string[] = [];
  let current: Piece[] = [];
  let inQuotes = false;

  const flush = (): void => {
    let start = 0;
    let end = current.length;
    while (start < end && !current[start].quoted && /\s/.test(current[start].ch)) start += 1;
    while (end > start && !current[end - 1].quoted && /\s/.test(current[end - 1].ch)) end -= 1;
    components.push(current.slice(start, end).map((piece) => piece.ch).join('').toLowerCase());
    current = [];
  };

  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (inQuotes) {
      if (ch !== '"') {
        current.push({ ch, quoted: true });
        continue;
      }
      if (value[i + 1] === '"') {
        // Escaped quote inside a quoted identifier.
        current.push({ ch: '"', quoted: true });
        i += 1;
        continue;
      }
      inQuotes = false;
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      continue;
    }
    if (ch === ',') {
      flush();
      continue;
    }
    // Outside quotes, so eligible for the trimming `flush` performs.
    current.push({ ch, quoted: false });
  }
  flush();

  return components;
}

/**
 * The  post-condition: does `SHOW search_path` report exactly the list we
 * pinned, component for component and in order?
 *
 * The previous check was `actual.toLowerCase().includes('public')`, which
 * passes for `analytics, " public"` — the very corruption it was supposed to
 * catch. Order matters too: `evil, public, analytics` is not the path we set,
 * and a path that merely *contains* the expected components in a different
 * order resolves unqualified names differently, so it is a failure.
 *
 * Length equality is part of the comparison, so a missing or an extra component
 * fails. That also covers a server which chose to fold duplicates: the list we
 * render is already de-duplicated, so any difference from it is a difference we
 * did not ask for.
 */
export function searchPathMatches(actual: string, expected: readonly string[]): boolean {
  if (expected.length === 0) return false;
  const got = parseSearchPathSetting(actual);
  if (got.length !== expected.length) return false;
  return got.every((component, index) => component === expected[index].toLowerCase());
}

/**
 * A human-readable, secret-free description of a `SHOW search_path` result for
 * an error message. Schema names are operator-controlled, not credentials, but
 * the value is still bounded because it reaches the browser.
 */
export function describeSearchPathSetting(value: string): string {
  return truncateForMessage(value);
}
