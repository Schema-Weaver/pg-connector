import { AsyncLocalStorage } from 'async_hooks';
import type { DbEntry } from '../config/db-config';

/**
 * The database identity an audit record is written under.
 *
 *  made this a required part of every record: the audit trail used to
 * carry only the caller-asserted `project`, so a frame that named one database
 * and executed against another left a record that named a database the
 * operation never touched, with no field able to name the one it did.
 *
 * These two values come from the entry the request actually resolved to, never
 * from the frame.
 */
export interface ResolvedDbIdentity {
  resolved_db_alias: string;
  resolved_database: string;
}

/**
 * The fail-closed identity: this request resolved to no database.
 *
 * Used when no context is established (an agent-generated record, a refusal, a
 * record written outside a request) and whenever the values are missing. It is
 * deliberately an obvious non-name rather than an empty string, so a record can
 * never be mistaken for one that resolved to a database whose alias happens to
 * be blank.
 */
export const UNRESOLVED_DB_ALIAS = 'unresolved';

export const UNRESOLVED_DB_IDENTITY: Readonly<ResolvedDbIdentity> = Object.freeze({
  resolved_db_alias: UNRESOLVED_DB_ALIAS,
  resolved_database: UNRESOLVED_DB_ALIAS,
});

/**
 * Per-request store for the resolved identity.
 *
 * An `AsyncLocalStorage` rather than a mutable field on the sink because the
 * sink is shared by every concurrent request: the identity has to follow the
 * async call tree of the request that established it, and a plain field would
 * let one request's audit record inherit another's identity — which is the same
 * class of defect as the caller-asserted value this replaces, only inverted.
 */
const storage = new AsyncLocalStorage<ResolvedDbIdentity>();

/**
 * Build an identity from a resolved entry, failing closed.
 *
 * A missing or blank `db_alias`/`database` yields `'unresolved'` rather than an
 * empty string, so "we could not tell" is distinguishable from "the database has
 * no alias" at read time and in a MAC-verified record.
 */
export function resolvedIdentityOf(entry: DbEntry | null | undefined): ResolvedDbIdentity {
  const alias = typeof entry?.db_alias === 'string' ? entry.db_alias.trim() : '';
  const database = typeof entry?.database === 'string' ? entry.database.trim() : '';
  return {
    resolved_db_alias: alias.length > 0 ? alias : UNRESOLVED_DB_ALIAS,
    resolved_database: database.length > 0 ? database : UNRESOLVED_DB_ALIAS,
  };
}

/**
 * Run `fn` with every audit record written inside it attributed to `identity`.
 *
 * This is the durable half of the  fix: the audit sink stamps the resolved
 * identity from this context on every record it builds, so no call site can
 * forget it and no call site can override it with the frame's own claim. The
 * dispatcher establishes the context at the single point where the resolved
 * entry is known.
 */
export function withResolvedDatabase<T>(identity: ResolvedDbIdentity, fn: () => T): T {
  return storage.run(normaliseIdentity(identity), fn);
}

/**
 * The identity of the request currently in scope, or the fail-closed
 * `'unresolved'` default when none was established.
 */
export function currentResolvedDbIdentity(): ResolvedDbIdentity {
  return storage.getStore() ?? UNRESOLVED_DB_IDENTITY;
}

/** Force every field to a non-empty, non-whitespace value. */
function normaliseIdentity(identity: ResolvedDbIdentity): ResolvedDbIdentity {
  const alias = typeof identity?.resolved_db_alias === 'string' ? identity.resolved_db_alias.trim() : '';
  const database =
    typeof identity?.resolved_database === 'string' ? identity.resolved_database.trim() : '';
  return {
    resolved_db_alias: alias.length > 0 ? alias : UNRESOLVED_DB_ALIAS,
    resolved_database: database.length > 0 ? database : UNRESOLVED_DB_ALIAS,
  };
}