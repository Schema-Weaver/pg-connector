import type { DbEntry } from '../config/db-config';

/**
 * Why a frame's `(project, db_alias)` did not resolve to a database.
 *
 * These are the codes that reach the audit trail as `denial_reason` on a `deny`
 * record, so they are stable, data-free and closed. They never name a database
 * that exists: distinguishing "you named a project that is not configured" from
 * "that project is out of scope" would be a database-existence oracle.
 */
export type DatabaseRefusalCode =
  /** No configured entry matches the frame. */
  | 'database_not_found'
  /** The entry exists but the allow-list does not permit it. */
  | 'database_out_of_scope'
  /** No allow-list is configured at all, so this installation serves ping only. */
  | 'database_scope_not_configured'
  /** `project` and `db_alias` select different configured entries. */
  | 'db_alias_project_mismatch';

export interface DatabaseLookupRefusal {
  ok: false;
  code: DatabaseRefusalCode;
  /** Data-free, caller-safe explanation. Never names a configured database. */
  reason: string;
  /** The project the frame claimed. */
  asserted_project: string;
  /** The `db_alias` the frame claimed, or `''` when it carried none. */
  asserted_db_alias: string;
}

export interface DatabaseLookupHit {
  ok: true;
  entry: DbEntry;
}

export type DatabaseLookupResult = DatabaseLookupHit | DatabaseLookupRefusal;

/**
 * The lookup signature the dispatcher accepts.
 *
 * `DbEntry | null` is still accepted so an existing caller — and every test that
 * passes a one-line `lookupDb` — keeps working; a `null` is read as
 * `database_not_found`, which is exactly what it meant before. A caller that
 * wants to say *why* (the allow-list, a project/alias collision) returns the rich
 * form, and the dispatcher records that code instead of a generic
 * `db_unavailable`.
 */
export type LookupDbFn = (
  project: string,
  alias?: string,
) => DbEntry | DatabaseLookupResult | null;

/** Read the entry out of any accepted lookup result, or null. */
export function resolvedEntry(result: DbEntry | DatabaseLookupResult | null): DbEntry | null {
  if (result === null || result === undefined) return null;
  if (isLookupRefusal(result)) return null;
  return 'entry' in result ? result.entry : result;
}

/** Whether a lookup result is a refusal rather than a hit. */
export function isLookupRefusal(
  result: DbEntry | DatabaseLookupResult | null,
): result is DatabaseLookupRefusal {
  return (
    typeof result === 'object' &&
    result !== null &&
    'ok' in result &&
    (result as { ok?: unknown }).ok === false
  );
}

/**
 * Normalise any accepted lookup result into the rich form.
 *
 * A legacy `DbEntry | null` becomes a hit or `database_not_found`, so the
 * dispatcher has exactly one shape to audit from.
 */
export function normaliseLookupResult(
  result: DbEntry | DatabaseLookupResult | null,
  assertedProject: string,
  assertedAlias: string | undefined,
): DatabaseLookupResult {
  if (result === null || result === undefined) {
    return {
      ok: false,
      code: 'database_not_found',
      reason: `No configured database matches project "${assertedProject}"`,
      asserted_project: assertedProject,
      asserted_db_alias: assertedAlias ?? '',
    };
  }
  if (isLookupRefusal(result)) return result;
  if ('entry' in result) return result;
  return { ok: true, entry: result };
}