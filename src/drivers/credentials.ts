import type { DbEntry } from '../config/db-config';

/**
 * Resolve the credential for an entry.
 *
 * `password_stored` is the decrypted in-memory form; `password_env` names an
 * environment variable read at connect time. Both are supported for every
 * engine, so the LCB behaviour is identical across drivers.
 */
export function resolveEntryPassword(entry: DbEntry): string {
  const password =
    entry.password_stored || (entry.password_env ? process.env[entry.password_env] : undefined);
  if (!password) {
    throw new Error(
      `Password unavailable for database "${entry.db_alias}".` +
        (entry.password_env ? ` Env var "${entry.password_env}" is not set.` : ''),
    );
  }
  return password;
}
