import type { DbEntry } from '../config/db-config';
import { dbTypeOf } from './config-shape';
import { MysqlDriver } from './mysql';
import { MongoDriver } from './mongodb';
import type { DatabaseDriver } from './types';

/**
 * Build the non-PostgreSQL driver for an entry.
 *
 * The daemon builds a long-lived registry instead. This factory exists for the
 * local CLI, which handles one statement and then exits: a fresh driver keeps
 * the lifecycle obvious, and `closeAll()` after the statement releases the
 * client it opened.
 *
 * PostgreSQL returns `undefined` because its local path predates the driver
 * split and uses a cursor over `pg` directly; wrapping it here would change that
 * path rather than preserve it.
 */
export function createDriverForEntry(entry: DbEntry): DatabaseDriver | undefined {
  switch (dbTypeOf(entry)) {
    case 'mysql':
      return new MysqlDriver();
    case 'mongodb':
      return new MongoDriver();
    case 'postgres':
    default:
      return undefined;
  }
}
