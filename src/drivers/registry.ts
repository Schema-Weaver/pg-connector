import type { DbEntry } from '../config/db-config';
import { dbTypeOf, DbType } from './config-shape';
import type { DatabaseDriver } from './types';

/**
 * Resolve a database entry to the driver that serves it.
 *
 * The type comes from the entry, never from the SQL or from a request. A caller
 * that reaches a MySQL database cannot have its statement classified by the
 * PostgreSQL grammar, or vice versa.
 */
export class DriverRegistry {
  private readonly drivers = new Map<DbType, DatabaseDriver>();

  constructor(drivers: readonly DatabaseDriver[] = []) {
    for (const driver of drivers) this.register(driver);
  }

  register(driver: DatabaseDriver): this {
    this.drivers.set(driver.type, driver);
    return this;
  }

  get(type: DbType): DatabaseDriver {
    const driver = this.drivers.get(type);
    if (!driver) {
      throw new Error(`No database driver is registered for '${type}'.`);
    }
    return driver;
  }

  forEntry(entry: DbEntry): DatabaseDriver {
    return this.get(dbTypeOf(entry));
  }

  has(type: DbType): boolean {
    return this.drivers.has(type);
  }

  list(): DatabaseDriver[] {
    return [...this.drivers.values()];
  }
}
