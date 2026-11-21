// =============================================================================
// Database metadata reported to the cloud relay.
//
// The relay uses this list for alias validation and engine-aware routing. The
// agent's local databases.config.json remains authoritative for execution, but
// omitting `db_type` here makes the relay treat every alias as PostgreSQL and
// send PostgreSQL SQL to MySQL/MongoDB aliases.
// =============================================================================

import type { DbEntry } from './db-config';

export interface ReportedDatabase {
  db_alias: string;
  database: string;
  db_type?: DbEntry['db_type'];
}

/**
 * Strip credentials and non-metadata fields before putting a database entry in
 * the `X-Agent-Databases` wake header. `db_type` is required for multi-engine
 * routing; it is omitted only for legacy entries that never declared one.
 */
export function toReportedDatabases(databases: DbEntry[]): ReportedDatabase[] {
  return databases.map((db) => ({
    db_alias: db.db_alias,
    database: db.database,
    ...(db.db_type ? { db_type: db.db_type } : {}),
  }));
}
