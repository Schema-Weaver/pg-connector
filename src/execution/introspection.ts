import { PoolManager } from './pool';
import { DbEntry } from '../config/db-config';
import { IntrospectPayload, IntrospectResultPayload } from '../protocol/messages';
import { SchemaSnapshot, TableSnapshot, extendedQuery } from './types';
import type { Role } from '../protocol/envelope';
import { introspectionDetailFor } from '../permissions/role-policy';

/**
 * How much of the schema a snapshot may carry.
 *
 * - `full` — everything, including `indexdef`, `check_clause`,
 *   `column_default`, trigger function source, owners, comments and partition
 *   bounds.
 * - `structure` — relation names, column names/types/nullable, and the
 *   primary-key/unique/foreign-key shape. Everything that is a *fact about the
 *   data model* is kept; every field that is *database implementation detail or
 *   business-rule expression* is dropped.
 *
 * Audit M-30: `ROLE_CAPABILITIES` granted `introspect` to all four roles while
 * the snapshot returned the entire schema, so a `viewer` could exfiltrate the
 * whole thing — index bodies, check-clause expressions (which encode validation
 * rules), column defaults (which name sequences and generated columns) and
 * trigger function source. Dropping `introspect` outright for the least
 * privileged roles was the other option; it was rejected because a read-only
 * user could then not populate a schema browser or write a valid join, which is
 * the product's whole purpose for them. The reduced level keeps the product and
 * removes the channel.
 */
export type IntrospectionDetail = 'full' | 'structure';

/**
 * Fields dropped at `structure` detail. Listed explicitly (rather than
 * "delete whatever looks internal") so the reduction is auditable: adding a
 * column to a snapshot query does not silently become a leak, it has to be added
 * here deliberately.
 */
export const STRUCTURE_ONLY_DROPPED_FIELDS = Object.freeze([
  'indexes[].definition',
  'constraints[].definition',
  'columns[].default',
  'triggers (entirely)',
  'owner',
  'comment',
  'partition_info[].for_values',
]);

export interface IntrospectorOptions {
  poolManager: PoolManager;
}

export class Introspector {
  private readonly poolManager: PoolManager;

  constructor(opts: IntrospectorOptions) {
    this.poolManager = opts.poolManager;
  }

  /**
   * Take a schema snapshot.
   *
   * `role` is the authenticated envelope's role; it selects the detail level via
   * `introspectionDetailFor` in permissions/role-policy.ts. It defaults to
   * `structure` rather than `full`, so a caller that forgets to pass it cannot
   * leak the full schema — the reverse of the usual default would be fail-open.
   *
   * Every catalogue query below goes out through `extendedQuery`, so it travels
   * over the extended query protocol: node-postgres takes the simple protocol
   * whenever `values` is falsy, and that protocol executes every
   * semicolon-separated statement in one round trip. The SQL here is
   * agent-authored and carries no caller-supplied text, but pinning it means a
   * future edit cannot quietly turn one catalogue query into a multi-command
   * string.
   */
  async introspect(
    payload: IntrospectPayload,
    dbEntry: DbEntry,
    role: Role = 'viewer',
  ): Promise<IntrospectResultPayload> {
    const detail = introspectionDetailFor(role);
    const full = detail === 'full';
    const { client, release } = await this.poolManager.acquire(dbEntry);

    try {
      // 1. Version
      const versionRes = await client.query(extendedQuery('SELECT version();'));
      const pg_version = versionRes.rows[0]?.version || 'unknown';

      // Honour `pg_version_hint` (audit L-08). It used to be type-checked by
      // `validateIntrospectPayload` and then never read, which is a contract
      // lie: a caller was free to ask for a "12.0" snapshot and receive the live
      // server's schema, labelled as though it answered the question.
      //
      // It is treated as an assertion about which server the caller means, not as
      // a request to rewrite the catalogue. A declared major version that does
      // not match the connected server fails the request closed: the snapshot
      // would describe a database the caller did not ask about, and silently
      // serving it is exactly the confusion the field invited.
      assertVersionHintMatches(pg_version, payload.pg_version_hint);

      // 2. Schemas
      const schemasRes = await client.query(
        extendedQuery(`
        SELECT schema_name FROM information_schema.schemata
        WHERE schema_name NOT LIKE 'pg_%' AND schema_name != 'information_schema'
        ORDER BY schema_name;
      `),
      );
      const schemas = schemasRes.rows.map((r) => r.schema_name);

      // 3. Tables & Views
      const tablesRes = await client.query(
        extendedQuery(`
        SELECT
          t.table_schema, t.table_name,
          CASE
            WHEN t.table_type = 'BASE TABLE' THEN 'table'
            WHEN t.table_type = 'VIEW' THEN 'view'
          END as type,
          ${
            full
              ? `pg_catalog.obj_description(c.oid) as comment,
          pg_catalog.pg_get_userbyid(c.relowner) as owner`
              : `NULL::text as comment,
          NULL::text as owner`
          }
        FROM information_schema.tables t
        JOIN pg_catalog.pg_class c ON c.relname = t.table_name
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.table_schema
        WHERE t.table_schema NOT LIKE 'pg_%' AND t.table_schema != 'information_schema'
        ORDER BY t.table_schema, t.table_name;
      `),
      );

      let matViewsRows: Array<{
        table_schema: string;
        table_name: string;
        type: 'materialized_view';
      }> = [];
      if (payload.include_views !== false) {
        const matViewsRes = await client.query(
          extendedQuery(`
          SELECT schemaname as table_schema, matviewname as table_name, 'materialized_view' as type
          FROM pg_catalog.pg_matviews
          WHERE schemaname NOT LIKE 'pg_%'
          ORDER BY schemaname, matviewname;
        `),
        );
        matViewsRows = matViewsRes.rows as Array<{
          table_schema: string;
          table_name: string;
          type: 'materialized_view';
        }>;
      }

      // Populate TableSnapshots
      const tablesMap = new Map<string, TableSnapshot>();
      const tablesList: TableSnapshot[] = [];

      for (const row of tablesRes.rows) {
        if (payload.include_views === false && row.type === 'view') {
          continue;
        }

        const key = `${row.table_schema}.${row.table_name}`;
        const tableSnap: TableSnapshot = {
          schema: row.table_schema,
          name: row.table_name,
          type: row.type || 'table',
          columns: [],
          indexes: [],
          constraints: [],
          triggers: [],
          owner: full ? row.owner || '' : '',
          comment: full ? row.comment || null : null,
        };
        tablesMap.set(key, tableSnap);
        tablesList.push(tableSnap);
      }

      for (const row of matViewsRows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const tableSnap: TableSnapshot = {
          schema: row.table_schema,
          name: row.table_name,
          type: 'materialized_view',
          columns: [],
          indexes: [],
          constraints: [],
          triggers: [],
          owner: '',
          comment: null,
        };
        tablesMap.set(key, tableSnap);
        tablesList.push(tableSnap);
      }

      // 4. Columns
      const columnsRes = await client.query(
        extendedQuery(`
        SELECT
          c.table_schema, c.table_name, c.column_name,
          c.data_type, c.udt_name, c.is_nullable, c.column_default,
          c.character_maximum_length, c.numeric_precision, c.numeric_scale,
          c.ordinal_position
        FROM information_schema.columns c
        WHERE c.table_schema NOT LIKE 'pg_%' AND c.table_schema != 'information_schema'
        ORDER BY c.table_schema, c.table_name, c.ordinal_position;
      `),
      );

      for (const row of columnsRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        table.columns.push({
          name: row.column_name,
          type: row.udt_name || row.data_type,
          nullable: row.is_nullable === 'YES',
          default: full ? row.column_default || null : null,
          is_primary_key: false,
          is_unique: false,
          is_foreign_key: false,
        });
      }

      // 5. PK / Uniques
      const constraintsRes = await client.query(
        extendedQuery(`
        SELECT
          tc.table_schema, tc.table_name, tc.constraint_name, tc.constraint_type,
          string_agg(kcu.column_name, ',' ORDER BY kcu.ordinal_position) as columns
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE')
          AND tc.table_schema NOT LIKE 'pg_%'
        GROUP BY tc.table_schema, tc.table_name, tc.constraint_name, tc.constraint_type;
      `),
      );

      for (const row of constraintsRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        const cols = (row.columns || '').split(',');
        if (row.constraint_type === 'PRIMARY KEY') {
          for (const colName of cols) {
            const col = table.columns.find((c) => c.name === colName);
            if (col) col.is_primary_key = true;
          }
        } else if (row.constraint_type === 'UNIQUE') {
          for (const colName of cols) {
            const col = table.columns.find((c) => c.name === colName);
            if (col) col.is_unique = true;
          }
        }
      }

      // 6. Foreign keys
      const fksRes = await client.query(
        extendedQuery(`
        SELECT
          tc.table_schema, tc.table_name, kcu.column_name,
          ccu.table_schema AS references_schema, ccu.table_name AS references_table, ccu.column_name AS references_column,
          rc.delete_rule AS on_delete, rc.update_rule AS on_update,
          tc.constraint_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.referential_constraints rc ON tc.constraint_name = rc.constraint_name
        JOIN information_schema.constraint_column_usage ccu ON rc.unique_constraint_name = ccu.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_schema NOT LIKE 'pg_%';
      `),
      );

      for (const row of fksRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        const col = table.columns.find((c) => c.name === row.column_name);
        if (col) {
          col.is_foreign_key = true;
          col.foreign_key = {
            references_schema: row.references_schema,
            references_table: row.references_table,
            references_column: row.references_column,
            on_delete: row.on_delete || null,
            on_update: row.on_update || null,
          };
        }
      }

      // 7. Indexes
      if (payload.include_indexes !== false) {
        const indexesRes = await client.query(
          extendedQuery(`
          SELECT
            schemaname, tablename, indexname, indexdef
          FROM pg_catalog.pg_indexes
          WHERE schemaname NOT LIKE 'pg_%'
          ORDER BY schemaname, tablename, indexname;
        `),
        );

        for (const row of indexesRes.rows) {
          const key = `${row.schemaname}.${row.tablename}`;
          const table = tablesMap.get(key);
          if (!table) continue;

          const isUnique = row.indexdef.toUpperCase().includes('UNIQUE');
          const isPrimary =
            row.indexdef.toUpperCase().includes('PRIMARY KEY') || row.indexname.endsWith('_pkey');

          let cols: string[] = [];
          const match = row.indexdef.match(/\((.*)\)$/);
          if (match) {
            cols = match[1].split(',').map((c: string) => c.trim().replace(/"/g, ''));
          }

          table.indexes.push({
            name: row.indexname,
            columns: cols,
            is_unique: isUnique,
            is_primary: isPrimary,
            // The index body is the DDL text; it is not part of the data model
            // a read-only user needs, so `structure` omits it. The name,
            // columns and uniqueness survive, which is what a schema browser
            // shows.
            definition: full ? row.indexdef : '',
          });
        }
      }

      // 8. Check constraints
      const checksRes = await client.query(
        extendedQuery(`
        SELECT
          tc.table_schema, tc.table_name, tc.constraint_name,
          cc.check_clause
        FROM information_schema.table_constraints tc
        JOIN information_schema.check_constraints cc ON tc.constraint_name = cc.constraint_name
        WHERE tc.constraint_type = 'CHECK'
          AND tc.table_schema NOT LIKE 'pg_%';
      `),
      );

      for (const row of checksRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        table.constraints.push({
          name: row.constraint_name,
          type: 'CHECK',
          // The check clause IS the validation rule. `structure` keeps the
          // constraint's existence and name, not the expression.
          definition: full ? row.check_clause : '',
        });
      }

      // 9. Triggers
      //
      // Trigger metadata is dropped entirely at `structure`: `action_statement`
      // is the trigger function's source, which for an audit trigger is the
      // table's own change history in PL/pgSQL. The query is not even issued for
      // a reduced snapshot, so the data does not exist in this process to leak.
      if (full && payload.include_triggers !== false) {
        const triggersRes = await client.query(
          extendedQuery(`
          SELECT
            event_object_schema, event_object_table, trigger_name,
            event_manipulation, action_timing, action_statement
          FROM information_schema.triggers
          WHERE event_object_schema NOT LIKE 'pg_%'
          ORDER BY event_object_schema, event_object_table, trigger_name;
        `),
        );

        for (const row of triggersRes.rows) {
          const key = `${row.event_object_schema}.${row.event_object_table}`;
          const table = tablesMap.get(key);
          if (!table) continue;

          table.triggers.push({
            name: row.trigger_name,
            event: row.event_manipulation,
            timing: row.action_timing,
            function: row.action_statement,
          });
        }
      }

      // 10. Extensions
      let extensions: Array<{ name: string; version: string; enabled: boolean }> = [];
      if (payload.include_extensions !== false) {
        const extensionsRes = await client.query(
          extendedQuery(`
          SELECT extname, extversion
          FROM pg_catalog.pg_extension
          WHERE extname NOT LIKE 'pg_%';
        `),
        );
        extensions = extensionsRes.rows.map((row) => ({
          name: row.extname,
          version: row.extversion,
          enabled: true,
        }));
      }

      // 11. Partitions
      if (payload.include_partitions !== false) {
        const partitionsRes = await client.query(
          extendedQuery(`
          SELECT
            parent.relname AS parent_table,
            parent_n.nspname AS parent_schema,
            child.relname AS child_table,
            pg_get_expr(child.relpartbound, child.oid) AS for_values
          FROM pg_catalog.pg_inherits inh
          JOIN pg_catalog.pg_class parent ON inh.inhparent = parent.oid
          JOIN pg_catalog.pg_class child ON inh.inhrelid = child.oid
          JOIN pg_catalog.pg_namespace parent_n ON parent.relnamespace = parent_n.oid
          WHERE parent_n.nspname NOT LIKE 'pg_%';
        `),
        );

        for (const row of partitionsRes.rows) {
          const parentKey = `${row.parent_schema}.${row.parent_table}`;
          const parentTable = tablesMap.get(parentKey);
          if (parentTable) {
            if (!parentTable.partition_info) {
              parentTable.partition_info = {
                is_partitioned: true,
                partition_key: null,
                partitions: [],
              };
            }
            parentTable.partition_info.partitions.push({
              name: row.child_table,
              // The partition bound is the row-range predicate; not part of the
              // relation structure.
              for_values: full ? row.for_values || '' : '',
            });
          }
        }
      }

      // The database's on-disk size, reported under its own name.
      //
      // Audit M-30: this used to be `Buffer.byteLength(JSON.stringify(snapshot))`
      // under the field `size_bytes`, i.e. the size of the JSON *response* filed
      // as the size of the *database*. `pg_database_size` is the real value. It
      // can fail on a hardened server that revokes EXECUTE from it, in which case
      // the field is `null` — an honest "unknown" rather than a plausible-looking
      // number that means something else.
      let databaseSizeBytes: number | null = null;
      try {
        const sizeRes = await client.query(
          extendedQuery('SELECT pg_database_size(current_database()) AS bytes;'),
        );
        const bytes = sizeRes.rows[0]?.bytes;
        databaseSizeBytes = typeof bytes === 'number' && Number.isFinite(bytes) ? bytes : null;
      } catch (err) {
        console.warn(
          'Introspector: could not read pg_database_size; reporting size_bytes as null rather ' +
            `than substituting a different measurement: ${err instanceof Error ? err.message : String(err)}`,
        );
      }

      const snapshot: SchemaSnapshot = {
        pg_version,
        snapshot_at: Date.now(),
        schemas,
        tables: tablesList,
        extensions,
        size_bytes: databaseSizeBytes ?? 0,
      };

      return {
        pg_version: snapshot.pg_version,
        snapshot_at: snapshot.snapshot_at,
        schema: {
          tables: snapshot.tables,
        },
        extensions: snapshot.extensions,
        schemas: snapshot.schemas,
        size_bytes: databaseSizeBytes,
        snapshot_json_bytes: Buffer.byteLength(JSON.stringify(snapshot), 'utf8'),
        detail,
      };
    } finally {
      release();
    }
  }
}

/**
 * Major version from a PostgreSQL version string.
 *
 * `SELECT version()` returns e.g. `PostgreSQL 16.2 (Debian 16.2-1.pgdg120+1) on
 * x86_64-pc-linux-gnu`, and a caller-supplied hint may be `16`, `16.2` or the
 * same string. Only the leading `major.minor` is meaningful for compatibility,
 * so the major is what is compared.
 */
export function parseMajorVersion(raw: string): number | null {
  const match = /(\d+)(?:\.\d+)?/.exec(raw);
  if (!match) {
    return null;
  }
  const major = Number(match[1]);
  return Number.isInteger(major) && major > 0 ? major : null;
}

/**
 * Fail closed when the caller's declared server version is not the server we are
 * connected to. An absent hint (`null`/blank) imposes no expectation.
 *
 * Throws a plain `Error`; the dispatcher converts it into an error frame, so the
 * caller learns that no snapshot was taken rather than receiving one that
 * answers a question it did not ask.
 */
export function assertVersionHintMatches(
  serverVersion: string,
  hint: string | null | undefined,
): void {
  if (hint === null || hint === undefined || hint.trim() === '') {
    return;
  }
  const declared = parseMajorVersion(hint);
  if (declared === null) {
    throw new Error(
      `pg_version_hint "${hint}" is not a PostgreSQL version; refusing to snapshot a server the ` +
        'caller could not have meant.',
    );
  }
  const actual = parseMajorVersion(serverVersion);
  if (actual === null) {
    throw new Error(
      `Could not determine the connected server's major version from ${JSON.stringify(serverVersion)}, ` +
        `so the declared hint "${hint}" cannot be verified. Refusing rather than assuming a match.`,
    );
  }
  if (declared !== actual) {
    throw new Error(
      `pg_version_hint declares PostgreSQL ${declared} but this database is PostgreSQL ${actual}. ` +
        'The snapshot would describe a different server, so the request was refused.',
    );
  }
}
