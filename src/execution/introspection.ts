import { PoolManager } from './pool';
import { DbEntry } from '../config/db-config';
import { IntrospectPayload, IntrospectResultPayload } from '../protocol/messages';
import { SchemaSnapshot, TableSnapshot } from './types';

export interface IntrospectorOptions {
  poolManager: PoolManager;
}

export class Introspector {
  private readonly poolManager: PoolManager;

  constructor(opts: IntrospectorOptions) {
    this.poolManager = opts.poolManager;
  }

  async introspect(payload: IntrospectPayload, dbEntry: DbEntry): Promise<IntrospectResultPayload> {
    const { client, release } = await this.poolManager.acquire(dbEntry);

    try {
      // 1. Version
      const versionRes = await client.query('SELECT version();');
      const pg_version = versionRes.rows[0]?.version || 'unknown';

      // 2. Schemas
      const schemasRes = await client.query(`
        SELECT schema_name FROM information_schema.schemata
        WHERE schema_name NOT LIKE 'pg_%' AND schema_name != 'information_schema'
        ORDER BY schema_name;
      `);
      const schemas = schemasRes.rows.map(r => r.schema_name);

      // 3. Tables & Views
      const tablesRes = await client.query(`
        SELECT
          t.table_schema, t.table_name,
          CASE
            WHEN t.table_type = 'BASE TABLE' THEN 'table'
            WHEN t.table_type = 'VIEW' THEN 'view'
          END as type,
          pg_catalog.obj_description(c.oid) as comment,
          pg_catalog.pg_get_userbyid(c.relowner) as owner
        FROM information_schema.tables t
        JOIN pg_catalog.pg_class c ON c.relname = t.table_name
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace AND n.nspname = t.table_schema
        WHERE t.table_schema NOT LIKE 'pg_%' AND t.table_schema != 'information_schema'
        ORDER BY t.table_schema, t.table_name;
      `);

      let matViewsRows: Array<{ table_schema: string; table_name: string; type: 'materialized_view' }> = [];
      if (payload.include_views !== false) {
        const matViewsRes = await client.query(`
          SELECT schemaname as table_schema, matviewname as table_name, 'materialized_view' as type
          FROM pg_catalog.pg_matviews
          WHERE schemaname NOT LIKE 'pg_%'
          ORDER BY schemaname, matviewname;
        `);
        matViewsRows = matViewsRes.rows as Array<{ table_schema: string; table_name: string; type: 'materialized_view' }>;
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
          owner: row.owner || '',
          comment: row.comment || null,
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
      const columnsRes = await client.query(`
        SELECT
          c.table_schema, c.table_name, c.column_name,
          c.data_type, c.udt_name, c.is_nullable, c.column_default,
          c.character_maximum_length, c.numeric_precision, c.numeric_scale,
          c.ordinal_position
        FROM information_schema.columns c
        WHERE c.table_schema NOT LIKE 'pg_%' AND c.table_schema != 'information_schema'
        ORDER BY c.table_schema, c.table_name, c.ordinal_position;
      `);

      for (const row of columnsRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        table.columns.push({
          name: row.column_name,
          type: row.udt_name || row.data_type,
          nullable: row.is_nullable === 'YES',
          default: row.column_default || null,
          is_primary_key: false,
          is_unique: false,
          is_foreign_key: false,
        });
      }

      // 5. PK / Uniques
      const constraintsRes = await client.query(`
        SELECT
          tc.table_schema, tc.table_name, tc.constraint_name, tc.constraint_type,
          string_agg(kcu.column_name, ',' ORDER BY kcu.ordinal_position) as columns
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE')
          AND tc.table_schema NOT LIKE 'pg_%'
        GROUP BY tc.table_schema, tc.table_name, tc.constraint_name, tc.constraint_type;
      `);

      for (const row of constraintsRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        const cols = (row.columns || '').split(',');
        if (row.constraint_type === 'PRIMARY KEY') {
          for (const colName of cols) {
            const col = table.columns.find(c => c.name === colName);
            if (col) col.is_primary_key = true;
          }
        } else if (row.constraint_type === 'UNIQUE') {
          for (const colName of cols) {
            const col = table.columns.find(c => c.name === colName);
            if (col) col.is_unique = true;
          }
        }
      }

      // 6. Foreign keys
      const fksRes = await client.query(`
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
      `);

      for (const row of fksRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        const col = table.columns.find(c => c.name === row.column_name);
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
        const indexesRes = await client.query(`
          SELECT
            schemaname, tablename, indexname, indexdef
          FROM pg_catalog.pg_indexes
          WHERE schemaname NOT LIKE 'pg_%'
          ORDER BY schemaname, tablename, indexname;
        `);

        for (const row of indexesRes.rows) {
          const key = `${row.schemaname}.${row.tablename}`;
          const table = tablesMap.get(key);
          if (!table) continue;

          const isUnique = row.indexdef.toUpperCase().includes('UNIQUE');
          const isPrimary = row.indexdef.toUpperCase().includes('PRIMARY KEY') || row.indexname.endsWith('_pkey');

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
            definition: row.indexdef,
          });
        }
      }

      // 8. Check constraints
      const checksRes = await client.query(`
        SELECT
          tc.table_schema, tc.table_name, tc.constraint_name,
          cc.check_clause
        FROM information_schema.table_constraints tc
        JOIN information_schema.check_constraints cc ON tc.constraint_name = cc.constraint_name
        WHERE tc.constraint_type = 'CHECK'
          AND tc.table_schema NOT LIKE 'pg_%';
      `);

      for (const row of checksRes.rows) {
        const key = `${row.table_schema}.${row.table_name}`;
        const table = tablesMap.get(key);
        if (!table) continue;

        table.constraints.push({
          name: row.constraint_name,
          type: 'CHECK',
          definition: row.check_clause,
        });
      }

      // 9. Triggers
      if (payload.include_triggers !== false) {
        const triggersRes = await client.query(`
          SELECT
            event_object_schema, event_object_table, trigger_name,
            event_manipulation, action_timing, action_statement
          FROM information_schema.triggers
          WHERE event_object_schema NOT LIKE 'pg_%'
          ORDER BY event_object_schema, event_object_table, trigger_name;
        `);

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
        const extensionsRes = await client.query(`
          SELECT extname, extversion
          FROM pg_catalog.pg_extension
          WHERE extname NOT LIKE 'pg_%';
        `);
        extensions = extensionsRes.rows.map(row => ({
          name: row.extname,
          version: row.extversion,
          enabled: true,
        }));
      }

      // 11. Partitions
      if (payload.include_partitions !== false) {
        const partitionsRes = await client.query(`
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
        `);

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
              for_values: row.for_values || '',
            });
          }
        }
      }

      const snapshot: SchemaSnapshot = {
        pg_version,
        snapshot_at: Date.now(),
        schemas,
        tables: tablesList,
        extensions,
        size_bytes: 0,
      };

      snapshot.size_bytes = Buffer.byteLength(JSON.stringify(snapshot), 'utf8');

      return {
        pg_version: snapshot.pg_version,
        snapshot_at: snapshot.snapshot_at,
        schema: {
          tables: snapshot.tables,
        },
        extensions: snapshot.extensions,
        schemas: snapshot.schemas,
        size_bytes: snapshot.size_bytes,
      };
    } finally {
      release();
    }
  }
}
