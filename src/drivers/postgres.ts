import { Pool } from 'pg';
import { DbEntry, redactDbEntry } from '../config/db-config';
import { classifyStatement } from '../execution/statement-classifier';
import { PoolManager, buildSslConfig } from '../execution/pool';
import { QueryRunner } from '../execution/query-runner';
import type {
  QueryPayload,
  QueryResultPayload,
  StreamQueryPayload,
} from '../protocol/messages';
import type {
  DatabaseDriver,
  DriverCapabilities,
  DriverClassifyOptions,
  DriverConnectionInfo,
  DriverQueryContext,
} from './types';

/**
 * PostgreSQL driver.
 *
 * This is intentionally an adapter over the existing implementation rather than
 * a rewrite: `statement-classifier`, `PoolManager`, `QueryRunner` and the
 * `pg_proc` function-effect resolver already carry the security properties the
 * connector promises. Wrapping them behind the common interface keeps the
 * PostgreSQL path byte-for-byte the same while giving MySQL and MongoDB a place
 * to plug in.
 */
export class PostgresDriver implements DatabaseDriver {
  readonly type = 'postgres' as const;
  readonly display_name = 'PostgreSQL';
  readonly default_port = 5432;
  readonly capabilities: DriverCapabilities = {
    query: true,
    stream: true,
    introspect: true,
    migration: true,
    server_cancel: true,
  };

  private readonly poolManager: PoolManager;
  private readonly queryRunner: QueryRunner;

  constructor(opts: { poolManager: PoolManager; queryRunner?: QueryRunner }) {
    this.poolManager = opts.poolManager;
    this.queryRunner = opts.queryRunner ?? new QueryRunner({ poolManager: this.poolManager });
  }

  async classify(sql: string, options: DriverClassifyOptions = {}) {
    return classifyStatement(sql, options);
  }

  async testConnection(entry: DbEntry): Promise<DriverConnectionInfo> {
    const password = resolvePassword(entry);
    const pool = new Pool({
      host: entry.host,
      port: entry.port,
      database: entry.database,
      user: entry.user,
      password,
      ssl: buildSslConfig(entry.ssl_mode, entry.ssl_root_cert, entry.host),
      max: 1,
      connectionTimeoutMillis: 5_000,
      application_name: 'schema-weaver-db-connector-probe',
    });

    try {
      const res = await pool.query(
        'SELECT version() AS version, current_database() AS database, current_user AS user',
      );
      const row = (res.rows[0] ?? {}) as Record<string, unknown>;
      const rawVersion = typeof row.version === 'string' ? row.version : '';
      const match = rawVersion.match(/PostgreSQL [^\s,]+/);
      return {
        version: match ? match[0] : rawVersion || 'PostgreSQL',
        database: typeof row.database === 'string' ? row.database : entry.database,
        user: typeof row.user === 'string' ? row.user : entry.user,
      };
    } finally {
      await pool.end().catch(() => undefined);
    }
  }

  async runOneShot(payload: QueryPayload, ctx: DriverQueryContext): Promise<QueryResultPayload> {
    return this.queryRunner.runOneShot(payload, ctx);
  }

  async runStreaming(payload: StreamQueryPayload, ctx: DriverQueryContext): Promise<void> {
    return this.queryRunner.runStreaming(payload, ctx);
  }

  async close(alias: string): Promise<void> {
    await this.poolManager.closePool(alias);
  }

  async closeAll(): Promise<void> {
    await this.poolManager.closeAll();
  }

  redactConfig(entry: DbEntry): Record<string, unknown> {
    return redactDbEntry(entry);
  }
}

export function resolvePassword(entry: DbEntry): string {
  const password =
    entry.password_stored || (entry.password_env ? process.env[entry.password_env] : undefined);
  if (!password) {
    throw new Error(`Password unavailable for database "${entry.db_alias}".`);
  }
  return password;
}
