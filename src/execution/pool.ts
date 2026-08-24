import { Pool, PoolClient } from 'pg';
import * as fs from 'fs';
import { DbEntry } from '../config/db-config';
import { PoolManagerEvents } from './types';
import { DEFAULTS } from '../protocol/constants';

export class PoolError extends Error {
  constructor(
    public code: 'env_var_missing' | 'connection_failed' | 'auth_failed' | 'db_not_found' | 'ssl_error' | 'pool_exhausted',
    message: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'PoolError';
  }
}

export interface PoolManagerOptions {
  /** Called when a pool opens/closes. */
  events?: PoolManagerEvents;
  /** Idle timeout before closing a pool. Default 60_000. */
  idleTimeoutMs?: number;
  /** Max connections per pool. Default 5. */
  maxPoolSize?: number;
}

/**
 * Build node-postgres SSL options from a DbEntry's ssl settings.
 * Shared by PoolManager and Canceller so ad-hoc connections (e.g. cancel
 * backends) negotiate TLS exactly like pooled ones.
 */
export function buildSslConfig(
  mode: string,
  rootCert?: string | null
): boolean | { ca: Buffer; rejectUnauthorized: boolean } {
  if (mode === 'require') return { ca: undefined as unknown as Buffer, rejectUnauthorized: false };
  if (mode === 'verify-ca' || mode === 'verify-full') {
    if (!rootCert) {
      throw new Error('ssl_root_cert required for ' + mode);
    }
    return { ca: fs.readFileSync(rootCert), rejectUnauthorized: true };
  }
  return false; // 'disable' (and unknown modes) → no TLS
}

export class PoolManager {
  private pools: Map<string, { pool: Pool; idleSince: number; idleTimer?: NodeJS.Timeout }> = new Map();
  private activeClientsCount: Map<string, number> = new Map();
  private readonly opts: PoolManagerOptions;

  constructor(opts: PoolManagerOptions = {}) {
    this.opts = opts;
  }

  /**
   * Get a pool client for the given DB entry.
   * Opens the pool if it doesn't exist.
   * Resets the idle timer.
   */
  async acquire(dbEntry: DbEntry): Promise<{ client: PoolClient; release: () => void; pid: number }> {
    const dbAlias = dbEntry.db_alias;

    let poolRecord = this.pools.get(dbAlias);
    if (!poolRecord) {
      const password = dbEntry.password_stored || (dbEntry.password_env ? process.env[dbEntry.password_env] : undefined);
      if (!password) {
        const envHint = dbEntry.password_env 
          ? `Environment variable "${dbEntry.password_env}" is missing or empty.`
          : 'No password configured.';
        throw new PoolError(
          'env_var_missing',
          `Password not found. ${envHint}`
        );
      }

      let sslConfig: boolean | { ca: Buffer; rejectUnauthorized: boolean };
      try {
        sslConfig = buildSslConfig(dbEntry.ssl_mode, dbEntry.ssl_root_cert);
      } catch (err: unknown) {
        throw new PoolError(
          'ssl_error',
          `Failed to load SSL configuration: ${err instanceof Error ? err.message : String(err)}`,
          err instanceof Error ? err : undefined
        );
      }

      const pool = new Pool({
        host: dbEntry.host,
        port: dbEntry.port,
        database: dbEntry.database,
        user: dbEntry.user,
        password: password,
        ssl: sslConfig,
        max: this.opts.maxPoolSize ?? 5,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
        statement_timeout: 30_000,
      });

      poolRecord = {
        pool,
        idleSince: Date.now(),
      };
      this.pools.set(dbAlias, poolRecord);
      this.activeClientsCount.set(dbAlias, 0);

      if (this.opts.events?.onPoolOpen) {
        this.opts.events.onPoolOpen(dbAlias);
      }
    }

    // Cancel idle timer if it is active
    if (poolRecord.idleTimer) {
      clearTimeout(poolRecord.idleTimer);
      poolRecord.idleTimer = undefined;
    }

    let client: PoolClient;
    try {
      client = await poolRecord.pool.connect();
    } catch (err: unknown) {
      // Map postgres errors
      const errorObj = err as { code?: string; message?: string };
      const code = errorObj.code || '';
      let errorType: 'connection_failed' | 'auth_failed' | 'db_not_found' | 'ssl_error' = 'connection_failed';
      let message = errorObj.message || 'Unknown connection error';

      if (code === 'ECONNREFUSED' || code === 'ENOTFOUND') {
        errorType = 'connection_failed';
        message = `Cannot reach PostgreSQL at ${dbEntry.host}:${dbEntry.port}. Check that the DB is running and the agent has network access.`;
      } else if (code === '28P01') {
        errorType = 'auth_failed';
        message = `PostgreSQL rejected credentials. Check password for user "${dbEntry.user}".`;
      } else if (code === '28000') {
        errorType = 'auth_failed';
        message = `PG user "${dbEntry.user}" does not have login permission.`;
      } else if (code === '3D000') {
        errorType = 'db_not_found';
        message = `PostgreSQL database "${dbEntry.database}" not found.`;
      } else if (code === '28040' || code === '28P01' || message.includes('no pg_hba.conf entry')) {
        errorType = 'auth_failed';
        message = `Access denied by pg_hba.conf. Check user "${dbEntry.user}" and database "${dbEntry.database}".`;
      } else if (message.includes('ssl') || message.includes('SSL') || message.includes('handshake')) {
        errorType = 'ssl_error';
      }

      throw new PoolError(errorType, message, err instanceof Error ? err : undefined);
    }

    // Acquire PID
    let pid = 0;
    try {
      const pidRes = await client.query('SELECT pg_backend_pid() AS pid');
      pid = pidRes.rows[0].pid;
    } catch (err: unknown) {
      client.release();
      throw new PoolError(
        'connection_failed',
        `Failed to acquire connection PID: ${err instanceof Error ? err.message : String(err)}`,
        err instanceof Error ? err : undefined
      );
    }

    const currentCount = this.activeClientsCount.get(dbAlias) || 0;
    this.activeClientsCount.set(dbAlias, currentCount + 1);

    if (this.opts.events?.onConnectionAcquired) {
      this.opts.events.onConnectionAcquired(dbAlias);
    }

    let released = false;
    const release = () => {
      if (!released) {
        released = true;
        this.release(dbAlias, client);
      }
    };

    return { client, release, pid };
  }

  /** Release a client back to the pool. Resets idle timer. */
  release(dbAlias: string, client: PoolClient): void {
    client.release();

    if (this.opts.events?.onConnectionReleased) {
      this.opts.events.onConnectionReleased(dbAlias);
    }

    const currentCount = this.activeClientsCount.get(dbAlias) || 0;
    const newCount = Math.max(0, currentCount - 1);
    this.activeClientsCount.set(dbAlias, newCount);

    const poolRecord = this.pools.get(dbAlias);
    if (poolRecord && newCount === 0) {
      poolRecord.idleSince = Date.now();
      
      if (poolRecord.idleTimer) {
        clearTimeout(poolRecord.idleTimer);
      }

      const timeout = this.opts.idleTimeoutMs ?? DEFAULTS.IDLE_WSS_TIMEOUT_MS;
      if (timeout > 0) {
        poolRecord.idleTimer = setTimeout(() => {
          this.closePool(dbAlias, 'idle').catch(err => {
            console.error(`Error closing idle pool for "${dbAlias}":`, err);
          });
        }, timeout);
      }
    }
  }

  /** Close a specific pool. */
  async closePool(dbAlias: string, reason: 'idle' | 'explicit' | 'error' = 'explicit'): Promise<void> {
    const poolRecord = this.pools.get(dbAlias);
    if (poolRecord) {
      if (poolRecord.idleTimer) {
        clearTimeout(poolRecord.idleTimer);
      }
      this.pools.delete(dbAlias);
      this.activeClientsCount.delete(dbAlias);

      try {
        await poolRecord.pool.end();
      } catch {
        // ignore errors during end
      }

      if (this.opts.events?.onPoolClose) {
        this.opts.events.onPoolClose(dbAlias, reason);
      }
    }
  }

  /** Close all pools. Used during shutdown. */
  async closeAll(): Promise<void> {
    const aliases = Array.from(this.pools.keys());
    await Promise.all(aliases.map(alias => this.closePool(alias, 'explicit')));
  }

  /** Check if a pool is currently open for this DB. */
  hasPool(dbAlias: string): boolean {
    return this.pools.has(dbAlias);
  }

  /** Get stats for monitoring. */
  getStats(): Array<{ db_alias: string; total_count: number; idle_count: number; waiting_count: number }> {
    return Array.from(this.pools.entries()).map(([dbAlias, record]) => {
      return {
        db_alias: dbAlias,
        total_count: record.pool.totalCount,
        idle_count: record.pool.idleCount,
        waiting_count: record.pool.waitingCount,
      };
    });
  }
}
