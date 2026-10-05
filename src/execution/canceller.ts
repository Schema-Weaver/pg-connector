import { Client, PoolClient } from 'pg';
import { DbEntry } from '../config/db-config';
import { InFlightRequest } from './types';
import { PoolManager, buildSslConfig } from './pool';

export interface CancellerOptions {
  /** Optional: reuse pool manager for the cancel connection. */
  poolManager?: PoolManager;
}

export interface CancelResult {
  cancelled: boolean;
  terminated: boolean;
  reason?: string;
}

export class Canceller {
  private readonly inFlight: Map<string, InFlightRequest> = new Map();
  private readonly opts: CancellerOptions;

  constructor(opts: CancellerOptions = {}) {
    this.opts = opts;
  }

  register(req: InFlightRequest): void {
    this.inFlight.set(req.request_id, req);
  }

  unregister(requestId: string): void {
    this.inFlight.delete(requestId);
  }

  getInFlight(): Map<string, InFlightRequest> {
    return this.inFlight;
  }

  /**
   * Cancel a request by request_id.
   * Opens a new connection to the same DB, runs pg_cancel_backend(pid).
   */
  async cancel(requestId: string, dbEntry: DbEntry): Promise<CancelResult> {
    const req = this.inFlight.get(requestId);
    if (!req) {
      return {
        cancelled: false,
        terminated: false,
        reason: 'No in-flight request found with the specified ID.',
      };
    }

    // Trigger local abort controller
    req.abort.abort();

    let client: Client | PoolClient | null = null;
    let cleanup: () => void = () => {};

    if (this.opts.poolManager) {
      try {
        const acquired = await this.opts.poolManager.acquire(dbEntry);
        client = acquired.client;
        cleanup = acquired.release;
      } catch {
        // Fallback to one-off if pool acquire fails
      }
    }

    if (!client) {
      // Mirror the pool's TLS negotiation — without this, cancellation fails
      // against verify-ca/verify-full databases that reject plaintext.
      let sslConfig: boolean | { ca: Buffer; rejectUnauthorized: boolean };
      try {
        sslConfig = buildSslConfig(dbEntry.ssl_mode, dbEntry.ssl_root_cert);
      } catch {
        sslConfig = false; // cancel is best-effort; never block on cert load
      }
      const password = dbEntry.password_stored || (dbEntry.password_env ? process.env[dbEntry.password_env] : '') || '';
      const c = new Client({
        host: dbEntry.host,
        port: dbEntry.port,
        database: dbEntry.database,
        user: dbEntry.user,
        password: password,
        ssl: sslConfig,
      });
      await c.connect();
      client = c;
      cleanup = () => {
        c.end().catch(() => {});
      };
    }

    try {
      const cancelRes = await client.query('SELECT pg_cancel_backend($1) AS cancelled', [req.pid]);
      const wasCancelled = cancelRes.rows[0]?.cancelled === true;
      if (wasCancelled) {
        return { cancelled: true, terminated: true };
      } else {
        return {
          cancelled: false,
          terminated: true,
          reason: 'Query already completed or PG backend session not found.',
        };
      }
    } catch (err: unknown) {
      return {
        cancelled: false,
        terminated: false,
        reason: `Failed to execute pg_cancel_backend query: ${err instanceof Error ? err.message : String(err)}`,
      };
    } finally {
      cleanup();
    }
  }
}
