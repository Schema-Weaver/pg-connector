import { Client, PoolClient } from 'pg';
import type { ClientConfig } from 'pg';
import { DbEntry } from '../config/db-config';
import { InFlightRequest } from './types';
import { PoolManager, buildSslConfig, markSessionDirty, PoolSslConfig } from './pool';

export interface CancellerOptions {
  /**
   * Reuse the pool for the cancellation connection.
   *
   * This is not an optimisation: without it every cancel opened a brand-new
   * TCP + TLS + password-authenticated PostgreSQL connection, so a stream of
   * cancel requests could exhaust `max_connections` on the customer's database.
   */
  poolManager?: PoolManager;
}

export interface CancelResult {
  /** Whether a cancellation signal was delivered to the request. */
  cancelled: boolean;
  /** Whether the PostgreSQL backend was actually signalled. */
  terminated: boolean;
  /**
   * Whether the in-process cooperative abort fired. The local runner stops at
   * its next checkpoint without any database round trip, so this can be true
   * while `terminated` is false — a blocked server-side statement is still
   * running until `pg_cancel_backend` reaches it.
   */
  local_abort: boolean;
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
   * Cancel a request by request_id using pg_cancel_backend on a separate
   * connection (PostgreSQL cannot cancel a query from the busy session).
   */
  async cancel(requestId: string, dbEntry: DbEntry): Promise<CancelResult> {
    const req = this.inFlight.get(requestId);
    if (!req) {
      return {
        cancelled: false,
        terminated: false,
        local_abort: false,
        reason: 'No in-flight request found with the specified ID.',
      };
    }

    // Cooperative local cancellation. Every runner that registers an in-flight
    // request listens on this controller, so firing it stops the local work at
    // the next checkpoint (between FETCH batches, before the next statement)
    // with no database round trip at all. This happens first and never depends
    // on the connection below succeeding.
    const localAbortFired = !req.abort.signal.aborted;
    req.abort.abort();

    let client: Client | PoolClient | null = null;
    let cleanup: () => void = () => {};

    if (this.opts.poolManager) {
      try {
        const acquired = await this.opts.poolManager.acquire(dbEntry);
        client = acquired.client;
        // This connection is about to issue `pg_cancel_backend`. From here on its
        // session is no longer a session this pool can vouch for: it has acted on
        // a backend the pool knows nothing about, and nothing that happens next
        // can prove the session clean again.
        //
        // Marking it dirty is what makes `PoolManager.release` destroy it instead
        // of recycling it. Releasing it normally would put a connection that has
        // already cancelled someone else's session back into the idle queue, where
        // the next unrelated request inherits it — the same reason
        // `MigrationRunner` marks its client dirty before it opens a transaction.
        // The cost is one reconnect per cancel, which is the point: reusing the
        // pool instead of dialling a new connection is what keeps a stream of
        // cancels from exhausting `max_connections`, and it does not require
        // recycling the connection that did it.
        markSessionDirty(acquired.client);
        cleanup = acquired.release;
      } catch {
        client = null;
      }
    }

    if (!client) {
      // Fall back to a one-off connection. Mirror the pool's TLS negotiation
      // exactly. The previous code fell back to `sslConfig = false`, which
      // silently downgraded a credential-bearing connection to plaintext when
      // the CA file could not be read.
      let sslConfig: PoolSslConfig;
      try {
        sslConfig = buildSslConfig(dbEntry.ssl_mode, dbEntry.ssl_root_cert);
      } catch (err: unknown) {
        // Audit M-02: fail CLOSED, and report it as the failure it is.
        //
        // `cancelled` is the wire fact documented on CancelResultPayload —
        // "whether the cancel signal was sent". No signal reached PostgreSQL,
        // so it is `false`; the cooperative abort that did fire is reported
        // separately and exactly, through `local_abort`. Claiming `cancelled:
        // true` here told the browser the backend had been signalled while a
        // blocked statement kept running.
        //
        // The detail is logged rather than folded into `reason`, which stays the
        // stable `ssl_error` code this contract specifies and that
        // validateCancelResultPayload accepts as a plain string.
        console.error(
          `Canceller: refusing to open a cancellation connection for ${dbEntry.db_alias} without TLS ` +
            `(ssl_mode ${dbEntry.ssl_mode}): ${
              err instanceof Error ? err.message : String(err)
            }`,
        );
        return {
          cancelled: false,
          terminated: false,
          local_abort: localAbortFired,
          reason: 'ssl_error',
        };
      }

      const password =
        dbEntry.password_stored ||
        (dbEntry.password_env ? process.env[dbEntry.password_env] : undefined);
      if (!password) {
        // Same contract as the TLS refusal above: no signal reached PostgreSQL,
        // so `cancelled` is false and the cooperative abort is reported through
        // `local_abort` alone. Claiming `cancelled: true` here told the browser
        // the backend had been signalled when nothing was ever sent.
        return {
          cancelled: false,
          terminated: false,
          local_abort: localAbortFired,
          reason: 'No password available for the cancellation connection.',
        };
      }

      const clientConfig: ClientConfig = {
        host: dbEntry.host,
        port: dbEntry.port,
        database: dbEntry.database,
        user: dbEntry.user,
        password,
        ssl: sslConfig as ClientConfig['ssl'],
        connectionTimeoutMillis: 5_000,
        application_name: 'schema-weaver-pg-connector-cancel',
      };
      const c = new Client(clientConfig);
      try {
        await c.connect();
      } catch (err: unknown) {
        // The connection never opened, so no cancel signal was sent. Fail closed
        // for the same reason as the TLS path, and keep the underlying cause on
        // the console rather than folding it into the stable `reason` string.
        console.error(
          `Canceller: could not open a cancellation connection for ${dbEntry.db_alias}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        return {
          cancelled: false,
          terminated: false,
          local_abort: localAbortFired,
          reason: `Could not open a cancellation connection: ${
            err instanceof Error ? err.message : String(err)
          }`,
        };
      }
      client = c;
      cleanup = () => {
        c.end().catch(() => {});
      };
    }

    try {
      const cancelRes = await client.query('SELECT pg_cancel_backend($1) AS cancelled', [req.pid]);
      const wasCancelled = cancelRes.rows[0]?.cancelled === true;
      if (wasCancelled) {
        return { cancelled: true, terminated: true, local_abort: localAbortFired };
      }
      // PostgreSQL answered `false`: no cancel signal was delivered. That is
      // the server's own verdict and it governs `cancelled`.
      //
      // This previously reported `cancelled: localAbortFired`, which is `true`
      // whenever the local AbortController fired. A caller that trusted the
      // field was told a blocked statement had been stopped while it kept
      // running on the server — the exact failure the `catch` branch below was
      // already corrected for. A local abort stops OUR loop; only
      // pg_cancel_backend stops PostgreSQL's.
      return {
        cancelled: false,
        terminated: true,
        local_abort: localAbortFired,
        reason:
          'PostgreSQL reported the cancel signal was not delivered (pg_cancel_backend ' +
          'returned false). The backend was likely already idle, gone, or the PID was ' +
          'recycled. The local fetch loop was aborted' +
          (localAbortFired ? '.' : ', but it had already finished.'),
      };
    } catch (err: unknown) {
      // `pg_cancel_backend` did not return a verdict, so no signal is known to
      // have reached PostgreSQL. The previous `cancelled: localAbortFired` made
      // a fired local abort indistinguishable from a delivered cancel, so the
      // browser was told a blocked statement had been stopped while it kept
      // running. Fail closed and keep the cause on the console.
      console.error(
        `Canceller: pg_cancel_backend failed for ${dbEntry.db_alias} (pid ${req.pid}): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
      return {
        cancelled: false,
        terminated: false,
        local_abort: localAbortFired,
        reason: `pg_cancel_backend failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    } finally {
      // A connection that has issued a cancel is never handed back for reuse.
      //
      // Pooled: `markSessionDirty` above makes this release *destroy* the
      //   connection instead of returning it to the idle queue, so the next
      //   request cannot inherit a session that just cancelled a backend.
      // One-off: `cleanup` ends the dedicated connection, and its rejection is
      //   already swallowed there.
      //
      // Both are the same call, so there is one branch — not a conditional whose
      // arms happen to be identical. Neither may throw: this runs in a `finally`,
      // and an exception raised while unwinding would replace the cancel result
      // the caller is about to report to the browser with a release failure that
      // says nothing about whether the query was actually stopped.
      try {
        cleanup();
      } catch {
        // The cancel outcome above stands; a connection that will not release is
        // the pool's problem to log, not a reason to misreport the cancel.
      }
    }
  }
}
