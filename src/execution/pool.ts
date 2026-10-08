import { Pool, PoolClient } from 'pg';
import * as fs from 'fs';
import * as net from 'node:net';
import { createHash } from 'node:crypto';
import { DbEntry } from '../config/db-config';
import { PoolManagerEvents, runExtended } from './types';
import { DEFAULTS, LIMITS } from '../protocol/constants';
import {
  describeSearchPathSetting,
  renderSearchPathSet,
  resolveSearchPathComponents,
  searchPathMatches,
} from './search-path';

/**
 * The search_path helpers live in `./search-path` so the pure composition and
 * verification logic can be tested without a pool or a database. They are
 * re-exported here because `./execution/pool` is the module the rest of the
 * codebase (and the tests) have always imported them from, and moving that
 * would be a change with no security value.
 */
export {
  DEFAULT_SEARCH_PATH,
  PG_CATALOG_SCHEMA,
  PG_TEMP_SCHEMA,
  isBareSchemaIdentifier,
  parseSearchPathSetting,
  renderSearchPathSet,
  searchPathMatches,
} from './search-path';

/** Stable machine-readable classification of a pool failure. */
export type PoolErrorCode =
  | 'env_var_missing'
  | 'connection_failed'
  | 'auth_failed'
  | 'db_not_found'
  | 'ssl_error'
  | 'pool_exhausted'
  | 'unsafe_session_setting';

/**
 * Absolute hard ceiling on `statement_timeout`, in milliseconds.
 *
 * Nothing can raise this: not a `timeout_ms` in a cloud request, not the
 * `SW_MAX_STATEMENT_TIMEOUT_MS` environment variable, and not the
 * `PoolManager` option. It exists so that "hard-capped" is a property of the
 * build rather than of whatever number is configured next.
 */
export const MAX_STATEMENT_TIMEOUT_MS = 900_000;

/**
 * How long a statement may wait for a lock before it is cancelled. Without
 * this, `SELECT ... FOR UPDATE` or a migration waiting on a DDL lock pins a
 * pooled backend (and its transaction snapshot) until the client's own
 * statement_timeout, which is per-statement and can be very large.
 */
export const LOCK_TIMEOUT_MS = 10_000;

/**
 * How long a connection may sit idle inside an open transaction. An idle
 * transaction holds a snapshot, blocks vacuum cleanup and pins a pool slot;
 * this terminates the backend instead of letting it linger.
 */
export const IDLE_IN_TRANSACTION_TIMEOUT_MS = DEFAULTS.MIGRATION_TIMEOUT_MS;

/** Bounds for the per-pool connection count. */
export const MIN_POOL_SIZE = 1;
export const MAX_POOL_SIZE = 100;
export const DEFAULT_POOL_SIZE = 15;

export class PoolError extends Error {
  constructor(
    public code: PoolErrorCode,
    message: string,
    public cause?: Error,
  ) {
    super(message);
    this.name = 'PoolError';
  }
}

/**
 * Collapse anything that is not an identifier character. Applied to every
 * operator-controlled value that is embedded in a user-facing message.
 */
function safeToken(value: string): string {
  return value.replace(/[^A-Za-z0-9_.:@-]/g, '_').slice(0, 64);
}

/**
 * The only connection identifier that may appear in an outbound message.
 * Host, port, user and database are connection secrets/topology: an auth
 * failure or an unreachable host used to disclose all four verbatim.
 */
function safeTarget(dbEntry: DbEntry): string {
  return `database "${safeToken(dbEntry.db_alias)}"`;
}

/**
 * Last-resort scrub of a PostgreSQL or driver message: replace anything that
 * looks like this entry's host, port, user, database or password with an opaque
 * placeholder before it is allowed into a message that will be forwarded to the
 * cloud and the browser.
 *
 * The curated messages in {@link PoolManager.mapConnectError} never contain
 * these values at all; this exists for the driver text that reaches the
 * unrecognised-error branch, which can quote the connection string verbatim.
 */
function scrubKnownSecrets(dbEntry: DbEntry, message: string): string {
  let out = message;
  const secrets: Array<[string, string]> = [
    [dbEntry.password_stored ?? '', 'password'],
    [dbEntry.host ?? '', 'host'],
    [dbEntry.user ?? '', 'user'],
    [dbEntry.database ?? '', 'database'],
    [String(dbEntry.port ?? ''), 'port'],
  ];
  for (const [secret, label] of secrets) {
    if (secret.length >= 2 && out.includes(secret)) {
      out = out.split(secret).join(`[${label}]`);
    }
  }
  return out;
}

/** Bound the length of any driver text that reaches a user-facing message. */
function truncateMessage(message: string, max = 200): string {
  const flat = message.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}...` : flat;
}

/**
 * Connections whose session state could not be proven clean. They are
 * destroyed on release rather than handed to the next request, because
 * `release()` is synchronous and cannot run the `RESET ALL` that would be
 * needed to make them safe again.
 */
const dirtySessions = new WeakSet<PoolClient>();

/**
 * Declare that a pooled connection has been used for a stateful sequence — an
 * open transaction, a cursor, or any statement that may have changed session
 * GUCs — and can no longer be proven to hold nothing but the posture
 * {@link PoolManager.acquire} established.
 *
 * Call this as soon as such a sequence starts. The connection is destroyed on
 * release, which costs one reconnect; forgetting to call it costs a session
 * GUC leak into the next request.
 */
export function markSessionDirty(client: PoolClient): void {
  dirtySessions.add(client);
}

export interface PoolManagerOptions {
  /** Called when a pool opens/closes. */
  events?: PoolManagerEvents;
  /** Idle timeout before closing a pool. Default 60_000. */
  idleTimeoutMs?: number;
  /** Max connections per pool. Default 15. */
  maxPoolSize?: number;
  /**
   * Absolute ceiling on statement_timeout in ms, regardless of what a request
   * asks for. A remote caller must never be able to raise this.
   */
  maxStatementTimeoutMs?: number;
}

export type PoolSslConfig =
  | boolean
  | { ca?: Buffer; rejectUnauthorized: boolean; checkServerIdentity?: () => undefined };

interface PoolRecord {
  pool: Pool;
  idleSince: number;
  idleTimer?: NodeJS.Timeout;
  /** Fingerprint of the connection parameters, so edits force a reconnect. */
  fingerprint: string;
}

/** True when `host` is an IPv4/IPv6 literal rather than a DNS name. */
export function isIpLiteral(host: string | null | undefined): boolean {
  if (typeof host !== 'string' || host.length === 0) return false;
  return net.isIP(host) !== 0;
}

/**
 * Warning text for a `verify-full` entry whose host is an IP literal, or `null`
 * when no warning applies.
 *
 * node-postgres only sets the TLS `servername` for DNS names
 * (`pg/lib/connection.js`: `if (net.isIP(host) === 0) options.servername = host`),
 * so an IP-literal host such as `10.0.1.20` gets no `servername` and Node
 * performs no hostname check at all — `verify-full` silently becomes
 * `verify-ca`. An on-path attacker with any certificate from the same CA can
 * therefore impersonate the server unless the certificate also carries an IP
 * SAN that Node checks, which is rare.
 */
export function hostnameVerificationWarning(
  mode: string,
  host: string | null | undefined,
): string | null {
  if (mode !== 'verify-full' || !isIpLiteral(host)) return null;
  return (
    `ssl_mode 'verify-full' with IP-literal host '${String(host)}' does not verify the ` +
    'server hostname: PostgreSQL drivers send no TLS servername for IP literals, so the ' +
    'certificate chain is checked but the identity is not. This is equivalent to ' +
    "'verify-ca'. Use the database's DNS name, or give the certificate an IP SAN, to " +
    'get real hostname verification.'
  );
}

/**
 * Build node-postgres SSL options from a DbEntry's ssl settings.
 *
 * `verify-ca` and `verify-full` are genuinely different here: `verify-ca`
 * pins the CA and deliberately skips the hostname comparison, `verify-full`
 * lets Node perform it. An unknown mode throws rather than falling back to
 * plaintext.
 *
 * `host` is optional and only used to warn about the IP-literal case; it never
 * changes the returned object.
 */
export function buildSslConfig(
  mode: string,
  rootCert?: string | null,
  host?: string | null,
): PoolSslConfig {
  const warning = hostnameVerificationWarning(mode, host);
  if (warning) {
    console.warn(`[sw-agent] WARNING: ${warning}`);
  }

  switch (mode) {
    case 'disable':
      return false;

    case 'require':
      // TLS, but no verification. Documented as such.
      return { rejectUnauthorized: false };

    case 'verify-ca': {
      if (!rootCert) throw new Error('ssl_root_cert required for verify-ca');
      return {
        ca: fs.readFileSync(rootCert),
        rejectUnauthorized: true,
        checkServerIdentity: () => undefined,
      };
    }

    case 'verify-full': {
      if (!rootCert) throw new Error('ssl_root_cert required for verify-full');
      return { ca: fs.readFileSync(rootCert), rejectUnauthorized: true };
    }

    default:
      // Fail closed. The previous implementation returned `false` (plaintext)
      // for any unrecognised mode.
      throw new Error(
        `Unsupported ssl_mode '${mode}'. Expected one of: disable, require, verify-ca, verify-full.`,
      );
  }
}

/**
 * Stable fingerprint of every parameter that affects the connection or the
 * session posture. The password is hashed, never included verbatim.
 *
 * `password_env` is part of the fingerprint in addition to the resolved
 * secret: switching the entry from `password_stored` to an env var that happens
 * to hold the same string still changes where the credential comes from, and a
 * pool opened for one must not serve the other.
 *
 * The `search_path` contribution is the resolved component list joined with `,`.
 * Components are validated bare identifiers, so they cannot contain `,` or a
 * quote and the join is unambiguous — unlike a joined-then-resplit round-trip,
 * which is exactly the defect  was.
 */
export function connectionFingerprint(entry: DbEntry, password: string): string {
  return [
    entry.host,
    entry.port,
    entry.database,
    entry.user,
    entry.ssl_mode,
    entry.ssl_root_cert ?? '',
    entry.permission_override ?? '',
    entry.password_env ?? '',
    resolveSearchPathComponents(entry).join(','),
    hashSecret(password),
  ].join('\u0000');
}

function hashSecret(secret: string): string {
  // Never put the password itself in a string that might be logged.
  return createHash('sha256').update(secret).digest('hex').slice(0, 16);
}

/**
 * Clamp a caller-supplied timeout to a server-controlled ceiling.
 *
 * `requested <= 0` means "no timeout" in the PostgreSQL world and is never
 * honoured: a remote caller must not be able to remove the ceiling by asking
 * for zero, so it falls back to the default instead.
 */
export function clampStatementTimeout(requested: number | undefined, ceilingMs: number): number {
  const ceiling = Math.min(Math.max(1, Math.floor(ceilingMs)), MAX_STATEMENT_TIMEOUT_MS);
  const fallback = Math.min(DEFAULTS.QUERY_TIMEOUT_MS, ceiling);
  if (requested === undefined || !Number.isFinite(requested)) return fallback;
  if (requested <= 0) return fallback;
  return Math.min(Math.floor(requested), ceiling);
}

export class PoolManager {
  private pools: Map<string, PoolRecord> = new Map();
  private activeClientsCount: Map<string, number> = new Map();
  private readonly opts: PoolManagerOptions;

  constructor(opts: PoolManagerOptions = {}) {
    this.opts = opts;
  }

  /**
   * Ceiling for `statement_timeout`, in milliseconds. Configurable by the
   * operator, never by a request, and never above {@link MAX_STATEMENT_TIMEOUT_MS}.
   */
  get maxStatementTimeoutMs(): number {
    const envCeiling = process.env.SW_MAX_STATEMENT_TIMEOUT_MS
      ? parseInt(process.env.SW_MAX_STATEMENT_TIMEOUT_MS, 10)
      : NaN;
    if (Number.isFinite(envCeiling) && envCeiling > 0) {
      return Math.min(envCeiling, MAX_STATEMENT_TIMEOUT_MS);
    }
    const configured = this.opts.maxStatementTimeoutMs;
    if (typeof configured === 'number' && Number.isFinite(configured) && configured > 0) {
      return Math.min(Math.floor(configured), MAX_STATEMENT_TIMEOUT_MS);
    }
    return Math.min(DEFAULTS.QUERY_TIMEOUT_MS, MAX_STATEMENT_TIMEOUT_MS);
  }

  /**
   * Connections per pool. `SW_PG_POOL_MAX` is operator-controlled but must not
   * be able to set an arbitrary number: an unbounded value exhausts the
   * database's `max_connections`, and a NaN/negative value makes node-postgres
   * behave unpredictably. Garbage falls back to the default of 15.
   */
  get maxPoolSize(): number {
    const envRaw = process.env.SW_PG_POOL_MAX;
    if (envRaw !== undefined && envRaw.trim() !== '') {
      const parsed = Number(envRaw.trim());
      if (Number.isInteger(parsed) && parsed >= MIN_POOL_SIZE) {
        if (parsed > MAX_POOL_SIZE) {
          console.warn(
            `[sw-agent] WARNING: SW_PG_POOL_MAX=${parsed} exceeds the ${MAX_POOL_SIZE} connection ` +
              `ceiling; using ${MAX_POOL_SIZE}.`,
          );
          return MAX_POOL_SIZE;
        }
        return parsed;
      }
      console.warn(
        `[sw-agent] WARNING: ignoring invalid SW_PG_POOL_MAX '${envRaw}'. Expected an integer ` +
          `between ${MIN_POOL_SIZE} and ${MAX_POOL_SIZE}; using ${DEFAULT_POOL_SIZE}.`,
      );
      return DEFAULT_POOL_SIZE;
    }

    const configured = this.opts.maxPoolSize;
    if (typeof configured === 'number' && Number.isInteger(configured)) {
      return Math.min(Math.max(configured, MIN_POOL_SIZE), MAX_POOL_SIZE);
    }
    return DEFAULT_POOL_SIZE;
  }

  /**
   * Get a pool client for the given DB entry.
   * Opens the pool if it does not exist, or if the entry's connection
   * parameters changed since the pool was created (so a rotated password or a
   * changed TLS mode takes effect immediately instead of after the idle timer).
   */
  async acquire(
    dbEntry: DbEntry,
  ): Promise<{ client: PoolClient; release: () => void; pid: number }> {
    const dbAlias = dbEntry.db_alias;

    const password =
      dbEntry.password_stored ||
      (dbEntry.password_env ? process.env[dbEntry.password_env] : undefined);
    if (!password) {
      // The variable *name* is credential location information; the host, user
      // and database are topology. Neither belongs in a message that travels to
      // the cloud and the browser.
      const hint = dbEntry.password_env
        ? 'Check that the password environment variable is set in the agent environment.'
        : 'No password is configured for this database.';
      throw new PoolError(
        'env_var_missing',
        `Password unavailable for ${safeTarget(dbEntry)}. ${hint}`,
      );
    }

    const fingerprint = connectionFingerprint(dbEntry, password);
    let poolRecord: PoolRecord | undefined = this.pools.get(dbAlias);

    if (poolRecord && poolRecord.fingerprint !== fingerprint) {
      // Connection parameters changed under us. Retire the old pool so the new
      // credentials / TLS settings actually take effect.
      await this.closePool(dbAlias, 'error');
      poolRecord = undefined;
    }

    if (!poolRecord) {
      let sslConfig: PoolSslConfig;
      try {
        sslConfig = buildSslConfig(dbEntry.ssl_mode, dbEntry.ssl_root_cert, dbEntry.host);
      } catch (err: unknown) {
        throw new PoolError(
          'ssl_error',
          `Failed to load the SSL configuration for ${safeTarget(dbEntry)}: ` +
            scrubKnownSecrets(dbEntry, err instanceof Error ? err.message : String(err)),
          err instanceof Error ? err : undefined,
        );
      }

      const pool = new Pool({
        host: dbEntry.host,
        port: dbEntry.port,
        database: dbEntry.database,
        user: dbEntry.user,
        password,
        ssl: sslConfig,
        max: this.maxPoolSize,
        idleTimeoutMillis: 30_000,
        connectionTimeoutMillis: 5_000,
        application_name: 'schema-weaver-pg-connector',
      });

      poolRecord = { pool, idleSince: Date.now(), fingerprint };
      this.pools.set(dbAlias, poolRecord);
      this.activeClientsCount.set(dbAlias, 0);

      if (this.opts.events?.onPoolOpen) {
        this.opts.events.onPoolOpen(dbAlias);
      }
    }

    // Cancel idle timer if it's active
    if (poolRecord.idleTimer) {
      clearTimeout(poolRecord.idleTimer);
      poolRecord.idleTimer = undefined;
    }

    let client: PoolClient;
    try {
      client = await poolRecord.pool.connect();
    } catch (err: unknown) {
      throw this.mapConnectError(err, dbEntry);
    }

    // Enforce the session posture we promised, on every connection, before any
    // caller-supplied SQL runs. This is defence in depth behind the permission
    // checker: even if a classification bug lets a write through, PostgreSQL
    // itself refuses it for a read_only database. If the posture cannot be
    // established the request is refused rather than served unprotected.
    try {
      await this.hardenSession(client, dbEntry);
    } catch (err: unknown) {
      // The posture is unknown: destroy this connection rather than recycle it.
      client.release(new Error('session hardening failed'));
      throw err;
    }

    let pid = 0;
    try {
      const pidRes = await runExtended(client, 'SELECT pg_backend_pid() AS pid');
      pid = Number((pidRes.rows[0] as { pid?: unknown } | undefined)?.pid ?? 0);
    } catch (err: unknown) {
      client.release(new Error('session state unconfirmed'));
      throw new PoolError(
        'connection_failed',
        `Lost the connection to ${safeTarget(dbEntry)} while confirming its session state.`,
        err instanceof Error ? err : undefined,
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

  /**
   * Put a freshly-checked-out connection into the posture this database entry
   * is configured for, and clear anything a previous request left behind.
   *
   * This is the enforcement point that makes `read_only` physical rather than
   * advisory: a `read_only` entry gets `default_transaction_read_only = on`, so
   * PostgreSQL itself raises `25006` for a write — including a write smuggled
   * in after a `SELECT` that every lexical layer agreed was a read. The value
   * is read back and verified, and any failure here aborts the request.
   */
  private async hardenSession(client: PoolClient, dbEntry: DbEntry): Promise<void> {
    const readOnly = effectivePermission(dbEntry) === 'read_only';
    const expected = readOnly ? 'on' : 'off';

    try {
      // RESET ALL clears every session GUC a previous request may have set
      // (search_path, statement_timeout, application_name, …).
      //
      // It does NOT clear `role` or `session_authorization` — PostgreSQL
      // excludes both. Verified against a live PostgreSQL 18:
      //
      //   SET ROLE jane;  RESET ALL;   -> current_user is STILL jane
      //   RESET ROLE;                   -> back to the authenticated user
      //
      //   SET SESSION AUTHORIZATION jane;  RESET ALL;
      //        -> still jane, and session_user has been rewritten too
      //   RESET SESSION AUTHORIZATION;     -> back to the login role
      //
      // Without the two extra resets, a request at `permission_level: full`
      // that runs `SET ROLE someuser` leaves the pooled backend impersonating
      // that role for every later request the pool hands it to. That is a
      // privilege leak between requests, not a cosmetic leak.
      await runExtended(client, 'RESET ALL');
      await runExtended(client, 'RESET ROLE');
      await runExtended(client, 'RESET SESSION AUTHORIZATION');

      await runExtended(client, `SET default_transaction_read_only = ${readOnly ? 'on' : 'off'}`);

      // Session-level, not SET LOCAL: SET LOCAL outside a transaction block is a
      // silent no-op, which is why queries used to run with no timeout at all.
      await runExtended(client, `SET statement_timeout = ${this.maxStatementTimeoutMs}`);
      await runExtended(
        client,
        `SET idle_in_transaction_session_timeout = ${IDLE_IN_TRANSACTION_TIMEOUT_MS}`,
      );
      await runExtended(client, `SET lock_timeout = ${LOCK_TIMEOUT_MS}`);

      // RESET ALL also cleared search_path back to the role default, and a
      // pooled session would otherwise resolve unqualified names against
      // whatever the previous request left behind.
      //
      // the resolved components are rendered into the *whole statement*
      // in one step from a `string[]`. There is no join-then-split here any
      // more, so a component cannot pick up or lose a space between what we
      // validated and what the server was told — which is how `"analytics,
      // public"` used to become `"analytics", " public"` and silently deleted
      // `public` from the path.
      //
      // `SET` (not `SET LOCAL`) is required: a session-level value must survive
      // until the connection is released.
      const searchPath = resolveSearchPathComponents(dbEntry);
      const searchPathSet = renderSearchPathSet(searchPath);
      await runExtended(client, searchPathSet);

      // Never assume the SET took: confirm it, and refuse the request if not.
      // A non-read_only entry must be confirmed `off` too, so one entry can
      // never leave another entry's connection stuck read-only.
      const check = await runExtended(client, 'SHOW default_transaction_read_only');
      const actual = String(
        (check.rows[0] as { default_transaction_read_only?: unknown } | undefined)
          ?.default_transaction_read_only ?? '',
      ).toLowerCase();
      if (actual !== expected) {
        throw new Error(`default_transaction_read_only is '${actual}', expected '${expected}'`);
      }

      //  post-condition. The old check was
      // `actualPath.toLowerCase().includes(DEFAULT_SEARCH_PATH)`, which the
      // server's own report of `analytics, " public"` satisfied — the control
      // was defeated by exactly the corruption it existed to detect. This
      // compares the reported path against the same array that was rendered,
      // component for component and in order, so a component that is `" public"`
      // instead of `public` fails and the connection is destroyed.
      const pathCheck = await runExtended(client, 'SHOW search_path');
      const actualPath = String(
        (pathCheck.rows[0] as { search_path?: unknown } | undefined)?.search_path ?? '',
      );
      if (!searchPathMatches(actualPath, searchPath)) {
        throw new Error(
          `search_path is '${describeSearchPathSetting(actualPath)}', which is not the pinned ` +
            `list [${searchPath.join(', ')}]`,
        );
      }
    } catch (err: unknown) {
      // The underlying text can contain the host/user/database (libpq and pg
      // both interpolate them), so it is scrubbed rather than forwarded raw.
      throw new PoolError(
        'unsafe_session_setting',
        `Refusing to serve ${safeTarget(dbEntry)}: the read-only session posture could not be ` +
          `established (${scrubKnownSecrets(dbEntry, err instanceof Error ? err.message : String(err))}).`,
        err instanceof Error ? err : undefined,
      );
    }
  }

  /**
   * Translate a driver/pg connection failure into a PoolError with a stable
   * machine code and a message that names the database only by its alias.
   *
   * These messages are forwarded to the cloud and the browser, so host, port,
   * username and database name must never appear in them: an authentication
   * failure used to disclose the username and the `pg_hba.conf` verdict, and a
   * refused connection disclosed the host and port of a production database.
   * `cause` is retained for the local error log only and is never sent.
   */
  private mapConnectError(err: unknown, dbEntry: DbEntry): PoolError {
    const errorObj = err as { code?: string; message?: string };
    const code = errorObj.code || '';
    const rawMessage = errorObj.message || 'Unknown connection error';
    let errorType:
      | 'connection_failed'
      | 'auth_failed'
      | 'db_not_found'
      | 'ssl_error'
      | 'pool_exhausted' = 'connection_failed';
    let message = scrubKnownSecrets(dbEntry, rawMessage);

    if (/timeout exceeded when trying to connect/i.test(rawMessage)) {
      // node-postgres raised this because every pool slot was checked out when
      // `connectionTimeoutMillis` elapsed. Distinct from a network timeout: the
      // server was reachable, the connector was saturated.
      errorType = 'pool_exhausted';
      message =
        `All connections for ${safeTarget(dbEntry)} were in use and none became free within ` +
        'the connection timeout. Lower the concurrency, or raise SW_PG_POOL_MAX.';
    } else if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'ETIMEDOUT') {
      errorType = 'connection_failed';
      message =
        `Cannot reach PostgreSQL for ${safeTarget(dbEntry)}. Check that the database is ` +
        'running and that the agent host can route to it.';
    } else if (code === '28P01') {
      errorType = 'auth_failed';
      message = `PostgreSQL rejected the credentials configured for ${safeTarget(dbEntry)}.`;
    } else if (code === '28000') {
      errorType = 'auth_failed';
      message = `The PostgreSQL role configured for ${safeTarget(dbEntry)} has no login permission.`;
    } else if (code === '3D000') {
      errorType = 'db_not_found';
      message = `The database configured for ${safeTarget(dbEntry)} does not exist on the server.`;
    } else if (code === '28040' || /no pg_hba\.conf entry/i.test(rawMessage)) {
      errorType = 'auth_failed';
      message =
        `pg_hba.conf denied the connection for ${safeTarget(dbEntry)}. The agent host, role, ` +
        'database and network must all be allowed by the server.';
    } else if (/ssl|tls|certificate|handshake|self.signed/i.test(rawMessage)) {
      errorType = 'ssl_error';
      message =
        `TLS negotiation with ${safeTarget(dbEntry)} failed. Check the CA certificate and the ` +
        'configured ssl_mode.';
    } else {
      message = `Could not connect to ${safeTarget(dbEntry)} (${truncateMessage(message)}).`;
    }

    return new PoolError(errorType, message, err instanceof Error ? err : undefined);
  }

  /**
   * Release a client back to the pool. Resets idle timer.
   *
   * A connection marked dirty could not be proven to be back in the posture
   * this entry requires, so it is destroyed instead of recycled: the next
   * request must not inherit an open transaction or a session GUC that the
   * previous request left behind.
   */
  release(dbAlias: string, client: PoolClient): void {
    const dirty = dirtySessions.has(client);
    dirtySessions.delete(client);
    if (dirty) {
      client.release(new Error('connection discarded: session state could not be verified'));
    } else {
      client.release();
    }

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
          this.closePool(dbAlias, 'idle').catch((err) => {
            console.error(`Error closing idle pool for "${dbAlias}":`, err);
          });
        }, timeout);
      }
    }
  }

  /** Close a specific pool. */
  async closePool(
    dbAlias: string,
    reason: 'idle' | 'explicit' | 'error' = 'explicit',
  ): Promise<void> {
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

  /**
   * Close any pool whose connection parameters no longer match the config.
   * Called after the databases config file is reloaded so that a rotated
   * password or a changed TLS mode takes effect immediately.
   */
  async reconcile(databases: DbEntry[]): Promise<string[]> {
    const closed: string[] = [];
    for (const [alias, record] of this.pools.entries()) {
      const entry = databases.find((d) => d.db_alias === alias);
      if (!entry) {
        await this.closePool(alias, 'explicit');
        closed.push(alias);
        continue;
      }
      const password =
        entry.password_stored ||
        (entry.password_env ? process.env[entry.password_env] : undefined) ||
        '';
      if (connectionFingerprint(entry, password) !== record.fingerprint) {
        await this.closePool(alias, 'error');
        closed.push(alias);
      }
    }
    return closed;
  }

  /** Close all pools. Used during shutdown. */
  async closeAll(): Promise<void> {
    const aliases = Array.from(this.pools.keys());
    await Promise.all(aliases.map((alias) => this.closePool(alias, 'explicit')));
  }

  /** Check if a pool is currently open for this DB. */
  hasPool(dbAlias: string): boolean {
    return this.pools.has(dbAlias);
  }

  /** Get stats for monitoring. */
  getStats(): Array<{
    db_alias: string;
    total_count: number;
    idle_count: number;
    waiting_count: number;
  }> {
    return Array.from(this.pools.entries()).map(([dbAlias, record]) => {
      return {
        db_alias: dbAlias,
        total_count: record.pool.totalCount,
        idle_count: record.pool.idleCount,
        waiting_count: record.pool.waitingCount,
      };
    });
  }

  /** Max bytes an inbound protocol message may occupy. Re-exported for the channel layer. */
  static get maxMessageBytes(): number {
    return LIMITS.MAX_PAYLOAD_BYTES;
  }
}

/**
 * The permission level that actually applies to a database entry. Mirrors the
 * dispatcher's resolution so the session posture can never disagree with the
 * permission decision.
 */
export function effectivePermission(dbEntry: DbEntry, machineDefault?: string): string {
  return dbEntry.permission_override ?? machineDefault ?? 'read_only';
}

/**
 * The `search_path` to pin for this entry, as an ordered list of schema names.
 *
 *  renamed this function's contract from `string` to `string[]` and moved
 * it to `./search-path`, together with {@link renderSearchPathSet} (which turns
 * the list into the full `SET search_path = ...` statement) and
 * {@link searchPathMatches} (which verifies the server reported exactly that
 * list back). The list is the only representation now: joining it into a string
 * and re-splitting it on `,` is what turned `public` into `" public"`.
 */
export const resolveSearchPath = resolveSearchPathComponents;
