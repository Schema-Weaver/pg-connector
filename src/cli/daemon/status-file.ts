import * as fs from 'fs';
import * as path from 'path';

/**
 * Health of the audit writer, mirrored from `AuditSinkHealth` so `sw-agent
 * status` can show whether the trail is actually being written instead of only
 * how many events were counted.
 *
 * The required fields are exactly the ones an operator needs to tell a healthy
 * writer from a silently failing one. Everything else the sink exposes is
 * carried as optional, so an `AuditSinkHealth` can be assigned here directly and
 * a producer that reports only the essentials still type-checks.
 */
export interface AuditStatusHealth {
  /** False if the last append failed. Audit loss must never be silent. */
  writable: boolean;
  /** The audit directory the writer is using. */
  dir: string;
  dir_mode: number | null;
  file_mode: number | null;
  events_written: number;
  events_failed: number;
  /** Records actually lost. Any non-zero value is silent history loss. */
  dropped: number;
  last_write_at: string | null;
  last_error: string | null;
  chain_id: string | null;
  /** Sequence number of the newest record this process wrote. */
  seq: number;
  chain_error: string | null;
  /** Oldest sequence number still on disk, or null when nothing is retained. */
  retained_from_seq: number | null;
  ready?: boolean;
  active_path?: string;
  last_error_at?: string | null;
  error_count?: number;
  bytes_written?: number;
  rotations?: number;
  queue_depth?: number;
  overflow_admitted?: number;
}

/**
 * Effective security posture, as the daemon resolved it.
 *
 *  and  are both invisible by default: an agent with no database
 * allow-list used to serve every configured database silently, and the local role
 * ceiling had no reader at all. Both facts are printed to the console of a
 * detached daemon that most operators never read, so the daemon also writes them
 * here — this is the block `sw-agent status` renders.
 *
 * Optional because a status file written by an older daemon predates it, and
 * because a reader that does not understand it must degrade rather than fail.
 */
export interface SecurityStatus {
  /** One line stating the effective database scope in words. */
  database_scope: string;
  /** Whether any allow-list (`allowed_databases` / `SW_AGENT_ALLOWED_DATABASES`) is in force. */
  allowlist_configured: boolean;
  /**
   * Whether the pre-remediation permissive default was deliberately restored with
   * `security.allow_unscoped_databases: true`. When true, one token reaches every
   * configured database.
   */
  allow_unscoped_databases: boolean;
  /** True when the agent serves `ping` only because nothing is declared. */
  fail_closed: boolean;
  /** True when the environment channel narrowed the configured allow-list. */
  env_narrowed_scope: boolean;
  /**
   * Effective local role ceiling. `'admin'` means a compromised relay has the
   * full capability set on every database the agent can reach.
   */
  max_negotiable_role: string;
}

export interface DaemonStatus {
  pid: number;
  started_at: string;
  last_heartbeat: string;
  version: string;
  channels: {
    sse: 'connecting' | 'connected' | 'disconnected' | 'error';
    wss: 'idle' | 'connecting' | 'connected' | 'disconnected' | 'error';
    last_sse_reconnect?: string;
    last_wss_session?: string;
  };
  stats: {
    queries_served: number;
    streams_served: number;
    migrations_run: number;
    cancellations: number;
    permission_denies: number;
    audit_events_written: number;
    /**
     * Records the sink could not persist. Optional because a status file written
     * by a daemon without it predates the counter; readers treat an absent value
     * as 0 rather than as "no failures".
     */
    audit_events_failed?: number;
    audit_buffer_overflows: number;
    /**
     * Records the bounded audit queue discarded outright under pressure. Optional
     * for the same reason as `audit_events_failed`: a status file written by a
     * daemon without the counter predates it, and an absent value means "no drops
     * reported", not "the trail is complete". Also available as `audit.dropped`.
     */
    audit_dropped?: number;
  };
  /**
   * Audit writer health. Optional because a status file written by a build
   * without it predates this field: readers must degrade to the counters rather
   * than fail.
   */
  audit?: AuditStatusHealth;
  config?: {
    databases: number;
    projects: number;
    revision: number;
  };
  /** Location and size of the local, rotated error log. Surfaced by `sw-agent status`. */
  errors_log?: {
    path: string;
    size_bytes: number;
  };
  /**
   * Effective security posture (database scope, role ceiling). Optional so a
   * status file written by a build without it still reads; `sw-agent status`
   * degrades to the counters rather than failing.
   */
  security?: SecurityStatus;
  last_error?: {
    ts: string;
    code: string;
    message: string;
  };
}

export interface StatusFileOptions {
  path: string;
}

import * as crypto from 'crypto';

export async function writeStatusFile(
  opts: StatusFileOptions,
  status: DaemonStatus,
): Promise<void> {
  const dir = path.dirname(opts.path);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });

  const tmpPath = opts.path + '.tmp.' + crypto.randomBytes(8).toString('hex');
  await fs.promises.writeFile(tmpPath, JSON.stringify(status, null, 2), {
    mode: 0o600,
    encoding: 'utf8',
  });

  for (let i = 0; i < 10; i++) {
    try {
      await fs.promises.rename(tmpPath, opts.path);
      return;
    } catch (err) {
      if (i === 9) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

export async function readStatusFile(opts: StatusFileOptions): Promise<DaemonStatus | null> {
  for (let i = 0; i < 10; i++) {
    try {
      const content = await fs.promises.readFile(opts.path, 'utf8');
      return JSON.parse(content) as DaemonStatus;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        return null;
      }
      if (i === 9) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  return null;
}

export function isStatusStale(status: DaemonStatus, now: Date = new Date()): boolean {
  const heartbeatTime = new Date(status.last_heartbeat).getTime();
  const nowTime = now.getTime();
  const ageMs = nowTime - heartbeatTime;
  return ageMs > 90_000;
}
