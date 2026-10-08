import * as fs from 'fs';
import * as path from 'path';
import {
  getAgentHome,
  getAuditDirPath,
  getCredentialKeyPath,
  getDbConfigPath,
  getPidFilePath,
  getStatusFilePath,
  getErrorsPath,
} from '../../config/paths';
import { isProcessAlive, PidFile } from './pid-file';
import { DaemonStatus, isStatusStale } from './status-file';

/* ------------------------------------------------------------------ */
/* Daemon environment allow-list                                       */
/* ------------------------------------------------------------------ */

/**
 * Variables the detached daemon child is allowed to inherit, copied verbatim.
 *
 * The child used to be spawned with `{ ...process.env }`, which handed it every
 * variable the operator's shell happened to contain — including nine that
 * materially change security posture (see `UNRECOGNISED_SECURITY_ENV`). The
 * list below is the complete set of variables the daemon actually needs.
 *
 * Anything not listed here is dropped rather than inherited.
 */
export const DAEMON_ENV_ALLOW_LIST: readonly string[] = [
  // Process/runtime basics. The child is spawned with `process.execPath`, an
  // absolute path, so PATH is only needed for the Windows `taskkill` fallback
  // in `sw-agent clean`.
  'PATH',
  'HOME',
  'SystemRoot',
  'WINDIR',
  'COMSPEC',
  'PATHEXT',
  'TEMP',
  'TMP',
  // POSIX locale/timezone: affects parsing and log rendering only.
  'LANG',
  'LC_ALL',
  'TZ',
  // TLS trust material for corporate proxies / private CAs.
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  // Corporate forward proxy support (documented feature).
  'HTTP_PROXY',
  'HTTPS_PROXY',
  'NO_PROXY',
  'http_proxy',
  'https_proxy',
  'no_proxy',
  // Terminal capability detection for the CLI surfaces.
  'TERM',
  'TERM_PROGRAM',
  'WT_SESSION',
  'NO_COLOR',
  'FORCE_COLOR',
  'ConEmuANSI',
  'MSYSTEM',
  // Recognised SW_AGENT_* presentation and diagnostic toggles.
  'SW_AGENT_NO_COLOR',
  'SW_AGENT_ASCII',
  'SW_AGENT_UNICODE',
  'SW_AGENT_COLUMNS',
  'SW_AGENT_DEBUG',
  // Machine-local audit chain key. Provisioned by the operator on the host; it
  // never leaves the machine, and the daemon cannot verify or extend the audit
  // chain without it.
  'SW_AGENT_AUDIT_KEY',
  'SW_AGENT_AUDIT_KEY_PATH',
  // Database scope. This one NARROWS access rather than widening it: an agent
  // scoped to a subset must reach every database outside that subset never be
  // reachable. Dropping it would turn a deliberately scoped deployment into an
  // unscoped one, so it is allow-listed for the same reason the pool ceiling and
  // statement_timeout ceilings are refused: honouring the operator's scope is
  // the secure direction, and silently discarding it is the insecure one.
  'SW_AGENT_ALLOWED_DATABASES',
];

/**
 * Variables that look like configuration but are NOT allow-listed, and each
 * value that would change the security posture if honoured.
 *
 * These are recognised — so they are not silently ignored — but they are
 * refused rather than applied. `buildDaemonChildEnv` reports them so the parent
 * can warn, and `stripUnrecognisedSecurityEnv` removes them so an
 * already-running foreground process cannot be steered by an inherited value.
 */
export const UNRECOGNISED_SECURITY_ENV: Readonly<Record<string, string>> = {
  SW_AGENT_E2E: 'enables a test-only inbound admin HTTP listener in the daemon',
  PG_CONNECTOR_HOME: 'relocates the whole agent home, including the permission configuration',
  SW_AGENT_MAX_STREAM_ROWS: 'raises the streaming row ceiling',
  SW_AGENT_AUDIT_BUFFER: 'raises the audit queue depth above the durable write path',
  SW_PG_POOL_MAX: 'raises the PostgreSQL pool ceiling',
  SW_MAX_STATEMENT_TIMEOUT_MS: 'raises the statement_timeout ceiling',
  SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS: 'changes how long an unapproved write stays pending',
};

/** Variables the child env builder sets itself, regardless of the parent. */
const DAEMON_ENV_INJECTED: Readonly<Record<string, string>> = {
  SW_AGENT_DAEMON: '1',
};

export interface DaemonChildEnvOptions {
  /**
   * Absolute, already-resolved agent home directory. Passed through as
   * `SW_AGENT_HOME` so the child cannot be redirected to a different state
   * directory by re-reading `PG_CONNECTOR_HOME` from its own environment.
   */
  agentHome: string;
}

export interface DaemonChildEnvResult {
  env: Record<string, string>;
  /** Recognised-but-refused variables that were present and are now dropped. */
  refused: Array<{ name: string; effect: string }>;
}

/**
 * Build the environment for the detached daemon child.
 *
 * Only allow-listed variables are copied. `SW_AGENT_HOME` is pinned to the
 * home the parent already resolved, and `SW_AGENT_DAEMON=1` is set. Anything in
 * `UNRECOGNISED_SECURITY_ENV` that happened to be set is dropped and reported
 * instead of being inherited.
 */
export function buildDaemonChildEnv(
  source: NodeJS.ProcessEnv = process.env,
  opts: DaemonChildEnvOptions,
): DaemonChildEnvResult {
  const env: Record<string, string> = {};

  for (const name of DAEMON_ENV_ALLOW_LIST) {
    const value = source[name];
    if (typeof value === 'string' && value.length > 0) {
      env[name] = value;
    }
  }

  const refused: Array<{ name: string; effect: string }> = [];
  for (const [name, effect] of Object.entries(UNRECOGNISED_SECURITY_ENV)) {
    if (typeof source[name] === 'string' && source[name]!.length > 0) {
      refused.push({ name, effect });
    }
  }

  for (const [name, value] of Object.entries(DAEMON_ENV_INJECTED)) {
    env[name] = value;
  }
  env.SW_AGENT_HOME = opts.agentHome;

  return { env, refused };
}

/**
 * Delete every recognised-but-refused security variable from the live
 * process environment. Called once at daemon startup so that a foreground
 * `sw-agent start` cannot be steered by a value inherited from a `.service`
 * file, wrapper script, PM2 ecosystem file, CI job, or Dockerfile `ENV`.
 *
 * Returns the names that were removed so the caller can log them.
 */
export function stripUnrecognisedSecurityEnv(target: NodeJS.ProcessEnv = process.env): string[] {
  const removed: string[] = [];
  for (const name of Object.keys(UNRECOGNISED_SECURITY_ENV)) {
    if (target[name] !== undefined) {
      delete target[name];
      removed.push(name);
    }
  }
  return removed;
}

/* ------------------------------------------------------------------ */
/* Resolved-home assertion                                     */
/* ------------------------------------------------------------------ */

/** The one code this module raises. */
export const AGENT_HOME_MISMATCH_CODE = 'agent_home_mismatch';

/**
 * Raised when the home this process is about to use is not the home its
 * environment asked for.
 *
 * A daemon that silently runs somewhere other than where it was told is the
 * whole of a different `sw-agent.config.json`, a different
 * `default_permission`, a different `allowed_databases`, a different audit
 * directory and therefore a DIFFERENT AUDIT KEY, while the operator's
 * `sw-agent audit verify` reviews the chain the daemon is not writing.
 */
export class AgentHomeMismatchError extends Error {
  readonly code = AGENT_HOME_MISMATCH_CODE;

  constructor(message: string) {
    super(`${AGENT_HOME_MISMATCH_CODE}: ${message}`);
    this.name = 'AgentHomeMismatchError';
  }
}

export interface ResolvedAgentHomeReport {
  /** `SW_AGENT_HOME` exactly as supplied, or null when it was not set. */
  requested: string | null;
  /** The absolute directory the daemon will actually use. */
  resolved: string;
  /** True when `resolved` is the absolute form of `requested`. */
  matches: boolean;
  /** True when neither home variable was supplied. */
  defaulted: boolean;
  /**
   * True when `PG_CONNECTOR_HOME` is still set. It must never be: it is in
   * {@link UNRECOGNISED_SECURITY_ENV} and is deleted at startup, so any path
   * resolved from it before that point silently changes home underneath the
   * process. Seeing it here means the strip did not run before the paths were
   * resolved.
   */
  stale_home_var_present: boolean;
  /** Derived paths, so the journal line names what the home actually controls. */
  config: string;
  audit_dir: string;
  credential_key: string;
  pid_file: string;
  status_file: string;
  errors_log: string;
}

/**
 * Resolves the agent home and everything derived from it, without throwing.
 *
 * `getAgentHome()` has a side effect — it creates the directory and repairs its
 * mode — so it is called through the same accessor the rest of the daemon uses.
 * A failure there (a read-only filesystem under `ProtectSystem=strict`, a
 * permission problem) is reported as `null` rather than thrown, because the
 * startup log must not be the thing that kills a daemon that is about to fail
 * closed on its own.
 */
export function resolveAgentHomeReport(
  env: NodeJS.ProcessEnv = process.env,
): ResolvedAgentHomeReport | null {
  let resolved: string;
  try {
    resolved = getAgentHome();
  } catch {
    return null;
  }
  const requested = env.SW_AGENT_HOME ?? null;
  const defaulted = requested === null && !env.PG_CONNECTOR_HOME;
  return {
    requested,
    resolved: path.resolve(resolved),
    matches:
      requested === null
        ? true
        : path.resolve(resolved) === path.resolve(requested) && requested.trim().length > 0,
    defaulted,
    stale_home_var_present: typeof env.PG_CONNECTOR_HOME === 'string',
    config: safeDerived(getDbConfigPath),
    audit_dir: safeDerived(getAuditDirPath),
    credential_key: safeDerived(getCredentialKeyPath),
    pid_file: safeDerived(getPidFilePath),
    status_file: safeDerived(getStatusFilePath),
    errors_log: safeDerived(getErrorsPath),
  };
}

function safeDerived(fn: () => string): string {
  try {
    return fn();
  } catch {
    return '<unresolved>';
  }
}

/**
 * The startup lines. Printed on EVERY daemon start, not only when
 * `SW_AGENT_HOME` is set, because the failure this defends against is invisible
 * from the journal: a daemon writing a fresh, empty audit chain in
 * `~/.sw-agent` looks exactly like a healthy one.
 *
 * The absolute resolved path is the whole point. `journalctl -u schemaweaver`
 * is where an operator checks that the 24/7 service is running against the home
 * they configured, and before this existed the only evidence available was a
 * unit file asserting a pin the daemon then ignored.
 */
export function formatAgentHomeReport(report: ResolvedAgentHomeReport): string[] {
  const lines = [
    `[security] Resolved agent home: ${report.resolved}` +
      (report.requested ? ` (from SW_AGENT_HOME=${report.requested})` : ' (default)'),
    `[security]   config=${report.config}`,
    `[security]   audit=${report.audit_dir}`,
    `[security]   credential key=${report.credential_key}` +
      ` (derived from HOME, not from the agent home)`,
  ];
  if (!report.matches) {
    lines.push(
      `[security] MISMATCH: SW_AGENT_HOME=${report.requested} did not resolve to the agent ` +
        `home in effect (${report.resolved}). Refusing to serve: the config, the database scope ` +
        `and the audit chain the operator reviews would not be the ones in use.`,
    );
  }
  if (report.stale_home_var_present) {
    lines.push(
      `[security] WARNING: PG_CONNECTOR_HOME is still set in this process's environment. It is a ` +
        'refused variable that is DELETED at startup, so any path already resolved from it now ' +
        'points somewhere this process will not use.',
    );
  }
  return lines;
}

/**
 * Asserts the resolved agent home matches what the environment asked for, logs
 * it, and returns the report.
 *
 * Called once per daemon start, after
 * {@link stripUnrecognisedSecurityEnv}. Throws
 * {@link AgentHomeMismatchError} rather than warning: a daemon running against a
 * home nobody configured would apply a different `default_permission`, a
 * different `allowed_databases` and a different audit key, which is worse than
 * not running.
 *
 * A `SW_AGENT_HOME` that is not absolute is refused too. A relative value
 * resolves against whatever working directory the supervisor happened to use,
 * which is exactly how a systemd unit ends up pointing somewhere nobody chose.
 */
export function assertAndLogResolvedAgentHome(
  env: NodeJS.ProcessEnv = process.env,
  log: (line: string) => void = (line) => console.log(line),
): ResolvedAgentHomeReport {
  const requested = env.SW_AGENT_HOME;
  if (typeof requested === 'string' && !path.isAbsolute(requested)) {
    throw new AgentHomeMismatchError(
      `SW_AGENT_HOME=${requested} is not an absolute path. It would resolve against whatever ` +
        'working directory the supervisor chose. Use an absolute path.',
    );
  }

  const report = resolveAgentHomeReport(env);
  if (!report) {
    log(
      '[security] Could not resolve the agent home (the directory could not be created or ' +
        'inspected). The daemon will fail closed rather than guess a home.',
    );
    throw new AgentHomeMismatchError('the agent home could not be resolved');
  }

  for (const line of formatAgentHomeReport(report)) log(line);
  if (!report.matches) {
    throw new AgentHomeMismatchError(
      `SW_AGENT_HOME=${report.requested} does not resolve to the agent home in effect ` +
        `(${report.resolved})`,
    );
  }
  return report;
}

export type AgentRuntimeKind = 'stopped' | 'starting' | 'running' | 'unresponsive';

export interface AgentRuntimeState {
  kind: AgentRuntimeKind;
  running: boolean;
  healthy: boolean;
  pid: number | null;
  version: string | null;
  started_at: string | null;
  uptime_sec: number | null;
  last_heartbeat: string | null;
  status: DaemonStatus | null;
  pidFile: PidFile | null;
  status_mismatch: boolean;
  /** Where local error telemetry is written, whether or not the daemon runs. */
  errors_log: DaemonStatus['errors_log'];
}

export function resolveAgentRuntimeState(now = new Date()): AgentRuntimeState {
  const pidInfo = readJsonFile<PidFile>(getPidFilePath());
  const statusInfo = readJsonFile<DaemonStatus>(getStatusFilePath());

  let kind: AgentRuntimeKind = 'stopped';
  let running = false;
  let healthy = false;
  let pid: number | null = null;
  let version: string | null = null;
  let startedAt: string | null = null;
  let uptimeSec: number | null = null;
  let lastHeartbeat: string | null = null;
  let statusMismatch = false;

  if (pidInfo) {
    pid = pidInfo.pid;
    version = pidInfo.version;
    startedAt = pidInfo.started_at;
    running = isProcessAlive(pidInfo.pid);

    if (startedAt) {
      const startedMs = new Date(startedAt).getTime();
      if (Number.isFinite(startedMs)) {
        uptimeSec = Math.max(0, Math.floor((now.getTime() - startedMs) / 1000));
      }
    }
  }

  if (!running) {
    kind = 'stopped';
  } else if (!statusInfo) {
    kind = 'starting';
  } else if (statusInfo.pid !== pid) {
    statusMismatch = true;
    kind = 'unresponsive';
  } else {
    lastHeartbeat = statusInfo.last_heartbeat;
    const stale = isStatusStale(statusInfo, now);
    kind = stale ? 'unresponsive' : 'running';
    healthy = !stale;
  }

  return {
    kind,
    running,
    healthy,
    pid,
    version,
    started_at: startedAt,
    uptime_sec: uptimeSec,
    last_heartbeat: lastHeartbeat,
    status: statusInfo,
    pidFile: pidInfo,
    status_mismatch: statusMismatch,
    errors_log: statusInfo?.errors_log ?? { path: getErrorsPath(), size_bytes: 0 },
  };
}

function readJsonFile<T>(file: string): T | null {
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

export function formatDuration(sec: number): string {
  const hours = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const secs = Math.floor(sec % 60);
  if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export function formatTimestamp(ts: string): string {
  return ts.replace('T', ' ').slice(0, 19);
}
