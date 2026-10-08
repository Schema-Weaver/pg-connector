import * as fs from 'fs';
import { MachineConfig } from '../../config/machine-config';
import { DatabasesConfig, loadDatabasesConfig } from '../../config/db-config';
import { getDbConfigPath, getDaemonLogPath, AGENT_HOME_ENV_VARS } from '../../config/paths';
import {
  ConfigInvalidError,
  isSecureCloudUrl,
  isValidIdentifier,
  redactSecrets,
} from '../../config/schema';
import { writePidFile, deletePidFile } from './pid-file';
import { writeStatusFile, DaemonStatus } from './status-file';
import { createShutdownCoordinator } from './shutdown';
import { installSignalHandlers } from './signal-handlers';
import { stripUnrecognisedSecurityEnv, UNRECOGNISED_SECURITY_ENV } from './state';
import { installGlobalHandlers, trackError, getErrorLogStats } from './error-tracker';
import {
  initOperationLogger,
  shutdownOperationLogger as _shutdownOperationLogger,
} from '../ops/operation-logger';
import { PoolManager, MAX_STATEMENT_TIMEOUT_MS } from '../../execution/pool';
import { QueryRunner } from '../../execution/query-runner';
import { MigrationRunner } from '../../execution/migration-runner';
import { Canceller } from '../../execution/canceller';
import { Introspector } from '../../execution/introspection';
import { Dispatcher } from '../../execution/dispatcher';
import type { DatabaseLookupResult, DatabaseRefusalCode } from '../../execution/database-lookup';
import { DEFAULTS } from '../../protocol/constants';
import { ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT, type Role } from '../../protocol/envelope';
import { PermissionChecker } from '../../permissions/checker';
import { PlanRegistry } from '../../permissions/plan-registry';
import { AutoUpgradeChecker } from '../../permissions/auto-upgrade';
import { ManualApprovalHandler } from '../../permissions/manual-approval';
import { AuditSink } from '../../audit/sink';
import type { AuditSinkHealth } from '../../audit/types';
import { LocalAuditWriter } from '../../audit/local-writer';
import { CloudAuditWriter } from '../../audit/cloud-writer';
import { AgentSession } from '../../channels/agent-session';
import { DbEntry } from '../../config/db-config';
import { initSqlParser } from '../../execution/sql-parser';
import { VERSION } from '../../index';

export interface RuntimeOptions {
  machineConfig: MachineConfig;
  databasesConfig: DatabasesConfig;
  relayUrl: string;
  auditDir: string;
  statusFile: string;
  pidFile: string;
  foreground: boolean;
  autoExitMs?: number;
}

export class RuntimeStats {
  queries_served = 0;
  streams_served = 0;
  migrations_run = 0;
  cancellations = 0;
  permission_denies = 0;
  audit_buffer_overflows = 0;
  /**
   * Appends this process saw rejected. `audit_events_written` is deliberately
   * absent: it is derived from the sink, never counted here.
   */
  audit_events_failed = 0;
}

/**
 * The audit half of the daemon status block.
 *
 * `DaemonStatus` does not yet declare `audit_events_failed` or an `audit`
 * block, so they are produced here and the owner of `status-file.ts` can spread
 * this object straight into `DaemonStatus['stats']` once the type declares them.
 */
export interface DaemonAuditStats {
  /** Appends the sink confirmed. Never includes a record it rejected. */
  audit_events_written: number;
  /** Records the sink could not persist. Audit loss, counted rather than hidden. */
  audit_events_failed: number;
  /** Records admitted above the audit queue high-water mark. */
  audit_buffer_overflows: number;
  /**
   * Records the bounded queue discarded outright under pressure.
   *
   * Distinct from the two counters above, and the reason it is promoted out of
   * the `audit` block: an overflow is *admitted* and eventually written, while a
   * drop never reaches the file at all. It is fire-and-forget telemetry only —
   * allow/deny decisions are written straight through and never queued, so a
   * non-zero value means silent history loss, not a lost authorization record.
   * Surfaced next to `audit_buffer_overflows` so an operator reading `stats`
   * sees that the trail is lossy rather than having to know that the number
   * exists somewhere else in the status file.
   */
  audit_dropped: number;
  /**
   * Full sink health, verbatim from {@link AuditSink.getHealth}:
   * `dir`, `active_path`, `ready`, `writable`, `dir_mode`, `file_mode`,
   * `retained_from_seq`, `last_write_at`, `last_error`, `last_error_at`,
   * `error_count`, `events_written`, `events_failed`, `bytes_written`,
   * `rotations`, `chain_id`, `seq`, `chain_error`, `queue_depth`,
   * `overflow_admitted`, `dropped`.
   */
  audit: AuditSinkHealth;
}

/**
 * Reconcile the audit counters from the sink's own health.
 *
 * `events_written` is the sink's count of appends that resolved, so a rejected
 * record can never inflate it. `events_failed` is the greater of the rejection
 * this process counted on the awaited path and the sink's queue-level failure
 * count, which also covers the fire-and-forget `log()` path. `dropped` is the
 * sink's own discard count, carried through unchanged: it has no local counter to
 * reconcile against, because a dropped record never reaches this process at all.
 */
export function buildDaemonAuditStats(
  stats: RuntimeStats,
  health: AuditSinkHealth,
): DaemonAuditStats {
  return {
    audit_events_written: health.events_written,
    audit_events_failed: Math.max(stats.audit_events_failed, health.events_failed),
    audit_buffer_overflows: stats.audit_buffer_overflows,
    audit_dropped: health.dropped,
    audit: health,
  };
}

/* ------------------------------------------------------------------ */
/* Audit shutdown (M-05)                                                */
/* ------------------------------------------------------------------ */

/** What a shutdown needs from the audit stack, and nothing more. */
export interface AuditShutdownTarget {
  /** Drains the sink's queue and fsyncs everything written but not committed. */
  flush(): Promise<void>;
  /** Flushes and releases the file handle. Always called *after* `flush`. */
  close(): Promise<void>;
}

/**
 * Builds the daemon's audit shutdown step: flush, then close — in that order,
 * exactly once, however many times it is called.
 *
 * Close-after-flush matters: `close()` on its own would be enough for the fd,
 * but the point of flushing first is that records already counted as written by
 * the sink reach the disk, and `LocalAuditWriter.flush()` is what advances the
 * chain head to match. Closing *instead of* flushing would drop both.
 *
 * Idempotent because shutdown can arrive twice (a signal and an explicit
 * `stop`, or a handler registered on two coordinators). Concurrent callers await
 * the *same* promise rather than starting a second flush/close pair, so a signal
 * that lands mid-shutdown cannot interleave with it. A failed attempt is not
 * remembered as done: the memo is cleared so a later stop retries instead of
 * reporting a shutdown that never completed.
 */
export function createAuditShutdown(target: AuditShutdownTarget): () => Promise<void> {
  let pending: Promise<void> | null = null;
  return () => {
    if (pending === null) {
      pending = (async () => {
        await target.flush();
        await target.close();
      })().catch((err: unknown) => {
        pending = null;
        throw err;
      });
    }
    return pending;
  };
}

/* ------------------------------------------------------------------ */
/* Relay URL override (M-08)                                           */
/* ------------------------------------------------------------------ */

export interface RelayResolution {
  /** The URL the agent will actually connect to. */
  url: string;
  /** True when the URL came from `--relay` rather than the persisted config. */
  isOverride: boolean;
  /** Host of the persisted `cloud_url`, or null when it cannot be parsed. */
  configuredHost: string | null;
  /** Host of the requested relay URL, or null when it cannot be parsed. */
  relayHost: string | null;
  /** True when the override names a different host than the persisted config. */
  hostChanged: boolean;
}

/**
 * Validate a relay URL with exactly the rule `cloud_url` must already satisfy
 * in `validateMachineConfig`: a well-formed `wss://` URL with an explicit
 * authority and no userinfo. `ws://`, `http://`, `WSS://`, `wss:/host` and
 * unparseable input are all refused.
 *
 * Throws {@link ConfigInvalidError} rather than falling back to the configured
 * URL: silently ignoring the flag would leave the operator believing the agent
 * is talking to the relay they named.
 */
export function assertSecureRelayUrl(raw: string): string {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new ConfigInvalidError(
      'Relay URL is empty. Expected a wss:// URL with an explicit authority.',
    );
  }
  if (!isSecureCloudUrl(raw)) {
    throw new ConfigInvalidError(
      'Refusing relay URL: it must be a wss:// URL with an explicit authority. ' +
        'ws:// and http:// are refused because the agent token is a permanent ' +
        'bearer credential and would travel in cleartext.',
    );
  }
  return raw;
}

function urlHost(raw: string): string | null {
  try {
    return new URL(raw).host || null;
  } catch {
    return null;
  }
}

export function relayHostMismatchWarning(configuredHost: string, relayHost: string): string {
  return (
    `[security] WARNING: --relay points at a DIFFERENT host than the configured cloud_url.\n` +
    `           configured cloud_url host: ${configuredHost}\n` +
    `           relay host:                 ${relayHost}\n` +
    `           The agent's permanent token will be presented to ${relayHost}. ` +
    `Anyone who controls that host receives this agent's credentials. ` +
    `Drop --relay to use the configured host.`
  );
}

/**
 * Decide which URL the agent uses, and whether that silently redirects the
 * token to a host the operator never configured.
 */
export function resolveRelayOverride(
  relayUrl: string | undefined,
  persistedCloudUrl: string,
): RelayResolution {
  const configuredHost = urlHost(persistedCloudUrl);
  if (!relayUrl) {
    return {
      url: persistedCloudUrl,
      isOverride: false,
      configuredHost,
      relayHost: null,
      hostChanged: false,
    };
  }
  const url = assertSecureRelayUrl(relayUrl);
  const relayHost = urlHost(url);
  return {
    url,
    isOverride: true,
    configuredHost,
    relayHost,
    hostChanged: relayHost !== null && configuredHost !== null && relayHost !== configuredHost,
  };
}

/**
 * Render a URL for a terminal or a log: scheme and host only. Userinfo, path
 * tokens, query and fragment are masked, so echoing a URL can never disclose a
 * credential.
 */
export function redactUrlForDisplay(raw: string): string {
  if (typeof raw !== 'string' || raw.length === 0) return '(unset)';
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return '(unparseable URL)';
  }
  const hasHiddenParts =
    url.username.length > 0 ||
    url.password.length > 0 ||
    (url.pathname.length > 0 && url.pathname !== '/') ||
    url.search.length > 0 ||
    url.hash.length > 0;
  const base = `${url.protocol}//${url.host}`;
  return hasHiddenParts ? `${base}/<redacted>` : base;
}

/* ------------------------------------------------------------------ */
/* Security-relevant environment resolution (M-09, L-03)              */
/* ------------------------------------------------------------------ */

/** Connections per database pool when nothing valid is configured. */
export const DEFAULT_POOL_MAX = 15;
export const MIN_POOL_MAX = 1;
export const MAX_POOL_MAX = 200;

/**
 * Strict decimal integer parse. `Number()` would accept `0x10`, `1e3` and
 * whitespace-only input, so every override is parsed this way instead.
 */
function parseStrictInteger(raw: string): number | null {
  const trimmed = raw.trim();
  if (!/^[+-]?\d+$/.test(trimmed)) return null;
  const parsed = Number(trimmed);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

/**
 * Resolve the per-pool connection ceiling.
 *
 * Anything that is not an integer inside `[MIN_POOL_MAX, MAX_POOL_MAX]` — a
 * non-numeric value, zero, a negative number, or an absurd ceiling that would
 * be refused by PostgreSQL's own `max_connections` — falls back to the
 * default. Previously `SW_PG_POOL_MAX` was passed straight through
 * `parseInt`, so `abc` produced `NaN` and `999999` asked the database for a
 * connection storm.
 */
export function resolvePoolMax(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SW_PG_POOL_MAX;
  if (typeof raw !== 'string' || raw.trim().length === 0) return DEFAULT_POOL_MAX;
  const parsed = parseStrictInteger(raw);
  if (parsed === null || parsed < MIN_POOL_MAX || parsed > MAX_POOL_MAX) return DEFAULT_POOL_MAX;
  return parsed;
}

/** Shortest approval window that is still an approval rather than a formality. */
export const MIN_APPROVAL_TIMEOUT_MS = 5_000;
export const MAX_APPROVAL_TIMEOUT_MS = 3_600_000;

/**
 * Resolve the manual-approval window.
 *
 * `0` and negative values are never honoured: they would expire every pending
 * approval the instant it was created, turning the approval gate into a no-op.
 * Garbage falls back to `DEFAULTS.APPROVAL_TIMEOUT_MS`, and an in-range value
 * is clamped rather than rejected so a deliberate typo cannot silently widen
 * the window.
 */
export function resolveApprovalTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS;
  const fallback = DEFAULTS.APPROVAL_TIMEOUT_MS;
  if (typeof raw !== 'string' || raw.trim().length === 0) return fallback;
  const parsed = parseStrictInteger(raw);
  if (parsed === null || parsed <= 0) return fallback;
  if (parsed < MIN_APPROVAL_TIMEOUT_MS) return MIN_APPROVAL_TIMEOUT_MS;
  if (parsed > MAX_APPROVAL_TIMEOUT_MS) return MAX_APPROVAL_TIMEOUT_MS;
  return parsed;
}

/**
 * Mirror `PoolManager.maxStatementTimeoutMs` for the startup posture log: the
 * environment may lower the ceiling but never raise it past the compiled-in
 * hard cap.
 */
export function resolveStatementTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SW_MAX_STATEMENT_TIMEOUT_MS;
  const fallback = Math.min(DEFAULTS.QUERY_TIMEOUT_MS, MAX_STATEMENT_TIMEOUT_MS);
  if (typeof raw !== 'string' || raw.trim().length === 0) return fallback;
  const parsed = parseStrictInteger(raw);
  if (parsed === null || parsed <= 0) return fallback;
  return Math.min(parsed, MAX_STATEMENT_TIMEOUT_MS);
}

/**
 * Mirror the query runner's streaming row ceiling for the posture log. Same
 * rule as its private `readBoundedEnvInt`, including its `parseInt` semantics:
 * NaN, zero and negatives fall back, absurd values are clamped.
 */
export function resolveMaxStreamRows(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SW_AGENT_MAX_STREAM_ROWS;
  if (typeof raw !== 'string' || raw.trim().length === 0) return DEFAULTS.MAX_STREAM_ROWS;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return DEFAULTS.MAX_STREAM_ROWS;
  return Math.min(parsed, 100_000_000);
}

export interface E2EAdminGate {
  requested: boolean;
  allowed: boolean;
  reason: string;
}

/**
 * Gate for the historical `SW_AGENT_E2E` escape hatch that used to start an
 * unauthenticated loopback admin server with `/admin/shutdown`.
 *
 * There is no admin server in this build, so `allowed: true` still starts
 * nothing. The gate exists so the conditions that would have to hold before
 * such a control plane could be reintroduced are stated once, in code, rather
 * than in a comment: never in production, never in a daemonised process, and
 * only with an explicit second opt-in.
 */
export function resolveE2EAdminGate(env: NodeJS.ProcessEnv = process.env): E2EAdminGate {
  const requested = env.SW_AGENT_E2E === '1';
  if (!requested) {
    return { requested: false, allowed: false, reason: 'not requested' };
  }
  const blockers: string[] = [];
  if (env.NODE_ENV === 'production') blockers.push('NODE_ENV=production');
  if (env.SW_AGENT_DAEMON === '1') blockers.push('the process is daemonised');
  if (env.SW_AGENT_DEV_ADMIN !== '1') blockers.push('SW_AGENT_DEV_ADMIN=1 not set');
  return {
    requested: true,
    allowed: blockers.length === 0,
    reason:
      blockers.length === 0
        ? 'explicit development opt-in present, and no admin control plane exists to start'
        : `refused (${blockers.join('; ')})`,
  };
}

/**
 * The audit fields the activity counters are derived from. Declared narrowly
 * rather than reusing `AuditEvent`, so the counters stay readable and do not
 * depend on the full record shape.
 */
interface CountedAuditEvent {
  action?: string;
  decision?: string;
  outcome?: string;
  denial_reason?: string;
}

export interface SecurityPostureEntry {
  name: string;
  resolved: string;
  detail: string;
}

/**
 * The resolved value of every input that changes this process's security
 * posture, so the effective configuration is observable in the log rather than
 * implicit in whatever environment the process happened to inherit.
 *
 * `env` is the environment the values are actually resolved from — the live one,
 * after the refused variables have been stripped, so a reported value is the
 * value in effect. `inherited` is the pre-strip snapshot, used only to say
 * whether a variable was set at all; pass it so the report can distinguish "not
 * set" from "set, and ignored".
 */
export function resolveSecurityPosture(
  env: NodeJS.ProcessEnv = process.env,
  inherited: NodeJS.ProcessEnv = env,
): SecurityPostureEntry[] {
  const accepted = (name: string, parse: (value: string) => number | null): string => {
    const raw = inherited[name];
    if (typeof raw !== 'string' || raw.trim().length === 0) return 'from default';
    return parse(raw) === null ? 'rejected, using default' : 'from environment';
  };
  const e2e = resolveE2EAdminGate(inherited);
  const scope = parseScopeEnv(env[ALLOWED_DATABASES_ENV]);
  const agentHome = inherited.PG_CONNECTOR_HOME || inherited.SW_AGENT_HOME;
  return [
    {
      name: 'SW_PG_POOL_MAX',
      resolved: `${resolvePoolMax(env)} connections per database pool`,
      detail: `${accepted('SW_PG_POOL_MAX', (value) => {
        const parsed = parseStrictInteger(value);
        return parsed !== null && parsed >= MIN_POOL_MAX && parsed <= MAX_POOL_MAX ? parsed : null;
      })}; valid range ${MIN_POOL_MAX}-${MAX_POOL_MAX}`,
    },
    {
      name: 'SW_MAX_STATEMENT_TIMEOUT_MS',
      resolved: `${resolveStatementTimeoutMs(env)} ms`,
      detail: `${accepted('SW_MAX_STATEMENT_TIMEOUT_MS', (value) => {
        const parsed = parseStrictInteger(value);
        return parsed !== null && parsed > 0 ? parsed : null;
      })}; hard cap ${MAX_STATEMENT_TIMEOUT_MS} ms`,
    },
    {
      name: 'SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS',
      resolved: `${resolveApprovalTimeoutMs(env)} ms`,
      detail: `${accepted('SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS', (value) => {
        const parsed = parseStrictInteger(value);
        return parsed !== null &&
          parsed >= MIN_APPROVAL_TIMEOUT_MS &&
          parsed <= MAX_APPROVAL_TIMEOUT_MS
          ? parsed
          : null;
      })}; clamped to ${MIN_APPROVAL_TIMEOUT_MS}-${MAX_APPROVAL_TIMEOUT_MS} ms`,
    },
    {
      name: 'SW_AGENT_MAX_STREAM_ROWS',
      resolved: `${resolveMaxStreamRows(env)} rows`,
      detail: accepted('SW_AGENT_MAX_STREAM_ROWS', (value) => {
        const parsed = Number.parseInt(value.trim(), 10);
        return Number.isFinite(parsed) && parsed >= 1 ? parsed : null;
      }),
    },
    {
      name: 'SW_AGENT_AUDIT_BUFFER',
      resolved: (() => {
        const buf = env.SW_AGENT_AUDIT_BUFFER;
        return typeof buf === 'string' && buf.trim().length > 0
          ? `${buf} (as provided)`
          : 'audit sink default';
      })(),
      detail: (() => {
        const buf = inherited.SW_AGENT_AUDIT_BUFFER;
        if (typeof buf !== 'string' || buf.trim().length === 0) return 'from default';
        return env.SW_AGENT_AUDIT_BUFFER === undefined
          ? 'set but refused; audit queue uses its default depth'
          : 'from environment';
      })(),
    },
    {
      name: 'SW_AGENT_E2E',
      resolved: e2e.requested ? 'requested' : 'not set',
      detail: `${e2e.reason}; this build starts no inbound admin listener`,
    },
    {
      name: ALLOWED_DATABASES_ENV,
      resolved: scope
        ? `${scope.length} allow-list rule(s)`
        : 'unscoped (all configured databases reachable)',
      detail:
        typeof env[ALLOWED_DATABASES_ENV] === 'string' &&
        env[ALLOWED_DATABASES_ENV]!.trim().length > 0
          ? 'from environment'
          : `from default (also settable as ${ALLOWED_DATABASES_CONFIG_KEY} in sw-agent.config.json)`,
    },
    {
      // Named for the variable an operator would actually set. This line reports
      // where the agent token and the audit chain live, so a wrong variable name
      // here sends a relocation attempt nowhere while the agent keeps writing
      // secrets to the default path.
      name: AGENT_HOME_ENV_VARS.join(' / '),
      resolved: agentHome ?? 'default (~/.sw-agent)',
      detail:
        'holds sw-agent.config.json, the agent token and the audit chain; ' +
        'set either variable to relocate all of it, or leave unset for ' +
        '~/.sw-agent. Not AGENT_HOME — nothing reads that one. ' +
        'PG_CONNECTOR_HOME is refused at runtime, but paths already resolved ' +
        'from it before startup still point there',
    },
    {
      name: 'SW_AGENT_DEBUG',
      resolved: env.SW_AGENT_DEBUG === '1' ? 'on' : 'off',
      detail: 'verbose logging; never enable in production',
    },
    {
      name: 'NODE_ENV',
      resolved: env.NODE_ENV ?? 'development',
      detail: 'production forbids every development-only control plane',
    },
  ];
}

/**
 * Render the posture block. `secrets` are replaced with `***` in every line, so
 * an agent token or an ingest URL can never reach the log through this path.
 */
export function formatSecurityPosture(
  entries: SecurityPostureEntry[],
  secrets: Array<string | undefined> = [],
): string[] {
  const width = entries.reduce((max, entry) => Math.max(max, entry.name.length), 0);
  const lines = [
    '[security] Effective configuration (resolved values; secrets redacted):',
    ...entries.map(
      (entry) => `[security]   ${entry.name.padEnd(width)} = ${entry.resolved}  — ${entry.detail}`,
    ),
  ];
  return lines.map((line) => redactSecrets(line, ...secrets));
}

/* ------------------------------------------------------------------ */
/* Per-token database scope (M-12)                                     */
/* ------------------------------------------------------------------ */

/**
 * One permitted `(project_name, db_alias)` pairing. A rule with only
 * `project_name` permits that project under any alias; a rule with only
 * `db_alias` permits that alias under any project.
 */
export interface DatabaseScopeRule {
  project_name?: string;
  db_alias?: string;
}

/** Environment channel for the allow-list, for installs that cannot edit config. */
export const ALLOWED_DATABASES_ENV = 'SW_AGENT_ALLOWED_DATABASES';

/** Config key read for the allow-list; the schema still needs to declare it. */
export const ALLOWED_DATABASES_CONFIG_KEY = 'allowed_databases';

function isScopeName(value: unknown): value is string {
  return typeof value === 'string' && isValidIdentifier(value, 64);
}

/**
 * Parse a `project`, `project:alias` or `:alias` token.
 */
function parseScopeToken(token: string): DatabaseScopeRule {
  const raw = token.trim();
  const separator = raw.indexOf(':');
  const project = separator === -1 ? raw : raw.slice(0, separator);
  if (separator === -1) {
    if (!isScopeName(project)) {
      throw new ConfigInvalidError(
        `Invalid ${ALLOWED_DATABASES_ENV} entry '${raw}': names may only contain letters, numbers, hyphens and underscores.`,
      );
    }
    return { project_name: project };
  }
  const alias = raw.slice(separator + 1);
  if (raw.indexOf(':', separator + 1) !== -1) {
    throw new ConfigInvalidError(
      `Invalid ${ALLOWED_DATABASES_ENV} entry '${raw}': expected 'project', 'project:db_alias' or ':db_alias'.`,
    );
  }
  if (project.length > 0 && !isScopeName(project)) {
    throw new ConfigInvalidError(
      `Invalid ${ALLOWED_DATABASES_ENV} entry '${raw}': project names may only contain letters, numbers, hyphens and underscores.`,
    );
  }
  if (alias.length === 0 || !isScopeName(alias)) {
    throw new ConfigInvalidError(
      `Invalid ${ALLOWED_DATABASES_ENV} entry '${raw}': the db_alias part is required when a ':' is present and must be a valid alias.`,
    );
  }
  return project.length > 0 ? { project_name: project, db_alias: alias } : { db_alias: alias };
}

/**
 * Validate an allow-list declaration. Returns null when nothing is configured
 * (the backwards-compatible unscoped case) and throws when something is
 * configured but malformed — a typo must not widen the scope it was meant to
 * narrow.
 */
export function parseScopeRules(raw: unknown): DatabaseScopeRule[] | null {
  if (raw === undefined || raw === null) return null;
  const items = Array.isArray(raw) ? raw : [raw];
  const rules: DatabaseScopeRule[] = [];
  for (const item of items) {
    if (typeof item === 'string') {
      rules.push(parseScopeToken(item));
      continue;
    }
    if (typeof item !== 'object' || item === null) {
      throw new ConfigInvalidError(
        `Invalid ${ALLOWED_DATABASES_CONFIG_KEY} entry: expected an object with project_name and/or db_alias.`,
      );
    }
    const record = item as Record<string, unknown>;
    const project = record.project_name;
    const alias = record.db_alias;
    if (project !== undefined && !isScopeName(project)) {
      throw new ConfigInvalidError(
        `Invalid ${ALLOWED_DATABASES_CONFIG_KEY} project_name: must be 1-64 characters of letters, numbers, hyphens and underscores.`,
      );
    }
    if (alias !== undefined && !isScopeName(alias)) {
      throw new ConfigInvalidError(
        `Invalid ${ALLOWED_DATABASES_CONFIG_KEY} db_alias: must be 1-64 characters of letters, numbers, hyphens and underscores.`,
      );
    }
    if (project === undefined && alias === undefined) {
      throw new ConfigInvalidError(
        `Invalid ${ALLOWED_DATABASES_CONFIG_KEY} entry: set project_name and/or db_alias; an empty rule would permit everything.`,
      );
    }
    const rule: DatabaseScopeRule = {};
    if (project !== undefined) rule.project_name = project;
    if (alias !== undefined) rule.db_alias = alias;
    rules.push(rule);
  }
  return rules.length > 0 ? rules : null;
}

/** Parse the comma-separated environment form of the allow-list. */
export function parseScopeEnv(raw: string | undefined): DatabaseScopeRule[] | null {
  if (typeof raw !== 'string' || raw.trim().length === 0) return null;
  const tokens = raw
    .split(',')
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  return tokens.length > 0 ? parseScopeRules(tokens) : null;
}

/**
 * Effective allow-list, resolved from both declaration channels.
 *
 * The environment can only **NARROW**. the two were unioned, so anybody
 * who could set `SW_AGENT_ALLOWED_DATABASES` in the daemon's environment could
 * add a database the operator had deliberately excluded — an environment
 * variable is a weaker channel than a config file and must not be the stronger
 * one. When both channels declare a scope, the result is their intersection; a
 * rule survives only if some config rule and some env rule can both match the
 * same entry. An empty intersection is a scope that permits nothing.
 *
 * Null means nothing was declared anywhere. That is no longer "every database is
 * permitted": see {@link resolveDatabaseScopeDecision}.
 */
export function resolveDatabaseScope(
  machineConfig: MachineConfig,
  env: NodeJS.ProcessEnv = process.env,
): DatabaseScopeRule[] | null {
  const fromConfig = parseScopeRules(
    (machineConfig as unknown as Record<string, unknown>)[ALLOWED_DATABASES_CONFIG_KEY],
  );
  const fromEnv = parseScopeEnv(env[ALLOWED_DATABASES_ENV]);
  if (!fromConfig) return fromEnv;
  if (!fromEnv) return fromConfig;
  return intersectScopeRules(fromConfig, fromEnv);
}

/**
 * Narrow every rule set to what BOTH permit.
 *
 * Rules carry at most a `project_name` and a `db_alias`, each optional, so the
 * intersection of two rules is either empty (they contradict each other) or a
 * single rule carrying every field they agree on. Duplicates are collapsed: an
 * entry must not be able to widen itself by being named twice.
 */
function intersectScopeRules(
  config: DatabaseScopeRule[],
  env: DatabaseScopeRule[],
): DatabaseScopeRule[] {
  const out: DatabaseScopeRule[] = [];
  for (const c of config) {
    for (const e of env) {
      const merged: DatabaseScopeRule = {};
      if (c.project_name !== undefined && c.project_name === e.project_name) {
        merged.project_name = c.project_name;
      }
      if (c.db_alias !== undefined && c.db_alias === e.db_alias) {
        merged.db_alias = c.db_alias;
      }
      if (c.project_name !== undefined && e.project_name !== undefined && merged.project_name === undefined) {
        continue; // different projects: no entry satisfies both
      }
      if (c.db_alias !== undefined && e.db_alias !== undefined && merged.db_alias === undefined) {
        continue; // different aliases: no entry satisfies both
      }
      if (merged.project_name === undefined && merged.db_alias === undefined) continue;
      if (!out.some((r) => r.project_name === merged.project_name && r.db_alias === merged.db_alias)) {
        out.push(merged);
      }
    }
  }
  return out.length > 0 ? out : [];
}

/**
 * Config key that restores the pre-remediation permissive default.
 *
 * RISK: with no allow-list and this key set to `true`, ONE agent token reaches
 * EVERY configured database on the host — typically dev, staging and production —
 * and any authenticated principal on the relay can name any of them. It exists
 * only so an existing deployment can keep working across this upgrade with a
 * deliberate, visible choice; the default is fail-closed.
 */
export const ALLOW_UNSCOPED_DATABASES_CONFIG_KEY = 'allow_unscoped_databases';

/** Machine-config path for the same escape hatch. */
export const ALLOW_UNSCOPED_DATABASES_CONFIG_PATH = `security.${ALLOW_UNSCOPED_DATABASES_CONFIG_KEY}`;

export interface DatabaseScopeDecision {
  /** Effective allow-list, or null when nothing was declared. */
  rules: DatabaseScopeRule[] | null;
  /** True when the environment channel narrowed (or contradicted) the config. */
  env_narrowed: boolean;
  /**
   * Whether the pre-remediation default is deliberately restored. Only ever true
   * for the literal boolean `true` under `security.allow_unscoped_databases` —
   * a string, a number or `1` does not restore it, so a typo cannot silently
   * re-open every database.
   */
  allow_unscoped: boolean;
  /** True when at least one channel declared an allow-list. */
  scoped: boolean;
  /**
   * True when this installation will serve `ping` only, because no allow-list was
   * declared and the permissive default was not explicitly restored.
   */
  fail_closed: boolean;
}

/**
 * The effective database scope, and whether this installation fails closed.
 *
 * . The default was "no allow-list means every configured database", so an
 * install that had never been configured — the default install — let a session
 * authenticated for one project read any other project on the host, including
 * production. The default is now the opposite: nothing declared means nothing is
 * reachable except `ping`, and the refusal is audited.
 *
 * Restoring the old behaviour requires the explicit
 * `security.allow_unscoped_databases: true`.
 */
export function resolveDatabaseScopeDecision(
  machineConfig: MachineConfig,
  env: NodeJS.ProcessEnv = process.env,
): DatabaseScopeDecision {
  const fromConfig = parseScopeRules(
    (machineConfig as unknown as Record<string, unknown>)[ALLOWED_DATABASES_CONFIG_KEY],
  );
  const fromEnv = parseScopeEnv(env[ALLOWED_DATABASES_ENV]);
  const allowUnscoped = readAllowUnscoped(machineConfig);

  let rules: DatabaseScopeRule[] | null;
  if (!fromConfig) {
    rules = fromEnv;
  } else if (!fromEnv) {
    rules = fromConfig;
  } else {
    rules = intersectScopeRules(fromConfig, fromEnv);
  }

  const scoped = rules !== null && rules.length > 0;
  return {
    rules,
    env_narrowed: Boolean(fromConfig && fromEnv),
    allow_unscoped: allowUnscoped,
    scoped,
    // An empty intersection is a scope that permits nothing, which is not the
    // same as no scope at all: it is a deliberate contradiction of the two
    // channels, and it must not fall back to "allow everything".
    fail_closed: !scoped && !allowUnscoped,
  };
}

/**
 * The escape hatch, read strictly.
 *
 * Read off the raw config object rather than off a typed field so that a config
 * that does not yet declare the key still works; the literal `true` is the only
 * accepted value.
 */
function readAllowUnscoped(machineConfig: MachineConfig): boolean {
  const security = (machineConfig as unknown as Record<string, unknown>)['security'];
  if (typeof security !== 'object' || security === null || Array.isArray(security)) return false;
  return (security as Record<string, unknown>)[ALLOW_UNSCOPED_DATABASES_CONFIG_KEY] === true;
}

/** True when the entry is permitted. An absent allow-list permits everything. */
export function scopeAllowsEntry(rules: DatabaseScopeRule[] | null, entry: DbEntry): boolean {
  if (!rules || rules.length === 0) return true;
  return rules.some(
    (rule) =>
      (rule.project_name === undefined || rule.project_name === entry.project_name) &&
      (rule.db_alias === undefined || rule.db_alias === entry.db_alias),
  );
}

export interface DeniedDatabaseRequest {
  project: string;
  db_alias?: string;
  reason: string;
  /**
   * Machine-readable refusal code, carried so the console line and any audit
   * record agree on what happened. Optional for callers that only render text.
   */
  code?: DatabaseRefusalCode;
}

export interface LookupDbOptions {
  getDatabases: () => DbEntry[];
  scope: DatabaseScopeRule[] | null;
  onDenied?: (attempt: DeniedDatabaseRequest) => void;
  /**
   * The effective scope decision. When it is absent the lookup keeps the
   * permissive historical behaviour of `scope === null` meaning "everything",
   * which is exactly what a caller with no decision object is assumed to want;
   * the daemon always supplies one.
   */
  decision?: DatabaseScopeDecision;
}

/**
 * Resolve an inbound frame's self-declared `project_name` / `db_alias` to a
 * database entry, refusing anything outside the allow-list.
 *
 * Two refusals that did not exist before:
 *
 *   - **Fail closed with no allow-list**. With nothing declared, this
 *     installation serves `ping` only. Restoring the old "everything is
 *     reachable" default requires the explicit
 *     `security.allow_unscoped_databases: true`.
 *   - **Project/alias collision**. When a frame names BOTH a project and
 *     an alias and they select *different* entries, the frame is refused. The
 *     old code silently preferred the project, executed against it, echoed the
 *     alias back and recorded neither — so the operation and the audit trail
 *     both named a database the operation never touched. Naming the same entry
 *     two ways is accepted.
 *
 * The result carries the refusal code rather than only `null` so the caller can
 * audit the refusal under its own reason instead of a generic "unavailable".
 */
export function createLookupDb(
  opts: LookupDbOptions,
): (project: string, alias?: string) => DatabaseLookupResult {
  const deny = (
    attempt: DeniedDatabaseRequest,
    code: DatabaseRefusalCode,
  ): DatabaseLookupResult => {
    opts.onDenied?.({ ...attempt, code });
    return {
      ok: false,
      code,
      reason: attempt.reason,
      asserted_project: attempt.project,
      asserted_db_alias: attempt.db_alias ?? '',
    };
  };

  return (project: string, alias?: string): DatabaseLookupResult => {
    const failClosed = opts.decision?.fail_closed === true;

    // Nothing is reachable without an allow-list unless the operator has
    // explicitly restored the permissive default. `ping` never reaches here:
    // the dispatcher answers it before consulting the lookup.
    if (opts.scope === null && failClosed) {
      return deny(
        {
          project,
          db_alias: alias,
          reason:
            'no database allow-list is configured for this agent, so no database is reachable',
        },
        'database_scope_not_configured',
      );
    }

    const databases = opts.getDatabases();
    const byProject = databases.find((entry) => entry.project_name === project);
    const byAlias = alias ? databases.find((entry) => entry.db_alias === alias) : undefined;

    // two names for one entry is fine; two names for two entries is not.
    if (byProject && byAlias && byProject.db_alias !== byAlias.db_alias) {
      return deny(
        {
          project,
          db_alias: alias,
          reason:
            'the project and the db_alias in this request name different configured databases',
        },
        'db_alias_project_mismatch',
      );
    }

    if (byProject) {
      if (!scopeAllowsEntry(opts.scope, byProject)) {
        return deny(
          {
            project,
            db_alias: byProject.db_alias,
            reason: "the project is not in this agent's permitted database allow-list",
          },
          'database_out_of_scope',
        );
      }
      return { ok: true, entry: byProject };
    }
    // Protocol also addresses DBs by db_alias. Fall back so relay clients that
    // only know the alias (e.g. the Data Explorer relay) still resolve.
    if (byAlias) {
      if (!scopeAllowsEntry(opts.scope, byAlias)) {
        return deny(
          {
            project,
            db_alias: alias,
            reason: "the database alias is not in this agent's permitted database allow-list",
          },
          'database_out_of_scope',
        );
      }
      return { ok: true, entry: byAlias };
    }
    return {
      ok: false,
      code: 'database_not_found',
      reason: `No configured database matches project "${project}"`,
      asserted_project: project,
      asserted_db_alias: alias ?? '',
    };
  };
}

/**
 * What an operator needs to know about this installation's database scope.
 *
 * Three states, and they read very differently on purpose:
 *
 *   - **scoped** — an allow-list is in force. Nothing to say.
 *   - **fail-closed (the new default)** — nothing is declared, so this agent
 *     serves `ping` only. This is the upgrade notice  asks for: an existing
 *     install that never configured `allowed_databases` previously reached every
 *     database on the host and will now reach none, and an operator who has not
 *     read a changelog needs to be told that in the first seconds of the daemon,
 *     not in a log file nobody opens.
 *   - **unscoped by explicit opt-in** — every configured database is reachable
 *     again, and the risk is named in full.
 */
export function databaseScopeWarningLines(
  scope: DatabaseScopeRule[] | null,
  databases: DbEntry[],
  decision?: DatabaseScopeDecision,
): string[] {
  const scoped = scope !== null && scope.length > 0;
  if (scoped) return [];
  const reachable = databases.map((entry) => `${entry.project_name}/${entry.db_alias}`).join(', ');
  const listed = reachable || 'none';
  const restoreHint =
    `set ${ALLOWED_DATABASES_CONFIG_KEY} in sw-agent.config.json, or ` +
    `${ALLOWED_DATABASES_ENV}, to a list of ` +
    '{ "project_name": ..., "db_alias": ... } pairs';

  if (decision && !decision.allow_unscoped) {
    return [
      '[security] ============================================================================',
      `[security] BREAKING CHANGE: no database allow-list is configured, so this agent now ` +
        `REFUSES every database request. Only 'ping' is answered.`,
      `[security] Before this release an unscoped agent token reached every configured ` +
        `database (${databases.length}): ${listed}.`,
      `[security] To restore that behaviour set 'true' in sw-agent.config.json: ` +
        `{ "security": { "${ALLOW_UNSCOPED_DATABASES_CONFIG_KEY}": true } } — and read ` +
        'the risk first: one token would again reach every database on this host, including',
      '[security] production, and any authenticated principal could name any of them.',
      `[security] To scope instead, ${restoreHint}.`,
      '[security] ============================================================================',
    ];
  }

  return [
    '[security] WARNING: no database allow-list is configured for this agent.',
    `[security] The agent token is UNSCOPED: it reaches every configured ` +
      `database (${databases.length}): ${listed}.`,
    '[security] A session authenticated for one project can therefore reach ' +
      `every other project on this host, including production. To scope it, ${restoreHint}.`,
    `[security] This permissive mode is active only because ` +
      `${ALLOW_UNSCOPED_DATABASES_CONFIG_PATH} is explicitly true in the machine config.`,
  ];
}

/**
 * One-line summary for `sw-agent status`.
 *
 * The warning above goes to the console of a detached daemon, which most
 * operators never see; this is the part that has to reach the CLI an operator
 * actually runs. See the `security` block of `DaemonStatus`.
 */
export function describeDatabaseScope(
  decision: DatabaseScopeDecision,
  databases: DbEntry[],
): string {
  if (decision.fail_closed) {
    return (
      'FAIL CLOSED — no allowed_databases allow-list is configured, so every database request ' +
      'is refused (ping only). Set allowed_databases in sw-agent.config.json, or ' +
      `${ALLOWED_DATABASES_ENV}, or set ${ALLOW_UNSCOPED_DATABASES_CONFIG_PATH}: true to ` +
      'restore the previous permissive default.'
    );
  }
  if (decision.allow_unscoped) {
    return (
      `UNSCOPED BY OPERATOR CHOICE — the token reaches every configured database ` +
      `(${databases.length}): ${databases.map((e) => `${e.project_name}/${e.db_alias}`).join(', ') || 'none'}. ` +
      'Any authenticated principal can name any of them.'
    );
  }
  return `SCOPED — ${decision.rules?.length ?? 0} allow-list rule(s).`;
}

export async function runAgent(opts: RuntimeOptions): Promise<number> {
  const daemonStartedAt = new Date().toISOString();
  // Snapshot the inherited environment before anything is stripped from it, so
  // the posture log below reports what this process was actually started with.
  const inheritedEnv: NodeJS.ProcessEnv = { ...process.env };

  // Validate the `--relay` override before applying it. Applied after
  // `validateMachineConfig` used to bypass every check, so `--relay
  // ws://attacker.example` sent the permanent agent token in cleartext from a
  // detached process.
  const relay = resolveRelayOverride(opts.relayUrl, opts.machineConfig.cloud_url);
  if (relay.isOverride && relay.hostChanged && relay.configuredHost && relay.relayHost) {
    console.error(relayHostMismatchWarning(relay.configuredHost, relay.relayHost));
  }
  if (relay.isOverride) {
    opts.machineConfig.cloud_url = relay.url;
  }
  // Refuse any inherited variable that would change the security posture of
  // this process (see UNRECOGNISED_SECURITY_ENV). Without this, a `.service`
  // file, wrapper script, PM2 ecosystem file, CI job, or Dockerfile `ENV` that
  // sets e.g. PG_CONNECTOR_HOME or SW_MAX_STATEMENT_TIMEOUT_MS silently
  // reconfigures the agent that inherits it.
  const refusedEnvVars = stripUnrecognisedSecurityEnv();
  // Everything resolved from here on reads the *live* environment, not the
  // snapshot, so a refused variable cannot be honoured through a captured copy.
  // Resolving from `inheritedEnv` would have quietly applied SW_PG_POOL_MAX and
  // SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS while claiming they were refused.
  // Capture crashes and per-operation errors to errors.jsonl.
  installGlobalHandlers(opts.machineConfig.agent_id);
  for (const name of refusedEnvVars) {
    console.error(
      `[security] Ignoring ${name}: ${UNRECOGNISED_SECURITY_ENV[name]} — this variable is not an accepted configuration input.`,
    );
  }
  for (const line of formatSecurityPosture(resolveSecurityPosture(process.env, inheritedEnv), [
    opts.machineConfig.agent_token,
    opts.machineConfig.cloud_telemetry?.ingest_url,
  ])) {
    console.log(line);
  }
  const e2eGate = resolveE2EAdminGate(inheritedEnv);
  if (e2eGate.requested) {
    console.error(
      `[security] WARNING: SW_AGENT_E2E=1 was set in the environment but ${e2eGate.reason}. ` +
        'This build contains no inbound admin control plane, so nothing was started; ' +
        'no /admin/shutdown endpoint exists to call.',
    );
  }

  // Load the real PostgreSQL parser before anything that can classify SQL exists.
  // `classifyStatement()` is fail-closed by design (audit finding C-01): with the
  // WASM module unloaded, `parseSql()` throws and every `query`, `stream_query`
  // and `migration_run` is refused with `parser_unavailable`. Awaited here, after
  // `installGlobalHandlers()` so a load failure is tracked like any other
  // startup error, and before `PlanRegistry` / `PermissionChecker` /
  // `Dispatcher` are constructed, so no request can be classified before the
  // parser is ready. There is deliberately no heuristic fallback: a lexical
  // classifier is the entire vulnerability this finding is about.
  try {
    await initSqlParser();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    trackError(err, { op: 'initSqlParser', level: 'fatal' });
    console.error();
    console.error(`[security] FATAL: ${message}`);
    console.error(
      '  The agent cannot classify SQL without it, so every query, stream and migration ' +
        'would be refused with `parser_unavailable`. Refusing to start rather than falling ' +
        'back to a lexical classifier.',
    );
    console.error(
      '  Reinstall the package so node_modules/pgsql-parser and its libpg-query WASM binary ' +
        'are intact, then run `sw-agent doctor` and `sw-agent start` again.',
    );
    console.error(`  Agent log: ${getDaemonLogPath()}`);
    console.error();
    return 1;
  }

  const poolManager = new PoolManager({ maxPoolSize: resolvePoolMax() });
  // Assigned further down, after the objects whose callbacks close over it exist.
  // eslint-disable-next-line prefer-const -- deferred initialisation, not reassignment
  let writeStatus: () => Promise<void>;
  let currentDatabasesConfig = opts.databasesConfig;
  let configRevision = Date.now();

  const planRegistry = new PlanRegistry();
  const autoUpgradeChecker = new AutoUpgradeChecker({ planRegistry });

  const auditLocalWriter = new LocalAuditWriter({
    dir: opts.auditDir,
    maxFileSize: 10 * 1024 * 1024,
    maxArchiveFiles: 10,
  });

  const auditSink = new AuditSink({
    agentId: opts.machineConfig.agent_id,
    localWriter: auditLocalWriter,
    cloudWriter: new CloudAuditWriter({
      enabled: opts.machineConfig.cloud_telemetry?.enabled !== false,
      url: opts.machineConfig.cloud_telemetry?.ingest_url,
      cloudUrl: opts.machineConfig.cloud_url,
      agent_token: opts.machineConfig.agent_token,
      agent_id: opts.machineConfig.agent_id,
    }),
  });

  // Deterministic shutdown of the audit path: drain the queue, fsync what was
  // written, then release the handle. Flushing without closing left the long-
  // lived file descriptor to the garbage collector and to process exit (finding
  // M-05), so records that had been counted but not yet committed could be lost
  // and the fd was not released before a restart reopened the same path.
  const closeAudit = createAuditShutdown({
    flush: () => auditSink.flush(),
    close: () => auditLocalWriter.close(),
  });

  // Also enable the operation logger (CLI/lifecycle ops) for cloud delivery.
  initOperationLogger({
    enabled: opts.machineConfig.cloud_telemetry?.enabled !== false,
    cloudUrl: opts.machineConfig.cloud_url,
    token: opts.machineConfig.agent_token,
    agentId: opts.machineConfig.agent_id,
  });

  // Assigned after the dispatcher is built, which itself closes over `session`.
  // eslint-disable-next-line prefer-const -- deferred initialisation, not reassignment
  let session: AgentSession;
  const manualApprovalHandler = new ManualApprovalHandler({
    send: async (msg) => {
      if (session) {
        await session.send(msg);
      }
    },
    timeoutMs: resolveApprovalTimeoutMs(),
    auditSink,
  });

  const permissionChecker = new PermissionChecker({
    autoUpgradeChecker,
    manualApprovalHandler,
    planRegistry,
  });

  const stats = new RuntimeStats();

  const originalLog = auditSink.log.bind(auditSink);
  const originalLogSync = auditSink.logSync.bind(auditSink);

  const updateStatsFromEvent = (partial: CountedAuditEvent) => {
    if (partial.decision === 'allow' && partial.outcome !== 'n/a') {
      if (partial.action === 'query') {
        stats.queries_served++;
      } else if (partial.action === 'stream_query') {
        stats.streams_served++;
      } else if (partial.action === 'migration_run') {
        stats.migrations_run++;
      } else if (partial.action === 'cancel') {
        stats.cancellations++;
      }
    } else if (partial.decision === 'deny') {
      if (partial.denial_reason === 'buffer_overflow') {
        stats.audit_buffer_overflows++;
      } else {
        stats.permission_denies++;
      }
    }
  };

  // `audit_events_written` is NOT incremented here. Both durability counters
  // are reconciled from the sink instead (see `buildDaemonAuditStats`): the
  // sink increments `events_written` only once an append has actually resolved,
  // and `log()` hands back no promise to await. Incrementing before the write
  // resolved claimed a durability the process did not have (audit finding C-06,
  // item 6).
  auditSink.log = (partial) => {
    updateStatsFromEvent(partial);
    originalLog(partial);
  };

  auditSink.logSync = async (partial) => {
    try {
      await originalLogSync(partial);
    } catch (err) {
      stats.audit_events_failed++;
      throw err;
    }
    // Only a persisted record may move the activity counters: for `logSync` the
    // append is the gate, so a rejected record means the work never happened.
    updateStatsFromEvent(partial);
  };

  // Create dispatcher dependencies
  const queryRunner = new QueryRunner({ poolManager });
  const migrationRunner = new MigrationRunner({ poolManager });
  // The pool manager is required here, not optional: without it every cancel
  // opened a fresh TCP + TLS + password-authenticated connection, so a stream
  // of cancel requests could exhaust max_connections on the database.
  const canceller = new Canceller({ poolManager });
  const introspector = new Introspector({ poolManager });

  const scopeDecision = resolveDatabaseScopeDecision(opts.machineConfig);
  const databaseScope = scopeDecision.rules;
  for (const line of databaseScopeWarningLines(
    databaseScope,
    currentDatabasesConfig.databases,
    scopeDecision,
  )) {
    console.error(line);
  }
  // an explicit `admin` ceiling is the documented escape hatch and the
  // only way past the default `developer` ceiling. Saying so once, loudly, at
  // startup, is what makes it a deliberate choice rather than an inherited one.
  const configuredRoleCeiling =
    (opts.machineConfig as unknown as { security?: { max_negotiable_role?: Role } }).security
      ?.max_negotiable_role ?? ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT;
  if (configuredRoleCeiling === 'admin') {
    console.error(
      '[security] WARNING: security.max_negotiable_role is "admin". A compromised relay can ' +
        'then assert the full capability set (ddl, migration_run, approve_ddl) on every ' +
        'configured database this agent can reach. The default ceiling is ' +
        `"${ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT}".`,
    );
  }
  const deniedScopes = new Set<string>();
  const lookupDb = createLookupDb({
    getDatabases: () => currentDatabasesConfig.databases,
    scope: databaseScope,
    decision: scopeDecision,
    onDenied: (attempt) => {
      const key = `${attempt.code ?? 'refused'}|${attempt.project}|${attempt.db_alias ?? ''}`;
      if (deniedScopes.has(key)) return;
      deniedScopes.add(key);
      console.error(
        `[security] Refused request for project "${attempt.project}"` +
          `${attempt.db_alias ? ` (alias "${attempt.db_alias}")` : ''}` +
          `${attempt.code ? ` [${attempt.code}]` : ''}: ${attempt.reason}.`,
      );
    },
  });

  const dispatcher = new Dispatcher({
    poolManager,
    queryRunner,
    migrationRunner,
    canceller,
    introspector,
    permissionChecker,
    planRegistry,
    lookupDb,
    getMachineConfig: () => opts.machineConfig,
    send: (msg) => session.send(msg),
    waitForDrain: () => session.waitForDrain(),
    auditSink,
  });

  session = new AgentSession({
    machineConfig: opts.machineConfig,
    getDatabases: () =>
      currentDatabasesConfig.databases.map((db) => ({
        db_alias: db.db_alias,
        database: db.database,
      })),
    onMessage: async (msg) => {
      try {
        await dispatcher.handle(msg);
      } catch (err) {
        trackError(err, { op: msg.type });
        throw err;
      }
    },
    onStateChange: () => {
      writeStatus().catch((err) => {
        console.error('[stateChange] failed to write status:', err);
        trackError(err, { op: 'writeStatus' });
      });
    },
  });

  const shutdown = createShutdownCoordinator();

  // Shutdown registration order matters (sequential execution)
  // 1. pool-manager: wait for active queries to finish
  shutdown.register('pool-manager', async () => {
    await poolManager.closeAll();
  });

  // 2. agent-session: close websocket (data channel)
  shutdown.register('agent-session', async () => {
    await session.stop();
  });

  // 3. audit-sink: flush what was written, then release the handle. The step is
  //    memoised, so the signal path and an explicit stop can both call it.
  shutdown.register('audit-sink', closeAudit);

  // 4. operation-logger: flush operation logs
  shutdown.register('operation-logger', async () => {
    await _shutdownOperationLogger();
  });

  // NOTE: there is deliberately no inbound HTTP listener anywhere in this
  // module. An earlier build started an unauthenticated loopback admin server
  // (`POST /admin/shutdown`, `GET /admin/stats`, `POST /admin/audit-flush`)
  // whenever `SW_AGENT_E2E=1`, which shipped in the published bundle and made
  // the README's "never calls listen()" claim false. Test control planes do
  // not belong in the daemon; if one is ever needed again it must live in a
  // separate `*-e2e` entry point that is excluded from the published `files`.
  // See SECURITY.md for the accurate statement of the network posture.

  const uninstallSignals = installSignalHandlers(shutdown);

  /**
   * A startup step that throws leaves the daemon to unwind without reaching the
   * shutdown coordinator, so the audit handle would not be released until the
   * process died. Close it here instead, then rethrow unchanged.
   */
  const failStartup = async (err: unknown, op: string): Promise<never> => {
    trackError(err, { op });
    console.error(`[daemon] ${op} failed; closing the audit writer before giving up:`, err);
    await closeAudit().catch(() => undefined);
    throw err;
  };

  try {
    await writePidFile(
      { path: opts.pidFile },
      {
        pid: process.pid,
        started_at: daemonStartedAt,
        version: VERSION,
      },
    );
  } catch (err: unknown) {
    await failStartup(err, 'writePidFile');
  }

  let isWritingStatus = false;
  let hasPendingStatusWrite = false;

  writeStatus = async () => {
    if (isWritingStatus) {
      hasPendingStatusWrite = true;
      return;
    }
    isWritingStatus = true;
    try {
      for (;;) {
        const state = session.getState();
        const errorStats = getErrorLogStats();
        const auditStats = buildDaemonAuditStats(stats, auditSink.getHealth());
        const status: DaemonStatus = {
          pid: process.pid,
          started_at: daemonStartedAt,
          last_heartbeat: new Date().toISOString(),
          version: VERSION,
          channels: {
            sse:
              state.wake === 'connected'
                ? 'connected'
                : state.wake === 'connecting'
                  ? 'connecting'
                  : state.wake === 'error'
                    ? 'error'
                    : 'disconnected',
            wss:
              state.data === 'open'
                ? 'connected'
                : state.data === 'connecting'
                  ? 'connecting'
                  : state.data === 'error'
                    ? 'error'
                    : state.data === 'closed'
                      ? 'idle'
                      : 'disconnected',
          },
          stats: {
            queries_served: stats.queries_served,
            streams_served: stats.streams_served,
            migrations_run: stats.migrations_run,
            cancellations: stats.cancellations,
            permission_denies: stats.permission_denies,
            audit_events_written: auditStats.audit_events_written,
            audit_events_failed: auditStats.audit_events_failed,
            audit_buffer_overflows: auditStats.audit_buffer_overflows,
            audit_dropped: auditStats.audit_dropped,
          },
          audit: auditStats.audit,
          config: {
            databases: currentDatabasesConfig.databases.length,
            projects: new Set(currentDatabasesConfig.databases.map((db) => db.project_name)).size,
            revision: configRevision,
          },
          errors_log: {
            path: errorStats.path,
            size_bytes: errorStats.size_bytes,
          },
          //  / the security posture an operator most needs to see is
          // the one that is invisible when it is wrong, and the daemon's own
          // console is not where an operator looks. This block is what
          // `sw-agent status` reads.
          security: {
            database_scope: describeDatabaseScope(
              scopeDecision,
              currentDatabasesConfig.databases,
            ),
            allowlist_configured: scopeDecision.scoped,
            allow_unscoped_databases: scopeDecision.allow_unscoped,
            fail_closed: scopeDecision.fail_closed,
            env_narrowed_scope: scopeDecision.env_narrowed,
            max_negotiable_role: configuredRoleCeiling,
          },
        };
        hasPendingStatusWrite = false;
        await writeStatusFile({ path: opts.statusFile }, status);
        if (!hasPendingStatusWrite) {
          break;
        }
      }
    } finally {
      isWritingStatus = false;
    }
  };

  const dbConfigPath = getDbConfigPath();
  const reloadDbConfig = async () => {
    try {
      const next = loadDatabasesConfig();

      currentDatabasesConfig = next;
      configRevision = Date.now();

      // Close every pool whose connection parameters no longer match the
      // config: a rotated password, a new host, an ssl_mode change or a
      // permission_override change. Previously only *removed* aliases were
      // closed, so an edited entry kept serving from the old pg.Pool until the
      // idle timer fired — revoking a compromised credential did not take
      // effect.
      const closed = await poolManager.reconcile(next.databases);
      if (closed.length > 0) {
        console.error(
          `[config] Closed ${closed.length} connection pool(s) whose settings changed: ${closed.join(', ')}.`,
        );
      }

      await writeStatus();
    } catch (err) {
      trackError(err, { op: 'reloadDbConfig' });
      console.error('[config] failed to reload database config:', err);
    }
  };

  try {
    fs.watchFile(dbConfigPath, { interval: 1000 }, (curr, prev) => {
      if (curr.mtimeMs !== prev.mtimeMs || curr.size !== prev.size) {
        void reloadDbConfig();
      }
    });
    shutdown.register('db-config-watcher', async () => {
      fs.unwatchFile(dbConfigPath);
    });
  } catch (err) {
    trackError(err, { op: 'watchDbConfig' });
  }

  try {
    await session.start();
  } catch (err: unknown) {
    await failStartup(err, 'session.start');
  }

  const heartbeat = setInterval(() => {
    writeStatus().catch((err) => {
      console.error('[heartbeat] failed to write status:', err);
    });
  }, 30_000);

  let autoExitTimer: ReturnType<typeof setTimeout> | undefined;
  if (opts.autoExitMs) {
    autoExitTimer = setTimeout(() => {
      debugLog('[daemon] Auto exit triggered');
      shutdown.shutdown(5_000).catch(() => {});
    }, opts.autoExitMs);
  }

  await new Promise<void>((resolve) => {
    const checkShutdown = setInterval(() => {
      if (shutdown.isShuttingDown()) {
        clearInterval(checkShutdown);
        debugLog(
          `[daemon] ${new Date().toISOString()} Shutdown detected, proceeding to cleanup...`,
        );
        resolve();
      }
    }, 100);
  });

  debugLog(`[daemon] ${new Date().toISOString()} Awaiting shutdown coordinator...`);
  const result = await shutdown.shutdown(30_000);
  debugLog(
    `[daemon] ${new Date().toISOString()} Shutdown coordinator finished with result: ${result}`,
  );

  clearInterval(heartbeat);
  if (autoExitTimer) clearTimeout(autoExitTimer);

  debugLog(`[daemon] ${new Date().toISOString()} Deleting pid file...`);
  await deletePidFile({ path: opts.pidFile });

  debugLog(`[daemon] ${new Date().toISOString()} Uninstalling signals...`);
  uninstallSignals();

  debugLog(`[daemon] ${new Date().toISOString()} Writing final status...`);
  const finalErrorStats = getErrorLogStats();
  const finalAuditStats = buildDaemonAuditStats(stats, auditSink.getHealth());
  await writeStatusFile(
    { path: opts.statusFile },
    {
      pid: process.pid,
      started_at: daemonStartedAt,
      last_heartbeat: new Date().toISOString(),
      version: VERSION,
      channels: {
        sse: 'disconnected',
        wss: 'disconnected',
      },
      stats: {
        queries_served: stats.queries_served,
        streams_served: stats.streams_served,
        migrations_run: stats.migrations_run,
        cancellations: stats.cancellations,
        permission_denies: stats.permission_denies,
        audit_events_written: finalAuditStats.audit_events_written,
        audit_events_failed: finalAuditStats.audit_events_failed,
        audit_buffer_overflows: finalAuditStats.audit_buffer_overflows,
        audit_dropped: finalAuditStats.audit_dropped,
      },
      audit: finalAuditStats.audit,
      config: {
        databases: currentDatabasesConfig.databases.length,
        projects: new Set(currentDatabasesConfig.databases.map((db) => db.project_name)).size,
        revision: configRevision,
      },
      errors_log: {
        path: finalErrorStats.path,
        size_bytes: finalErrorStats.size_bytes,
      },
    },
  );

  debugLog(`[daemon] runAgent returning exit code: ${result === 'clean' ? 0 : 1}`);
  return result === 'clean' ? 0 : 1;
}

function debugLog(message: string): void {
  if (process.env.SW_AGENT_DEBUG === '1') {
    console.error(message);
  }
}
