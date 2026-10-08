import * as fs from 'fs';
import { getMachineConfigPath } from './paths';
import {
  validateAgentTokenFormat,
  generateAgentToken,
  generateAgentId,
  isDevToken,
  DEV_TOKEN,
} from './token';
import { atomicWriteFile, withFileLock } from './atomic-write';
import { isRole, type Role } from '../protocol/envelope';
import { PermissionLevel } from '../permissions/checker';
export { PermissionLevel };
import {
  ConfigInvalidError,
  ConfigNotFoundError,
  ConfigError,
  isValidIso8601,
  isValidIdentifier,
  isSecureCloudUrl,
  isSecureIngestUrl,
} from './schema';

const CONFIG_FILE_MODE = 0o600;

/**
 * Machine-level config: sw-agent.config.json
 * Contains: cloud URL, agent token, agent ID, default permission, machine label.
 * Does NOT contain: database connection info (that's in db-config.ts).
 */
export interface MachineConfig {
  config_version: 1; // schema version, always 1 for now
  cloud_url: string; // e.g. "wss://api.schemaweaver.dev" (wss: only)
  agent_token: string; // format: swagt_<32 chars>
  agent_id: string; // format: agt_<label>_<8 hex>
  default_permission: PermissionLevel;
  machine_label: string; // human-readable, e.g. "vivek-laptop"
  log_level: 'debug' | 'info' | 'warn' | 'error';
  /** Cloud telemetry: ship audit + operation logs to the backend (best-effort). */
  cloud_telemetry?: {
    enabled: boolean;
    ingest_url?: string; // optional override; https: only, otherwise derived from cloud_url
  };
  /**
   * Transport-security overrides. Every key is optional and absent means "the
   * secure default", so a config written by an older build keeps working and a
   * partially written block cannot silently relax a control.
   */
  security?: {
    /** Require a per-session MAC on inbound data-channel envelopes. Default: true. */
    envelope_mac_required?: boolean;
    /**
     * Hard local ceiling on the role a relay may assert for a data-channel
     * session, applied by `InboundEnvelopeGuard` after the negotiated-set
     * check.
     *
     * Default: `'developer'` — `ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT`, not
     * `'admin'`. An earlier revision of this file documented `'admin'`, which is
     * not what the code does: the default was the strongest role, so the
     * ceiling bound nothing. Setting `'admin'` here is honoured and warned
     * about at daemon startup, and `sw-agent status` reports the effective
     * ceiling.
     */
    max_negotiable_role?: Role;
  };
  created_at: string; // ISO 8601
  updated_at: string; // ISO 8601
}

export const DEFAULT_MACHINE_CONFIG: Partial<MachineConfig> = {
  cloud_url: 'wss://api.schemaweaver.dev',
  default_permission: 'read_only',
  machine_label: 'unknown',
  log_level: 'info',
};

/** Least-privileged permission level; the default for every new install. */
export const SAFEST_PERMISSION: PermissionLevel = 'read_only';

/**
 * Creates a new default MachineConfig with the given options and current ISO timestamps.
 * Defaults to the least-privileged permission level; a more permissive level
 * must be requested explicitly by the caller.
 */
export function createDefaultMachineConfig(opts: {
  machineLabel: string;
  cloudUrl?: string;
  permission?: PermissionLevel;
  token?: string;
}): MachineConfig {
  const cloudUrl = opts.cloudUrl || 'wss://api.schemaweaver.dev';
  const permission = opts.permission || SAFEST_PERMISSION;
  const token = opts.token || generateAgentToken();
  const agentId = generateAgentId(opts.machineLabel);
  const now = new Date().toISOString();

  return {
    config_version: 1,
    cloud_url: cloudUrl,
    agent_token: token,
    agent_id: agentId,
    default_permission: permission,
    machine_label: opts.machineLabel,
    log_level: 'info',
    created_at: now,
    updated_at: now,
  };
}

/**
 * Validates the raw JSON input to ensure it meets MachineConfig constraints.
 */
export function validateMachineConfig(raw: unknown): MachineConfig {
  if (typeof raw !== 'object' || raw === null) {
    throw new ConfigInvalidError('Config is not a valid JSON object');
  }

  const data = raw as Record<string, unknown>;

  if (data.config_version !== 1) {
    throw new ConfigInvalidError('Field "config_version" invalid: Must be 1');
  }

  // The agent token is a permanent bearer credential, so the transport that
  // carries it must be TLS end to end. ws:// and http:// are refused rather
  // than warned about: there is no way to carry a one-shot opt-in flag through
  // the detached daemon/service start paths, so an accepted-but-plaintext URL
  // would produce a config the agent can never load again.
  if (typeof data.cloud_url !== 'string' || !isSecureCloudUrl(data.cloud_url)) {
    throw new ConfigInvalidError(
      'Field "cloud_url" invalid: Must be a wss:// URL with an explicit authority (ws:// and http:// are not accepted; the agent token would travel in cleartext)',
    );
  }

  const token = data.agent_token;
  if (typeof token !== 'string' || (!validateAgentTokenFormat(token) && !isDevToken(token))) {
    throw new ConfigInvalidError(
      `Field "agent_token" invalid: Must match swagt_<32 chars base62> or be ${DEV_TOKEN}`,
    );
  }

  const agentId = data.agent_id;
  if (typeof agentId !== 'string' || !/^agt_[a-zA-Z0-9_-]+_[a-f0-9]{8}$/.test(agentId)) {
    throw new ConfigInvalidError(
      'Field "agent_id" invalid: Must match pattern agt_<label>_<8 hex>',
    );
  }

  const perm = data.default_permission;
  if (perm !== 'read_only' && perm !== 'auto_upgrade' && perm !== 'manual' && perm !== 'full') {
    throw new ConfigInvalidError(
      'Field "default_permission" invalid: Must be read_only, auto_upgrade, manual, or full',
    );
  }

  const label = data.machine_label;
  if (typeof label !== 'string' || !isValidIdentifier(label, 64) || label.includes(' ')) {
    throw new ConfigInvalidError(
      'Field "machine_label" invalid: Must be 1-64 characters containing only letters, numbers, hyphens, and underscores (no spaces)',
    );
  }

  const level = data.log_level;
  if (level !== 'debug' && level !== 'info' && level !== 'warn' && level !== 'error') {
    throw new ConfigInvalidError('Field "log_level" invalid: Must be debug, info, warn, or error');
  }

  // Optional cloud telemetry config.
  const telemetry = data.cloud_telemetry;
  if (telemetry !== undefined && telemetry !== null) {
    if (typeof telemetry !== 'object') {
      throw new ConfigInvalidError('Field "cloud_telemetry" invalid: Must be an object');
    }
    const t = telemetry as Record<string, unknown>;
    if (typeof t.enabled !== 'boolean') {
      throw new ConfigInvalidError('Field "cloud_telemetry.enabled" invalid: Must be boolean');
    }
    if (t.ingest_url !== undefined && t.ingest_url !== null) {
      if (typeof t.ingest_url !== 'string' || !isSecureIngestUrl(t.ingest_url)) {
        throw new ConfigInvalidError(
          'Field "cloud_telemetry.ingest_url" invalid: Must be an https:// URL with an explicit authority (http:// is not accepted)',
        );
      }
    }
  }

  // Optional transport-security overrides. Absent keys keep the secure default,
  // so a hand-edited block can only ever be as permissive as its own values.
  const security = data.security;
  if (security !== undefined && security !== null) {
    if (typeof security !== 'object' || Array.isArray(security)) {
      throw new ConfigInvalidError('Field "security" invalid: Must be an object');
    }
    const s = security as Record<string, unknown>;
    if (s.envelope_mac_required !== undefined && s.envelope_mac_required !== null) {
      if (typeof s.envelope_mac_required !== 'boolean') {
        throw new ConfigInvalidError(
          'Field "security.envelope_mac_required" invalid: Must be boolean',
        );
      }
    }
    if (s.max_negotiable_role !== undefined && s.max_negotiable_role !== null) {
      if (!isRole(s.max_negotiable_role)) {
        throw new ConfigInvalidError(
          'Field "security.max_negotiable_role" invalid: Must be a known role',
        );
      }
    }
  }

  const created = data.created_at;
  if (typeof created !== 'string' || !isValidIso8601(created)) {
    throw new ConfigInvalidError('Field "created_at" invalid: Must be a valid ISO 8601 string');
  }

  const updated = data.updated_at;
  if (typeof updated !== 'string' || !isValidIso8601(updated)) {
    throw new ConfigInvalidError('Field "updated_at" invalid: Must be a valid ISO 8601 string');
  }

  return raw as MachineConfig;
}

/**
 * Checks if the sw-agent.config.json file exists.
 */
export function machineConfigExists(): boolean {
  try {
    return fs.existsSync(getMachineConfigPath());
  } catch {
    return false;
  }
}

/**
 * Loads and validates the machine config file.
 */
export function loadMachineConfig(): MachineConfig {
  const p = getMachineConfigPath();
  if (!fs.existsSync(p)) {
    throw new ConfigNotFoundError(p);
  }
  let fileContent: string;
  try {
    fileContent = fs.readFileSync(p, 'utf8');
  } catch (err) {
    throw new ConfigError(
      'invalid',
      `Failed to read config file: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  let json: unknown;
  try {
    json = JSON.parse(stripBom(fileContent));
  } catch (err) {
    throw new ConfigInvalidError(
      `Config file is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return validateMachineConfig(json);
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

/**
 * Saves the machine config to disk with 0o600 permissions on POSIX, written
 * atomically and with the mode repaired if a pre-existing file is readable by
 * group or other.
 */
export function saveMachineConfig(config: MachineConfig): void {
  const p = getMachineConfigPath();
  config.updated_at = new Date().toISOString();
  validateMachineConfig(config);
  try {
    atomicWriteFile(p, JSON.stringify(config, null, 2), CONFIG_FILE_MODE);
  } catch (err) {
    throw new ConfigError(
      'write_failed',
      `Failed to write machine config: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Runs a load → mutate → save cycle over sw-agent.config.json under an advisory
 * lock, so a concurrent `config set` cannot be lost to a read-modify-write
 * race. `mutate` edits the config in place; its return value is passed back.
 */
export function mutateMachineConfig<T>(mutate: (config: MachineConfig) => T): T {
  return withFileLock(getMachineConfigPath(), () => {
    const config = loadMachineConfig();
    const result = mutate(config);
    saveMachineConfig(config);
    return result;
  });
}
