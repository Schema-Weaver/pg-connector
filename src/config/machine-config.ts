import * as fs from 'fs';
import { getMachineConfigPath } from './paths';
import { validateAgentTokenFormat, generateAgentToken, generateAgentId } from './token';
import { PermissionLevel } from '../permissions/checker';
export { PermissionLevel };
import {
  ConfigInvalidError,
  ConfigNotFoundError,
  ConfigError,
  isValidIso8601,
  isValidIdentifier,
} from './schema';

/**
 * Machine-level config: sw-agent.config.json
 * Contains: cloud URL, agent token, agent ID, default permission, machine label.
 * Does NOT contain: database connection info (that's in db-config.ts).
 */
export interface MachineConfig {
  config_version: 1; // schema version, always 1 for now
  cloud_url: string; // e.g. "wss://api.schemaweaver.dev"
  agent_token: string; // format: swagt_<32 chars>
  agent_id: string; // format: agt_<label>_<8 hex>
  default_permission: PermissionLevel;
  machine_label: string; // human-readable, e.g. "vivek-laptop"
  log_level: 'debug' | 'info' | 'warn' | 'error';
  /** Cloud telemetry: ship audit + operation logs to the backend (best-effort). */
  cloud_telemetry?: {
    enabled: boolean;
    ingest_url?: string; // optional override; otherwise derived from cloud_url
  };
  created_at: string; // ISO 8601
  updated_at: string; // ISO 8601
}

export const DEFAULT_MACHINE_CONFIG: Partial<MachineConfig> = {
  cloud_url: 'wss://api.schemaweaver.dev',
  default_permission: 'auto_upgrade',
  machine_label: 'unknown',
  log_level: 'info',
};

/**
 * Creates a new default MachineConfig with the given options and current ISO timestamps.
 */
export function createDefaultMachineConfig(opts: {
  machineLabel: string;
  cloudUrl?: string;
  permission?: PermissionLevel;
  token?: string;
}): MachineConfig {
  const cloudUrl = opts.cloudUrl || 'wss://api.schemaweaver.dev';
  const permission = opts.permission || 'auto_upgrade';
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

  if (
    typeof data.cloud_url !== 'string' ||
    (!data.cloud_url.startsWith('wss://') && !data.cloud_url.startsWith('ws://')) ||
    data.cloud_url.length < 10
  ) {
    throw new ConfigInvalidError(
      'Field "cloud_url" invalid: Must start with wss:// or ws:// and be at least 10 characters',
    );
  }

  const token = data.agent_token;
  if (
    typeof token !== 'string' ||
    (!validateAgentTokenFormat(token) && token !== 'swagt_DEV_LOCAL_ONLY')
  ) {
    throw new ConfigInvalidError(
      'Field "agent_token" invalid: Must match swagt_<32 chars base62> or be swagt_DEV_LOCAL_ONLY',
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
      if (typeof t.ingest_url !== 'string' || (!t.ingest_url.startsWith('http://') && !t.ingest_url.startsWith('https://'))) {
        throw new ConfigInvalidError('Field "cloud_telemetry.ingest_url" invalid: Must start with http:// or https://');
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
 * Saves the machine config to disk with 0o600 permissions on POSIX.
 */
export function saveMachineConfig(config: MachineConfig): void {
  const p = getMachineConfigPath();
  config.updated_at = new Date().toISOString();
  validateMachineConfig(config);
  try {
    fs.writeFileSync(p, JSON.stringify(config, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch (err) {
    throw new ConfigError(
      'write_failed',
      `Failed to write machine config: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
