import * as fs from 'fs';
import { getDbConfigPath } from './paths';
import { PermissionLevel } from '../permissions/checker';
import {
  ConfigError,
  ConfigInvalidError,
  isValidIdentifier,
  isValidHostname,
  isValidIpv4,
  isValidIpv6,
  isValidEnvVarName,
  isValidIso8601,
} from './schema';

/**
 * Database-level config: databases.config.json
 * Array of DB entries. Each entry binds one DB to one project.
 * One project = one DB (schema weaver constraint).
 */
export interface DbEntry {
  project_name: string; // unique across array
  db_alias: string; // unique across array
  host: string;
  port: number; // 1-65535
  database: string;
  user: string;
  password_env?: string; // OS env var name (optional)
  password_stored?: string; // Password stored directly (optional)
  ssl_mode: 'disable' | 'require' | 'verify-ca' | 'verify-full';
  ssl_root_cert?: string | null; // path to CA cert, optional
  permission_override: PermissionLevel | null;
  created_at: string;
}

export type DbConfig = DbEntry[];

/**
 * Checks if the databases.config.json file exists.
 */
export function dbConfigExists(): boolean {
  try {
    return fs.existsSync(getDbConfigPath());
  } catch {
    return false;
  }
}

/**
 * Validates the database config.
 */
export function validateDbConfig(raw: unknown): DbConfig {
  if (!Array.isArray(raw)) {
    throw new ConfigInvalidError('DB config must be a JSON array of database entries');
  }

  const projects = new Set<string>();
  const aliases = new Set<string>();

  for (let i = 0; i < raw.length; i++) {
    const entry = raw[i];
    if (typeof entry !== 'object' || entry === null) {
      throw new ConfigInvalidError(`DB entry at index ${i} is not a valid JSON object`);
    }

    const data = entry as Record<string, unknown>;

    const project = data.project_name;
    if (typeof project !== 'string' || !isValidIdentifier(project, 64) || project.includes(' ')) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Project name can only contain letters, numbers, hyphens, and underscores.`,
      );
    }
    if (projects.has(project)) {
      const aliasName = data.db_alias || 'unknown';
      throw new ConfigInvalidError(
        `Project "${project}" already has a database (${aliasName}). Schema Weaver enforces one database per project. Remove the existing entry first or use a different project name.`,
      );
    }
    projects.add(project);

    const alias = data.db_alias;
    if (typeof alias !== 'string' || !isValidIdentifier(alias, 64) || alias.includes(' ')) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Database alias can only contain letters, numbers, hyphens, and underscores.`,
      );
    }
    if (aliases.has(alias)) {
      throw new ConfigInvalidError(`Database alias "${alias}" already exists in config`);
    }
    aliases.add(alias);

    const host = data.host;
    if (
      typeof host !== 'string' ||
      host.trim().length === 0 ||
      (!isValidHostname(host) && !isValidIpv4(host) && !isValidIpv6(host))
    ) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Field "host" must be a valid hostname or IP address`,
      );
    }

    const port = data.port;
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Port must be between 1 and 65535.`,
      );
    }

    const db = data.database;
    if (typeof db !== 'string' || db.length === 0 || db.length > 63) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Database name must be 1-63 characters`,
      );
    }

    const user = data.user;
    if (typeof user !== 'string' || user.length === 0 || user.length > 63) {
      throw new ConfigInvalidError(`Entry at index ${i} invalid: Username must be 1-63 characters`);
    }

    const pwEnv = data.password_env;
    const pwStored = data.password_stored;
    if (pwEnv !== undefined && pwEnv !== null) {
      if (typeof pwEnv !== 'string' || !isValidEnvVarName(pwEnv)) {
        throw new ConfigInvalidError(
          `Entry at index ${i} invalid: password_env must be uppercase letters, digits, and underscores, starting with a letter.`,
        );
      }
    }
    if (pwStored !== undefined && pwStored !== null) {
      if (typeof pwStored !== 'string') {
        throw new ConfigInvalidError(
          `Entry at index ${i} invalid: password_stored must be a string.`,
        );
      }
    }
    if (!pwEnv && !pwStored) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: Either password_env or password_stored is required.`,
      );
    }

    const ssl = data.ssl_mode;
    if (ssl !== 'disable' && ssl !== 'require' && ssl !== 'verify-ca' && ssl !== 'verify-full') {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: ssl_mode must be disable, require, verify-ca, or verify-full`,
      );
    }

    const sslRoot = data.ssl_root_cert;
    if (sslRoot !== undefined && sslRoot !== null) {
      if (typeof sslRoot !== 'string') {
        throw new ConfigInvalidError(
          `Entry at index ${i} invalid: ssl_root_cert must be a string path or null`,
        );
      }
      if (!fs.existsSync(sslRoot)) {
        throw new ConfigInvalidError(
          `Entry at index ${i} invalid: ssl_root_cert path does not exist: ${sslRoot}`,
        );
      }
    }

    const perm = data.permission_override;
    if (perm !== undefined && perm !== null) {
      if (perm !== 'read_only' && perm !== 'auto_upgrade' && perm !== 'manual' && perm !== 'full') {
        throw new ConfigInvalidError(
          `Entry at index ${i} invalid: permission_override must be read_only, auto_upgrade, manual, full, or null`,
        );
      }
    }

    const created = data.created_at;
    if (typeof created !== 'string' || !isValidIso8601(created)) {
      throw new ConfigInvalidError(
        `Entry at index ${i} invalid: created_at must be a valid ISO 8601 string`,
      );
    }
  }

  return raw as DbConfig;
}

/**
 * Loads the database config. Returns empty array if file does not exist.
 */
export function loadDbConfig(): DbConfig {
  const p = getDbConfigPath();
  if (!fs.existsSync(p)) {
    return [];
  }
  let fileContent: string;
  try {
    fileContent = fs.readFileSync(p, 'utf8');
  } catch (err) {
    throw new ConfigError(
      'invalid',
      `Failed to read DB config file: ${err instanceof Error ? err.message : String(err)}`,
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

  return validateDbConfig(json);
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

/**
 * Saves the database config to disk with 0o600 permissions on POSIX.
 */
export function saveDbConfig(config: DbConfig): void {
  const p = getDbConfigPath();
  validateDbConfig(config);
  try {
    fs.writeFileSync(p, JSON.stringify(config, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch (err) {
    throw new ConfigError(
      'write_failed',
      `Failed to write DB config: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/**
 * Adds a database entry to config and saves it. Enforces one DB per project.
 */
export function addDbEntry(entry: Omit<DbEntry, 'created_at'>): DbEntry {
  const config = loadDbConfig();

  // One-DB-Per-Project rule
  const existingProj = config.find((e) => e.project_name === entry.project_name);
  if (existingProj) {
    throw new ConfigInvalidError(
      `Project "${entry.project_name}" already has a database (${existingProj.db_alias}). Schema Weaver enforces one database per project. Remove the existing entry first or use a different project name.`,
    );
  }

  // Alias uniqueness rule
  if (config.some((e) => e.db_alias === entry.db_alias)) {
    throw new ConfigInvalidError(`Database alias "${entry.db_alias}" already exists in config`);
  }

  const newEntry: DbEntry = {
    ...entry,
    created_at: new Date().toISOString(),
  };

  config.push(newEntry);
  saveDbConfig(config);
  return newEntry;
}

/**
 * Removes a database entry by its alias. Returns true if removed, false if not found.
 */
export function removeDbEntry(dbAlias: string): boolean {
  const config = loadDbConfig();
  const index = config.findIndex((e) => e.db_alias === dbAlias);
  if (index === -1) {
    return false;
  }
  config.splice(index, 1);
  saveDbConfig(config);
  return true;
}

/**
 * Finds a database entry by its alias.
 */
export function findDbEntry(dbAlias: string): DbEntry | null {
  const config = loadDbConfig();
  return config.find((e) => e.db_alias === dbAlias) || null;
}

/**
 * Finds a database entry by its project name.
 */
export function findDbByProject(projectName: string): DbEntry | null {
  const config = loadDbConfig();
  return config.find((e) => e.project_name === projectName) || null;
}

/**
 * Lists unique project names across all configured databases, sorted alphabetically.
 */
export function listProjects(): string[] {
  const config = loadDbConfig();
  const projects = config.map((e) => e.project_name);
  return Array.from(new Set(projects)).sort();
}

export interface DatabasesConfig {
  databases: DbEntry[];
}

export function loadDatabasesConfig(): DatabasesConfig {
  return {
    databases: loadDbConfig(),
  };
}
