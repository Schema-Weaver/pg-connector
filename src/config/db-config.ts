import * as fs from 'fs';
import * as crypto from 'crypto';
import { getDbConfigPath, getCredentialKeyPath } from './paths';
import { PermissionLevel } from '../permissions/checker';
import { atomicWriteFile, assertNotSymlink, withFileLock } from './atomic-write';
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
  /**
   * Password in cleartext. Present only in memory: the on-disk form is an
   * {@link EncryptedPassword} envelope (see `sealDbConfig`). A plain string is
   * still accepted on read so configs written by earlier versions load, and is
   * re-encrypted on the next write.
   */
  password_stored?: string;
  ssl_mode: 'disable' | 'require' | 'verify-ca' | 'verify-full';
  ssl_root_cert?: string | null; // path to CA cert, optional
  permission_override: PermissionLevel | null;
  created_at: string;
}

export type DbConfig = DbEntry[];

/**
 * Envelope written to disk in place of a cleartext password.
 * The plaintext never leaves the process; `ct` is AES-256-GCM output whose
 * authentication tag also covers the entry identity (AAD), so a ciphertext
 * cannot be moved between entries.
 */
export interface EncryptedPassword {
  v: 1;
  kdf: 'scrypt';
  iv: string; // base64, 12 random bytes
  tag: string; // base64, 16 bytes, GCM auth tag over ct + AAD
  ct: string; // base64 ciphertext
}

/** Entry identity an encrypted password is bound to. */
export interface PasswordBinding {
  db_alias: string;
  host: string;
  port: number;
  database: string;
  user: string;
}

const CIPHER = 'aes-256-gcm';
const KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const KEYFILE_MODE = 0o400;
const CONFIG_FILE_MODE = 0o600;

interface KeyMaterial {
  v: 1;
  kdf: 'scrypt';
  n: number;
  r: number;
  p: number;
  salt: string;
  key: string;
}

let derivedKeyCache: { fingerprint: string; key: Buffer } | null = null;

function isErrno(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code;
}

function encodeB64(buf: Buffer): string {
  return buf.toString('base64');
}

function decodeB64(value: string, expectedBytes: number, field: string): Buffer {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigInvalidError(`Stored password field "${field}" is not valid base64`);
  }
  const buf = Buffer.from(value, 'base64');
  if (buf.length !== expectedBytes || encodeB64(buf) !== value) {
    throw new ConfigInvalidError(
      `Stored password field "${field}" must be ${expectedBytes} base64-encoded bytes`,
    );
  }
  return buf;
}

/**
 * Builds the additional authenticated data for a stored password: the entry
 * identity. Serialised as a JSON array so no field value can shift the
 * boundaries of another one.
 */
export function buildPasswordAad(binding: PasswordBinding): string {
  return JSON.stringify([
    binding.db_alias,
    binding.host,
    binding.port,
    binding.database,
    binding.user,
  ]);
}

/**
 * True when a value is an encrypted-password envelope rather than cleartext.
 */
export function isEncryptedPassword(value: unknown): value is EncryptedPassword {
  if (typeof value !== 'object' || value === null) return false;
  const env = value as Record<string, unknown>;
  return (
    env.v === 1 &&
    env.kdf === 'scrypt' &&
    typeof env.iv === 'string' &&
    typeof env.tag === 'string' &&
    typeof env.ct === 'string' &&
    env.ct.length > 0
  );
}

function parseKeyMaterial(raw: string): KeyMaterial {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ConfigError('invalid', 'Credential key file is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new ConfigError('invalid', 'Credential key file is malformed');
  }
  const m = parsed as Record<string, unknown>;
  if (
    m.v !== 1 ||
    m.kdf !== 'scrypt' ||
    typeof m.n !== 'number' ||
    typeof m.r !== 'number' ||
    typeof m.p !== 'number' ||
    typeof m.salt !== 'string' ||
    typeof m.key !== 'string'
  ) {
    throw new ConfigError('invalid', 'Credential key file has an unsupported format');
  }
  if (m.n < 2 || m.r < 1 || m.p < 1) {
    throw new ConfigError('invalid', 'Credential key file has invalid KDF parameters');
  }
  decodeB64(m.salt, SALT_BYTES, 'salt');
  decodeB64(m.key, KEY_BYTES, 'key');
  return { v: 1, kdf: 'scrypt', n: m.n, r: m.r, p: m.p, salt: m.salt, key: m.key };
}

/**
 * Verifies the key file is owner-only and repairs the mode when it is not.
 * A key readable by other local users is a failed control, not a warning.
 */
function enforceKeyFileMode(keyPath: string): void {
  if (process.platform === 'win32') return;
  let mode: number;
  try {
    mode = fs.statSync(keyPath).mode & 0o777;
  } catch (err) {
    throw new ConfigError('invalid', `Failed to stat credential key file: ${errorText(err)}`);
  }
  if ((mode & 0o400) === 0o400 && (mode & 0o177) === 0) return;
  try {
    fs.chmodSync(keyPath, KEYFILE_MODE);
  } catch (err) {
    throw new ConfigError(
      'invalid',
      `Credential key file is not owner-only (mode ${mode.toString(8)}) and could not be repaired: ${errorText(err)}`,
    );
  }
  const repaired = fs.statSync(keyPath).mode & 0o777;
  if ((repaired & 0o400) !== 0o400 || (repaired & 0o177) !== 0) {
    throw new ConfigError(
      'invalid',
      `Credential key file is not owner-only (mode ${repaired.toString(8)})`,
    );
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function deriveKey(material: KeyMaterial, keyPath: string): Buffer {
  const fingerprint = `${keyPath}:${material.salt}:${material.key}:${material.n}:${material.r}:${material.p}`;
  if (derivedKeyCache && derivedKeyCache.fingerprint === fingerprint) {
    return derivedKeyCache.key;
  }
  const key = crypto.scryptSync(
    Buffer.from(material.key, 'base64'),
    Buffer.from(material.salt, 'base64'),
    KEY_BYTES,
    {
      N: material.n,
      r: material.r,
      p: material.p,
      maxmem: SCRYPT_MAXMEM,
    },
  );
  derivedKeyCache = { fingerprint, key };
  return key;
}

/**
 * Creates the machine-local key file if it is absent, racing other processes
 * safely: the file is created with O_EXCL, and a concurrent winner's file is
 * used instead of overwriting it.
 */
function createKeyFile(keyPath: string): KeyMaterial {
  const material: KeyMaterial = {
    v: 1,
    kdf: 'scrypt',
    n: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    salt: encodeB64(crypto.randomBytes(SALT_BYTES)),
    key: encodeB64(crypto.randomBytes(KEY_BYTES)),
  };

  let fd: number;
  try {
    fd = fs.openSync(keyPath, 'wx', KEYFILE_MODE);
  } catch (err) {
    if (isErrno(err, 'EEXIST')) {
      const existing = readKeyFile(keyPath);
      if (!existing) {
        throw new ConfigError('invalid', 'Credential key file disappeared while being created');
      }
      return existing;
    }
    throw new ConfigError(
      'write_failed',
      `Failed to create credential key file: ${errorText(err)}`,
    );
  }

  try {
    fs.writeSync(fd, `${JSON.stringify(material, null, 2)}\n`, null, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  try {
    fs.chmodSync(keyPath, KEYFILE_MODE);
  } catch (err) {
    if (process.platform !== 'win32') {
      throw new ConfigError(
        'write_failed',
        `Failed to restrict credential key file permissions: ${errorText(err)}`,
      );
    }
  }

  enforceKeyFileMode(keyPath);
  return material;
}

function readKeyFile(keyPath: string): KeyMaterial | null {
  // A planted symlink would hand the key to whoever owns the link target, so
  // refuse to follow one. Throws rather than returning null: the caller must
  // not fall back to creating a new key over an existing path.
  assertNotSymlink(keyPath);
  let raw: string;
  try {
    raw = fs.readFileSync(keyPath, 'utf8');
  } catch {
    return null;
  }
  const material = parseKeyMaterial(raw);
  enforceKeyFileMode(keyPath);
  return material;
}

/**
 * Loads the key file, creating it on first use. The derived key is cached for
 * the life of the process so repeated config reads cost one KDF run.
 */
export function loadCredentialKey(): Buffer {
  const keyPath = getCredentialKeyPath();
  if (!fs.existsSync(keyPath)) {
    return deriveKey(createKeyFile(keyPath), keyPath);
  }
  const material = readKeyFile(keyPath);
  if (!material) {
    throw new ConfigError('invalid', 'Credential key file could not be read');
  }
  return deriveKey(material, keyPath);
}

/**
 * Loads the key file for decryption only. Never creates it: a missing or
 * unreadable key for an existing encrypted config fails closed instead of
 * silently falling back to cleartext.
 */
function loadCredentialKeyForDecryption(keyPath: string): Buffer {
  if (!fs.existsSync(keyPath)) {
    throw new ConfigError(
      'invalid',
      `Credential key file is missing (${keyPath}). Stored database passwords cannot be decrypted.`,
    );
  }
  const material = readKeyFile(keyPath);
  if (!material) {
    throw new ConfigError(
      'invalid',
      `Credential key file is unreadable (${keyPath}). Stored database passwords cannot be decrypted.`,
    );
  }
  return deriveKey(material, keyPath);
}

/**
 * Encrypts a database password for storage. Generates a fresh random 96-bit
 * IV and authenticates the entry identity as AAD.
 */
export function encryptDbPassword(binding: PasswordBinding, plaintext: string): EncryptedPassword {
  const key = loadCredentialKey();
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(buildPasswordAad(binding), 'utf8'), {
    plaintextLength: Buffer.byteLength(plaintext, 'utf8'),
  });
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    v: 1,
    kdf: 'scrypt',
    iv: encodeB64(iv),
    tag: encodeB64(cipher.getAuthTag()),
    ct: encodeB64(ct),
  };
}

/**
 * Decrypts a stored database password. Throws when the envelope fails
 * authentication, which includes a ciphertext copied from another entry.
 */
export function decryptDbPassword(binding: PasswordBinding, env: EncryptedPassword): string {
  // Envelope shape is checked before the key is touched so a corrupt file
  // reports a corrupt file, not a missing key.
  const iv = decodeB64(env.iv, IV_BYTES, 'iv');
  const tag = decodeB64(env.tag, TAG_BYTES, 'tag');
  const ct = decodeB64(env.ct, ctLength(env.ct), 'ct');

  const key = loadCredentialKeyForDecryption(getCredentialKeyPath());
  const decipher = crypto.createDecipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(buildPasswordAad(binding), 'utf8'));
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    throw new ConfigError(
      'invalid',
      `Stored password for "${binding.db_alias}" failed authentication. The credential key does not match this entry, or the entry's host/port/database/user was changed outside the CLI. Re-set it with: sw-agent db edit ${binding.db_alias} --password <secret>`,
    );
  }
}

function ctLength(value: string): number {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigInvalidError('Stored password field "ct" is empty');
  }
  return Buffer.from(value, 'base64').length;
}

function bindingOf(entry: DbEntry): PasswordBinding {
  return {
    db_alias: entry.db_alias,
    host: entry.host,
    port: entry.port,
    database: entry.database,
    user: entry.user,
  };
}

/**
 * Replaces a stored cleartext password with its encrypted envelope. Returns the
 * on-disk shape, which is wider than {@link DbEntry}: `password_stored` is an
 * envelope on disk and cleartext only in memory.
 */
function sealEntryPasswords(entry: DbEntry): Record<string, unknown> {
  const stored = entry.password_stored as unknown;
  if (isEncryptedPassword(stored)) {
    return { ...entry };
  }
  if (typeof stored !== 'string' || stored.length === 0) {
    return { ...entry, password_stored: undefined };
  }
  return { ...entry, password_stored: encryptDbPassword(bindingOf(entry), stored) };
}

/** Replaces a stored envelope with its cleartext password, in memory only. */
function openEntryPasswords(entry: DbEntry): DbEntry {
  const stored = entry.password_stored as unknown;
  if (isEncryptedPassword(stored)) {
    return { ...entry, password_stored: decryptDbPassword(bindingOf(entry), stored) };
  }
  return entry;
}

/**
 * Encrypts every cleartext password in the config for storage.
 * Entries that already hold an envelope are passed through unchanged, so a
 * load/save round trip never double-encrypts.
 */
export function sealDbConfig(config: DbConfig): unknown[] {
  return config.map(sealEntryPasswords);
}

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
 * Accepts a cleartext `password_stored` (pre-encryption on-disk shape) or an
 * encrypted envelope; both are narrowed to cleartext in memory by
 * {@link loadDbConfig} and re-sealed by {@link saveDbConfig}.
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
      if (!isEncryptedPassword(pwStored)) {
        if (typeof pwStored !== 'string' || pwStored.length === 0) {
          throw new ConfigInvalidError(
            `Entry at index ${i} invalid: password_stored must be a non-empty string or an encrypted envelope.`,
          );
        }
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
 * Encrypted `password_stored` envelopes are decrypted in memory; a config
 * written by an earlier version (cleartext) is returned as-is and is upgraded
 * on the next save.
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
    throw new ConfigError('invalid', `Failed to read DB config file: ${errorText(err)}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(stripBom(fileContent));
  } catch (err) {
    throw new ConfigInvalidError(`Config file is not valid JSON: ${errorText(err)}`);
  }

  return validateDbConfig(json).map(openEntryPasswords);
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

/**
 * Saves the database config to disk with 0o600 permissions on POSIX.
 * Every cleartext `password_stored` is replaced by an encrypted envelope bound
 * to that entry's identity before anything is written.
 */
export function saveDbConfig(config: DbConfig): void {
  const p = getDbConfigPath();
  validateDbConfig(config);
  const sealed = sealDbConfig(config);
  try {
    atomicWriteFile(p, JSON.stringify(sealed, null, 2), CONFIG_FILE_MODE);
  } catch (err) {
    throw new ConfigError('write_failed', `Failed to write DB config: ${errorText(err)}`);
  }
}

/**
 * Runs a load → mutate → save cycle over databases.config.json under an
 * advisory lock, so two concurrent CLI invocations cannot lose one another's
 * update. `mutate` edits the array in place; its return value is passed back.
 */
export function mutateDbConfig<T>(mutate: (config: DbConfig) => T): T {
  return withFileLock(getDbConfigPath(), () => {
    const config = loadDbConfig();
    const result = mutate(config);
    saveDbConfig(config);
    return result;
  });
}

/**
 * Adds a database entry to config and saves it. Enforces one DB per project.
 */
export function addDbEntry(entry: Omit<DbEntry, 'created_at'>): DbEntry {
  return mutateDbConfig((config) => {
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
    return newEntry;
  });
}

/**
 * Removes a database entry by its alias. Returns true if removed, false if not found.
 */
export function removeDbEntry(dbAlias: string): boolean {
  return mutateDbConfig((config) => {
    const index = config.findIndex((e) => e.db_alias === dbAlias);
    if (index === -1) {
      return false;
    }
    config.splice(index, 1);
    return true;
  });
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
