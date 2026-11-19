import {
  ConfigInvalidError,
  isValidHostname,
  isValidIpv4,
  isValidIpv6,
} from '../config/schema';

/**
 * The database engines this connector can talk to.
 *
 * `postgres` is the default for entries written before the driver split, so an
 * existing `databases.config.json` keeps loading without a migration step.
 */
export type DbType = 'postgres' | 'mysql' | 'mongodb';

export const DB_TYPES: readonly DbType[] = ['postgres', 'mysql', 'mongodb'];

export function isDbType(value: unknown): value is DbType {
  return value === 'postgres' || value === 'mysql' || value === 'mongodb';
}

export function dbTypeOf(entry: { db_type?: DbType | null }): DbType {
  return entry.db_type ?? 'postgres';
}

export function defaultPortFor(type: DbType): number {
  switch (type) {
    case 'mysql':
      return 3306;
    case 'mongodb':
      return 27017;
    case 'postgres':
    default:
      return 5432;
  }
}

export const MONGODB_READ_PREFERENCES = [
  'primary',
  'primaryPreferred',
  'secondary',
  'secondaryPreferred',
  'nearest',
] as const;

export const MONGODB_READ_CONCERNS = ['local', 'available', 'majority', 'linearizable'] as const;

export type MongoReadPreference = (typeof MONGODB_READ_PREFERENCES)[number];
export type MongoReadConcern = (typeof MONGODB_READ_CONCERNS)[number];

function fail(index: number, message: string): never {
  throw new ConfigInvalidError(`Entry at index ${index} invalid: ${message}`);
}

/** Validate fields every driver shares. */
export function validateCommonFields(data: Record<string, unknown>, index: number): void {
  const host = data.host;
  if (
    typeof host !== 'string' ||
    host.trim().length === 0 ||
    (!isValidHostname(host) && !isValidIpv4(host) && !isValidIpv6(host))
  ) {
    fail(index, 'Field "host" must be a valid hostname or IP address');
  }

  const port = data.port;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
    fail(index, 'Port must be between 1 and 65535.');
  }

  const ssl = data.ssl_mode;
  if (ssl !== 'disable' && ssl !== 'require' && ssl !== 'verify-ca' && ssl !== 'verify-full') {
    fail(index, 'ssl_mode must be disable, require, verify-ca, or verify-full');
  }
}

/** Validate the fields that are specific to one engine. */
export function validateDriverFields(data: Record<string, unknown>, index: number): void {
  const type = data.db_type === undefined || data.db_type === null ? 'postgres' : data.db_type;
  if (!isDbType(type)) {
    fail(index, 'db_type must be postgres, mysql, or mongodb');
  }

  const database = data.database;
  const user = data.user;

  if (type === 'mysql') {
    if (typeof database !== 'string' || database.length === 0 || database.length > 64) {
      fail(index, 'Database name must be 1-64 characters');
    }
    if (typeof user !== 'string' || user.length === 0 || user.length > 128) {
      fail(index, 'Username must be 1-128 characters');
    }
    return;
  }

  if (type === 'mongodb') {
    if (typeof database !== 'string' || database.length === 0 || database.length > 63) {
      fail(index, 'Database name must be 1-63 characters');
    }
    if (typeof user !== 'string' || user.length === 0 || user.length > 128) {
      fail(index, 'Username must be 1-128 characters');
    }

    const srv = data.srv;
    if (srv !== undefined && typeof srv !== 'boolean') {
      fail(index, 'srv must be a boolean when present');
    }

    const authSource = data.auth_source;
    if (
      authSource !== undefined &&
      authSource !== null &&
      (typeof authSource !== 'string' || authSource.length === 0 || authSource.length > 63)
    ) {
      fail(index, 'auth_source must be 1-63 characters when present');
    }

    const readPreference = data.read_preference;
    if (
      readPreference !== undefined &&
      readPreference !== null &&
      !MONGODB_READ_PREFERENCES.includes(readPreference as MongoReadPreference)
    ) {
      fail(index, `read_preference must be one of ${MONGODB_READ_PREFERENCES.join(', ')}`);
    }

    const readConcern = data.read_concern;
    if (
      readConcern !== undefined &&
      readConcern !== null &&
      !MONGODB_READ_CONCERNS.includes(readConcern as MongoReadConcern)
    ) {
      fail(index, `read_concern must be one of ${MONGODB_READ_CONCERNS.join(', ')}`);
    }
    return;
  }

  if (typeof database !== 'string' || database.length === 0 || database.length > 63) {
    fail(index, 'Database name must be 1-63 characters');
  }
  if (typeof user !== 'string' || user.length === 0 || user.length > 63) {
    fail(index, 'Username must be 1-63 characters');
  }
}
