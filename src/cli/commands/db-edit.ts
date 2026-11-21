import {
  ask,
  askChoice,
  askSecret,
  closePrompts,
  isReplMode,
  isSecretRefusalError,
  refuseSecretInArgv,
  resolveSecret,
} from '../prompt';
import { findDbEntry, mutateDbConfig, DbEntry } from '../../config/db-config';
import {
  isValidIdentifier,
  isValidHostname,
  isValidIpv4,
  isValidIpv6,
  isValidEnvVarName,
  redactSecrets,
} from '../../config/schema';
import { PermissionLevel } from '../../config/machine-config';
import * as fs from 'fs';
import { C, S, check, separator, cross } from '../ui';
import {
  DB_TYPES,
  dbTypeOf,
  defaultPortFor,
  isDbType,
  maxDatabaseNameLength,
  maxUserNameLength,
  MONGODB_READ_CONCERNS,
  MONGODB_READ_PREFERENCES,
  validateCommonFields,
  validateDriverFields,
  type DbType,
  type MongoReadConcern,
  type MongoReadPreference,
} from '../../drivers/config-shape';

function exit_(code: number): never {
  closePrompts();
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

function findFlag(args: string[], ...names: string[]): string | undefined {
  for (const name of names) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length && !args[idx + 1].startsWith('-')) {
      return args[idx + 1];
    }
  }
  return undefined;
}

function hasAnyFlag(args: string[], ...names: string[]): boolean {
  return names.some((name) => args.includes(name));
}

function printRefusal(err: unknown): void {
  if (isSecretRefusalError(err)) {
    console.log(`  ${C.red(S.cross)} ${C.bold(err.code)}`);
    for (const line of err.lines) {
      console.log(`    ${C.dim(line)}`);
    }
    return;
  }
  console.log(`  ${C.red(S.cross)} ${err instanceof Error ? err.message : String(err)}`);
}

/**
 * Keep engine-specific fields coherent when an entry changes engine.
 *
 * A postgres/mysql entry must not retain MongoDB-only settings, and a MongoDB
 * entry needs defaults for the settings the driver always applies.
 */
function normaliseEngineFields(entry: Partial<DbEntry>, type: DbType): void {
  if (type === 'mongodb') {
    entry.srv = entry.srv ?? false;
    entry.auth_source = entry.auth_source ?? entry.database ?? null;
    entry.read_preference = entry.read_preference ?? 'primary';
    entry.read_concern = entry.read_concern ?? 'local';
    return;
  }
  entry.srv = undefined;
  entry.auth_source = undefined;
  entry.read_preference = undefined;
  entry.read_concern = undefined;
}

function validateCandidate(candidate: DbEntry): void {
  const data = candidate as unknown as Record<string, unknown>;
  validateCommonFields(data, 0);
  validateDriverFields(data, 0);
}

export async function runDbEdit(args: string[]): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log();
    console.log(`  ${C.bold('Edit Database Configuration')}`);
    console.log();
    console.log(`  ${C.yellow('Usage:')} ${C.white('db edit <alias>')} [options]`);
    console.log();
    console.log(`  ${C.bold('Engines:')} ${C.cyan('postgres')}, ${C.cyan('mysql')}, ${C.cyan('mongodb')}`);
    console.log();
    console.log(`  ${C.bold('Options (non-interactive):')}`);
    console.log(`    ${C.cyan('--type <engine>')}        Engine: postgres, mysql or mongodb`);
    console.log(`    ${C.cyan('--host <host>')}          Host name or IP address`);
    console.log(`    ${C.cyan('--port <port>')}          Port (defaults: 5432/3306/27017 by engine)`);
    console.log(`    ${C.cyan('--database <name>')}      Database name`);
    console.log(`    ${C.cyan('--user <username>')}      Database user`);
    console.log(`    ${C.cyan('--password-file <path>')} Read the password from a file (0600)`);
    console.log(`    ${C.cyan('--password-stdin')}       Read the password from stdin`);
    console.log(`    ${C.dim('--password / --pw are REFUSED: process.argv is readable by every local user.')}`);
    console.log(`    ${C.dim('Use $SW_AGENT_DB_PASSWORD, --password-file, --password-stdin or --env <var>.')}`);
    console.log(`    ${C.cyan('--env <var_name>')}       Use environment variable for password`);
    console.log(`    ${C.cyan('--ssl <mode>')}           SSL mode (disable, require, verify-ca, verify-full)`);
    console.log(`    ${C.cyan('--cert <path>')}          Path to CA root certificate`);
    console.log(`    ${C.cyan('--permission <level>')}   Permission override (read_only, auto_upgrade, manual, full)`);
    console.log(`    ${C.cyan('--project <name>')}       Project name`);
    console.log();
    console.log(`  ${C.bold('MongoDB-only options:')}`);
    console.log(`    ${C.cyan('--srv | --no-srv')}       Use or disable mongodb+srv:// discovery`);
    console.log(`    ${C.cyan('--auth-source <db>')}     Authentication database`);
    console.log(`    ${C.cyan('--read-preference <mode>')} ${C.dim(MONGODB_READ_PREFERENCES.join(', '))}`);
    console.log(`    ${C.cyan('--read-concern <level>')}   ${C.dim(MONGODB_READ_CONCERNS.join(', '))}`);
    console.log();
    exit_(0);
  }

  const alias = args.find((a) => !a.startsWith('-'));
  if (!alias) {
    console.log();
    console.log(`  ${C.yellow('Usage:')} ${C.white('db edit <alias>')} [options]`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db edit --help')} ${C.dim('for available flags.')}\n`);
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}`);
    exit_(1);
  }

  const found = entry as DbEntry;
  const newEntry: Partial<DbEntry> = { ...found };

  // Check if non-interactive flags are provided
  const flagType = findFlag(args, '--type', '--engine');
  const flagHost = findFlag(args, '--host', '-h');
  const flagPort = findFlag(args, '--port', '-p');
  const flagDb = findFlag(args, '--database', '-d', '--db');
  const flagUser = findFlag(args, '--user', '-u');
  const flagEnv = findFlag(args, '--env', '--password-env');
  const flagSsl = findFlag(args, '--ssl', '--ssl-mode');
  const flagCert = findFlag(args, '--cert', '--ssl-cert');
  const flagPerm = findFlag(args, '--permission', '--perm');
  const flagProject = findFlag(args, '--project');
  const flagAuthSource = findFlag(args, '--auth-source');
  const flagReadPref = findFlag(args, '--read-preference');
  const flagReadConcern = findFlag(args, '--read-concern');
  const flagSrv = args.includes('--srv');
  const flagNoSrv = args.includes('--no-srv');

  const hasPasswordFlag =
    args.includes('--password-file') || args.includes('--password-stdin');

  const hasFlags = Boolean(
    flagType ||
      flagHost ||
      flagPort ||
      flagDb ||
      flagUser ||
      hasPasswordFlag ||
      flagEnv ||
      flagSsl ||
      flagCert ||
      flagPerm ||
      flagProject ||
      flagAuthSource ||
      flagReadPref ||
      flagReadConcern ||
      flagSrv ||
      flagNoSrv,
  );

  function persist(): void {
    mutateDbConfig((current) => {
      const at = current.findIndex((e) => e.db_alias === alias);
      if (at !== -1) {
        current[at] = {
          ...found,
          ...newEntry,
          created_at: found.created_at,
        } as DbEntry;
      }
    });
  }

  if (hasAnyFlag(args, '--password', '--pw')) {
    printRefusal(
      refuseSecretInArgv(['--password', '--pw'], 'database password', [
        '$SW_AGENT_DB_PASSWORD <value>',
        '--password-file <path>',
        '--password-stdin',
        '--env <var>',
      ]),
    );
    exit_(1);
  }

  if (hasFlags) {
    const updatedFields: string[] = [];

    if (flagType !== undefined) {
      if (!isDbType(flagType)) {
        console.log(`  ${C.red(S.cross)} --type must be one of ${DB_TYPES.join(', ')}.`);
        exit_(1);
      }
      if (flagType !== dbTypeOf(found)) {
        newEntry.db_type = flagType;
        normaliseEngineFields(newEntry, flagType);
      }
      updatedFields.push('db_type');
    }

    const targetType = dbTypeOf(newEntry);

    if (flagProject !== undefined) {
      if (!isValidIdentifier(flagProject, 64) || flagProject.includes(' ')) {
        console.log(`  ${C.red(S.cross)} Invalid project name: ${flagProject}`);
        exit_(1);
      }
      newEntry.project_name = flagProject;
      updatedFields.push('project_name');
    }

    if (flagHost !== undefined) {
      if (!isValidHostname(flagHost) && !isValidIpv4(flagHost) && !isValidIpv6(flagHost)) {
        console.log(`  ${C.red(S.cross)} Invalid host: ${flagHost}`);
        exit_(1);
      }
      newEntry.host = flagHost;
      updatedFields.push('host');
    }

    if (flagPort !== undefined) {
      const p = parseInt(flagPort, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        console.log(`  ${C.red(S.cross)} Invalid port (1-65535): ${flagPort}`);
        exit_(1);
      }
      newEntry.port = p;
      updatedFields.push('port');
    }

    if (flagDb !== undefined) {
      const maxLength = maxDatabaseNameLength(targetType);
      if (flagDb.length > maxLength || flagDb.trim() === '') {
        console.log(`  ${C.red(S.cross)} Invalid database name (max ${maxLength}): ${flagDb}`);
        exit_(1);
      }
      newEntry.database = flagDb;
      updatedFields.push('database');
    }

    if (flagUser !== undefined) {
      const maxLength = maxUserNameLength(targetType);
      if (flagUser.length > maxLength || flagUser.trim() === '') {
        console.log(`  ${C.red(S.cross)} Invalid username (max ${maxLength}): ${flagUser}`);
        exit_(1);
      }
      newEntry.user = flagUser;
      updatedFields.push('user');
    }

    if (hasPasswordFlag) {
      let supplied: string | undefined;
      try {
        supplied = (
          await resolveSecret({
            args,
            label: 'Database password',
            argvFlags: ['--password', '--pw'],
            fileFlags: ['--password-file'],
            stdinFlags: ['--password-stdin'],
          })
        ).value;
      } catch (err) {
        printRefusal(err);
        exit_(1);
      }
      if (!supplied) {
        console.log(`  ${C.red(S.cross)} No password received.`);
        exit_(1);
      }
      newEntry.password_stored = supplied;
      newEntry.password_env = undefined;
      updatedFields.push('password (stored)');
    } else if (flagEnv !== undefined) {
      if (!isValidEnvVarName(flagEnv)) {
        console.log(`  ${C.red(S.cross)} Invalid environment variable name: ${flagEnv}`);
        exit_(1);
      }
      newEntry.password_env = flagEnv;
      newEntry.password_stored = undefined;
      updatedFields.push(`password (env: $${flagEnv})`);
    }

    if (flagSsl !== undefined) {
      if (!['disable', 'require', 'verify-ca', 'verify-full'].includes(flagSsl)) {
        console.log(
          `  ${C.red(S.cross)} Invalid SSL mode (disable, require, verify-ca, verify-full): ${flagSsl}`,
        );
        exit_(1);
      }
      newEntry.ssl_mode = flagSsl as DbEntry['ssl_mode'];
      updatedFields.push('ssl_mode');
    }

    if (flagCert !== undefined) {
      if (flagCert === '' || flagCert === 'none') {
        newEntry.ssl_root_cert = null;
      } else if (fs.existsSync(flagCert)) {
        newEntry.ssl_root_cert = flagCert;
      } else {
        console.log(`  ${C.red(S.cross)} SSL certificate file not found: ${flagCert}`);
        exit_(1);
      }
      updatedFields.push('ssl_root_cert');
    }

    if (
      targetType !== 'mongodb' &&
      (flagSrv || flagNoSrv || flagAuthSource || flagReadPref || flagReadConcern)
    ) {
      console.log(
        `  ${C.red(S.cross)} --srv, --auth-source, --read-preference and --read-concern are MongoDB-only.`,
      );
      exit_(1);
    }

    if (targetType === 'mongodb') {
      if (flagSrv || flagNoSrv) {
        newEntry.srv = flagSrv;
        updatedFields.push('srv');
      }
      if (flagAuthSource !== undefined) {
        if (flagAuthSource.length === 0 || flagAuthSource.length > 63) {
          console.log(`  ${C.red(S.cross)} Auth source must be 1-63 characters.`);
          exit_(1);
        }
        newEntry.auth_source = flagAuthSource;
        updatedFields.push('auth_source');
      }
      if (flagReadPref !== undefined) {
        if (!MONGODB_READ_PREFERENCES.includes(flagReadPref as MongoReadPreference)) {
          console.log(
            `  ${C.red(S.cross)} Read preference must be one of ${MONGODB_READ_PREFERENCES.join(', ')}.`,
          );
          exit_(1);
        }
        newEntry.read_preference = flagReadPref as MongoReadPreference;
        updatedFields.push('read_preference');
      }
      if (flagReadConcern !== undefined) {
        if (!MONGODB_READ_CONCERNS.includes(flagReadConcern as MongoReadConcern)) {
          console.log(
            `  ${C.red(S.cross)} Read concern must be one of ${MONGODB_READ_CONCERNS.join(', ')}.`,
          );
          exit_(1);
        }
        newEntry.read_concern = flagReadConcern as MongoReadConcern;
        updatedFields.push('read_concern');
      }
    }

    if (flagPerm !== undefined) {
      if (flagPerm === 'default' || flagPerm === 'none') {
        newEntry.permission_override = null;
      } else if (['read_only', 'auto_upgrade', 'manual', 'full'].includes(flagPerm)) {
        newEntry.permission_override = flagPerm as PermissionLevel;
      } else {
        console.log(
          `  ${C.red(S.cross)} Invalid permission (read_only, auto_upgrade, manual, full, default): ${flagPerm}`,
        );
        exit_(1);
      }
      updatedFields.push('permission');
    }

    const candidate = {
      ...found,
      ...newEntry,
      created_at: found.created_at,
    } as DbEntry;
    try {
      validateCandidate(candidate);
    } catch (err) {
      console.log(`  ${C.red(S.cross)} ${err instanceof Error ? err.message : String(err)}`);
      exit_(1);
    }

    try {
      persist();
    } catch (err) {
      console.log(
        `  ${C.red(S.cross)} Failed to save: ${redactSecrets(err instanceof Error ? err.message : String(err), newEntry.password_stored)}`,
      );
      exit_(1);
    }

    if (updatedFields.length > 0) {
      console.log();
      console.log(`  ${check(`Database "${C.cyan(alias)}" updated successfully.`)}`);
      console.log();
      console.log(`  ${C.bold('Updated fields:')}`);
      for (const f of updatedFields) {
        console.log(`    ${C.cyan(S.dot)} ${C.white(f)}`);
      }
      console.log();
    }
    exit_(0);
  }

  // Interactive flow
  console.log();
  console.log(C.bold(C.brand(`  Edit database: ${C.white(alias)}`)));
  console.log(separator('', 50));
  console.log();

  // Ask which field(s) to edit — skip if only one field is requested.
  const field = args[1];
  let fieldsToEdit: readonly string[];
  if (field && (VALID_FIELDS as readonly string[]).includes(field)) {
    fieldsToEdit = [field];
  } else {
    const choice = await askChoice(
      'Which field to edit?',
      [...VALID_FIELDS, 'all'] as string[],
      'all',
    );
    fieldsToEdit = choice === 'all' ? VALID_FIELDS : ([choice] as const);
  }

  if (fieldsToEdit.includes('db_type')) {
    const engine = await askChoice('Database engine', [...DB_TYPES], dbTypeOf(found));
    if (isDbType(engine)) {
      newEntry.db_type = engine;
      normaliseEngineFields(newEntry, engine);
    }
  }

  const targetType = dbTypeOf(newEntry);

  if (fieldsToEdit.includes('project_name')) {
    const val = await ask(`Project name`, found.project_name);
    if (val && isValidIdentifier(val, 64)) newEntry.project_name = val;
    else console.log(`  ${cross('Invalid, keeping current.')}`);
  }
  if (fieldsToEdit.includes('host')) {
    const val = await ask(`Host`, found.host);
    if (val && (isValidHostname(val) || isValidIpv4(val) || isValidIpv6(val)))
      newEntry.host = val;
    else console.log(`  ${cross('Invalid, keeping current.')}`);
  }
  if (fieldsToEdit.includes('port')) {
    const val = await ask(`Port (default ${defaultPortFor(targetType)})`, String(found.port));
    const num = parseInt(val, 10);
    if (!isNaN(num) && num >= 1 && num <= 65535) newEntry.port = num;
    else console.log(`  ${cross('Invalid, keeping current.')}`);
  }
  if (fieldsToEdit.includes('database')) {
    const maxLength = maxDatabaseNameLength(targetType);
    const val = await ask(`Database name`, found.database);
    if (val && val.length <= maxLength) newEntry.database = val;
    else console.log(`  ${cross(`Invalid (max ${maxLength}), keeping current.`)}`);
  }
  if (fieldsToEdit.includes('user')) {
    const maxLength = maxUserNameLength(targetType);
    const val = await ask(`Username`, found.user);
    if (val && val.length <= maxLength) newEntry.user = val;
    else console.log(`  ${cross(`Invalid (max ${maxLength}), keeping current.`)}`);
  }
  if (fieldsToEdit.includes('password')) {
    const pwChoice = await askChoice(
      'Password',
      ['Keep current', 'Use environment variable', 'Enter new password'],
      'Keep current',
    );
    if (pwChoice === 'Use environment variable') {
      const envVar = await ask('Env var name', found.password_env || 'DB_PASSWORD');
      if (isValidEnvVarName(envVar)) {
        newEntry.password_env = envVar;
        newEntry.password_stored = undefined;
      } else {
        console.log(`  ${cross('Invalid env var name, keeping current.')}`);
      }
    } else if (pwChoice === 'Enter new password') {
      const pw = await askSecret('Password');
      newEntry.password_stored = pw;
      newEntry.password_env = undefined;
    }
  }
  if (fieldsToEdit.includes('ssl')) {
    const newSsl = await askChoice(
      'SSL mode',
      ['disable', 'require', 'verify-ca', 'verify-full'],
      found.ssl_mode,
    );
    newEntry.ssl_mode = newSsl as DbEntry['ssl_mode'];

    if (newEntry.ssl_mode !== 'disable') {
      const cert = await ask('SSL root cert path', found.ssl_root_cert || '');
      if (cert.trim() === '') {
        newEntry.ssl_root_cert = null;
      } else if (fs.existsSync(cert)) {
        newEntry.ssl_root_cert = cert;
      } else {
        console.log(`  ${C.yellow(S.warning)} Cert file not found. Keeping existing.`);
      }
    } else {
      newEntry.ssl_root_cert = null;
    }
  }

  if (targetType === 'mongodb') {
    if (fieldsToEdit.includes('srv')) {
      newEntry.srv = await askChoice('Use mongodb+srv://?', ['no', 'yes'], newEntry.srv ? 'yes' : 'no') === 'yes';
    }
    if (fieldsToEdit.includes('auth_source')) {
      const authSource = await ask('Auth source database', newEntry.auth_source || found.database);
      if (authSource && authSource.length <= 63) newEntry.auth_source = authSource;
      else console.log(`  ${cross('Invalid, keeping current.')}`);
    }
    if (fieldsToEdit.includes('read_preference')) {
      newEntry.read_preference = (await askChoice(
        'Read preference',
        [...MONGODB_READ_PREFERENCES],
        newEntry.read_preference || 'primary',
      )) as MongoReadPreference;
    }
    if (fieldsToEdit.includes('read_concern')) {
      newEntry.read_concern = (await askChoice(
        'Read concern',
        [...MONGODB_READ_CONCERNS],
        newEntry.read_concern || 'local',
      )) as MongoReadConcern;
    }
  } else if (
    fieldsToEdit.some((f) =>
      ['srv', 'auth_source', 'read_preference', 'read_concern'].includes(f),
    )
  ) {
    console.log(`  ${C.yellow(S.warning)} MongoDB-only fields were skipped for engine '${targetType}'.`);
  }

  if (fieldsToEdit.includes('permission')) {
    const perm = await askChoice(
      'Permission',
      ['read_only', 'auto_upgrade', 'manual', 'full', 'use default'],
      found.permission_override || 'use default',
    );
    newEntry.permission_override = perm === 'use default' ? null : (perm as PermissionLevel);
  }

  const updatedEntry: DbEntry = {
    ...found,
    ...newEntry,
    created_at: found.created_at,
  };

  try {
    validateCandidate(updatedEntry);
  } catch (err) {
    console.log(`  ${C.red(S.cross)} ${err instanceof Error ? err.message : String(err)}`);
    exit_(1);
  }

  try {
    persist();
  } catch (err) {
    console.log(
      `  ${C.red(S.cross)} Error: ${redactSecrets(err instanceof Error ? err.message : String(err), newEntry.password_stored)}`,
    );
    exit_(1);
  }

  console.log();
  console.log(`  ${check('Database updated successfully.')}`);
  console.log();
  console.log(`  ${C.bold('Updated fields:')}`);
  for (const f of fieldsToEdit) {
    const label = FIELD_LABELS[f] || f;
    if (f === 'password') {
      console.log(
        `    ${C.bold(label.padEnd(14))} ${C.white(newEntry.password_env ? `$${newEntry.password_env}` : 'stored (AES-256-GCM at rest)')}`,
      );
      continue;
    }
    const val = updatedEntry[f as keyof DbEntry];
    console.log(`    ${C.bold(label.padEnd(14))} ${C.white(String(val ?? 'default'))}`);
  }
  console.log();
  exit_(0);
}

const VALID_FIELDS = [
  'db_type',
  'project_name',
  'host',
  'port',
  'database',
  'user',
  'password',
  'ssl',
  'srv',
  'auth_source',
  'read_preference',
  'read_concern',
  'permission',
] as const;

const FIELD_LABELS: Record<string, string> = {
  db_type: 'Engine',
  project_name: 'Project',
  host: 'Host',
  port: 'Port',
  database: 'Database',
  user: 'User',
  password: 'Password',
  ssl: 'SSL',
  srv: 'SRV',
  auth_source: 'Auth Source',
  read_preference: 'Read Pref.',
  read_concern: 'Read Concern',
  permission: 'Permission',
};
