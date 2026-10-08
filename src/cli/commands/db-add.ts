import {
  ask,
  askConfirm,
  askSecret,
  askChoice,
  closePrompts,
  isReplMode,
  isSecretRefusalError,
  assertUrlHasNoPassword,
  redactUrlPassword,
  refuseSecretInArgv,
  resolveSecret,
  type SecretSource,
} from '../prompt';
import { machineConfigExists } from '../../config/machine-config';
import { addDbEntry, findDbByProject, removeDbEntry, DbEntry } from '../../config/db-config';
import {
  isValidIdentifier,
  isValidHostname,
  isValidIpv4,
  isValidIpv6,
  isValidEnvVarName,
  redactSecrets,
} from '../../config/schema';
import { PermissionLevel } from '../../config/machine-config';
import { Pool, PoolConfig } from 'pg';
import * as fs from 'fs';
import { C, S, check, separator, createSpinner } from '../ui';
import { buildSslConfig } from '../../execution/pool';

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

/** True when any of `names` appears in `args`, with or without a value. */
function hasAnyFlag(args: string[], ...names: string[]): boolean {
  return names.some((name) => args.includes(name));
}

/**
 * One-shot password channel read from the environment.
 *
 * `/proc/<pid>/environ` is mode 0400 and owned by the process's own user, so
 * unlike argv it is NOT readable by another local UID, and the value never
 * enters `ps` output, the shell history or a CI command echo. `SW_AGENT_DB_PASSWORD=x
 * sw-agent db add …` is therefore a genuine secret channel, and the only one
 * that needs no file and no TTY.
 *
 * Checked before the interactive prompt so a scripted `db add` is unattended,
 * and never echoed, never passed to a child process, and never written to any
 * log: the NAME is safe to print, the VALUE is not.
 */
export const DB_PASSWORD_ENV_VAR = 'SW_AGENT_DB_PASSWORD';

/** The argv flags this command no longer accepts, named so the refusal can. */
const REFUSED_PASSWORD_ARGV_FLAGS = ['--password', '--pw'] as const;

function readDbPasswordFromEnv(): string | undefined {
  const value = process.env[DB_PASSWORD_ENV_VAR];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Renders a refusal so its machine-readable code is on its own greppable line. */
function printSecretRefusal(err: unknown): void {
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
 * Describes where the password came from without ever naming its value.
 *
 * `--env` stores a VARIABLE NAME and reads the value at connect time, so that
 * case is reported as an env reference. `SW_AGENT_DB_PASSWORD` was read once at
 * `db add` time, so the value is now encrypted at rest like any other stored
 * password — reporting it as "stored" rather than "env" keeps that honest.
 */
function describePasswordSource(
  passwordEnv: string | undefined,
  source: SecretSource | undefined,
): string {
  if (passwordEnv) return C.green(`env ($${passwordEnv}, read at connect time)`);
  if (source === 'env') return C.green(`env ($${DB_PASSWORD_ENV_VAR}, read once)`);
  return C.yellow('stored (AES-256-GCM at rest)');
}

export async function runDbAdd(args: string[] = []): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log();
    console.log(`  ${C.bold('Add a Database')}`);
    console.log();
    console.log(`  ${C.bold('Interactive Mode:')}`);
    console.log(`    ${C.cyan('db add')}`);
    console.log(
      `    ${C.dim('Password is asked for with a masked prompt; it never touches argv.')}`,
    );
    console.log();
    console.log(`  ${C.bold('Non-Interactive via URL:')}`);
    console.log(
      `    ${C.cyan('db add --url-file <path> [--url-stdin] [--alias <alias>] [--project <proj>]')}`,
    );
    console.log(`    ${C.cyan('db add --url postgresql://user@host:5432/dbname')}`);
    console.log(
      `    ${C.dim('(a --url carrying a password is refused: it would put it in process.argv)')}`,
    );
    console.log();
    console.log(`  ${C.bold('Non-Interactive via Flags:')}`);
    console.log(
      `    ${C.cyan('db add --alias <a> --project <p> --host <h> --port <p> --database <d> --user <u>')}`,
    );
    console.log(
      `    ${C.cyan('       [--password-file <path> | --password-stdin | --env <var>] [--ssl <mode>] [--cert <path>]')}`,
    );
    console.log(`    ${C.cyan('       [--permission <level>] [--no-test]')}`);
    console.log();
    console.log(`  ${C.bold('Password sources, safest first:')}`);
    console.log(
      `    ${C.cyan(`$${DB_PASSWORD_ENV_VAR}=… db add …`)}  Read the password from the environment (never argv)`,
    );
    console.log(
      `    ${C.cyan('--password-file <path>')}  Read the password from a file; the file must be mode 0600 and not a symlink`,
    );
    console.log(`    ${C.cyan('--password-stdin')}       Read the password from stdin`);
    console.log(
      `    ${C.cyan('--env <var>')}            Store an environment VARIABLE NAME and read the value at connect time`,
    );
    console.log(
      `    ${C.dim('--password / --pw are REFUSED: process.argv is readable by every local user via')}`,
    );
    console.log(
      `    ${C.dim('/proc/<pid>/cmdline and is kept in your shell history. --url with a password is')}`,
    );
    console.log(
      `    ${C.dim('refused too; use --url with no password plus one of the sources above.')}`,
    );
    console.log();
    exit_(0);
  }

  if (!machineConfigExists()) {
    console.log(`  ${C.red(S.cross)} Error: Run ${C.cyan('init')} first.`);
    exit_(1);
  }

  // Check if non-interactive flags or URL are provided
  const flagAlias = findFlag(args, '--alias', '-a');
  const flagProject = findFlag(args, '--project', '-p');
  const flagHost = findFlag(args, '--host', '-h');
  const flagPort = findFlag(args, '--port');
  const flagDatabase = findFlag(args, '--database', '-d', '--db');
  const flagUser = findFlag(args, '--user', '-u');
  const flagEnv = findFlag(args, '--env', '--password-env');
  const flagSsl = findFlag(args, '--ssl', '--ssl-mode');
  const flagCert = findFlag(args, '--cert');
  const flagPerm = findFlag(args, '--permission', '--perm');
  const skipTest = args.includes('--no-test') || args.includes('--skip-test');

  const hasUrlArg = args.some((a) => a === '--url' || a === '--url-file' || a === '--url-stdin');
  const hasNonInteractiveArgs = Boolean(
    hasUrlArg || flagHost || flagDatabase || (flagAlias && flagProject),
  );

  if (hasNonInteractiveArgs) {
    let passwordStored: string | undefined;
    let passwordSource: SecretSource | undefined;
    const passwordEnv = flagEnv;
    let urlArg: string | undefined;

    // Refuse `--password`/`--pw` before anything else touches them. Checked
    // here as well as inside `resolveSecret` so the refusal names the flag even
    // when the URL channel is what the operator also supplied: a value in argv
    // is exposed whether or not the rest of the command succeeds.
    if (hasAnyFlag(args, ...REFUSED_PASSWORD_ARGV_FLAGS)) {
      printSecretRefusal(
        refuseSecretInArgv(REFUSED_PASSWORD_ARGV_FLAGS, 'database password', [
          `$${DB_PASSWORD_ENV_VAR} <value>`,
          '--password-file <path>',
          '--password-stdin',
          '--env <var>',
        ]),
      );
      exit_(1);
    }

    try {
      urlArg = (
        await resolveSecret({
          args,
          label: 'Connection URL',
          // `--url` is the one argv value still accepted, and only because a URL
          // without userinfo is not a credential. This assertion refuses a URL
          // with an embedded password — percent-encoded or not — and echoes it
          // back redacted.
          argvFlags: ['--url'],
          assertArgvValueSafe: assertUrlHasNoPassword,
          fileFlags: ['--url-file'],
          stdinFlags: ['--url-stdin'],
        })
      ).value;

      if (!passwordEnv) {
        // The environment is checked BEFORE the interactive prompt and before
        // any file/stdin flag, so `SW_AGENT_DB_PASSWORD=x sw-agent db add …` is
        // the unattended channel, and it is the one that cannot leak to another
        // local UID through /proc/<pid>/cmdline.
        const fromEnv = hasAnyFlag(args, '--password-file', '--password-stdin')
          ? undefined
          : readDbPasswordFromEnv();
        if (fromEnv !== undefined) {
          passwordStored = fromEnv;
          passwordSource = 'env';
        } else {
          const secret = await resolveSecret({
            args,
            label: 'Database password',
            argvFlags: REFUSED_PASSWORD_ARGV_FLAGS,
            fileFlags: ['--password-file'],
            stdinFlags: ['--password-stdin'],
            promptWhenMissing: true,
          });
          passwordStored = secret.value;
          passwordSource = secret.source;
        }
      }
    } catch (err) {
      printSecretRefusal(err);
      exit_(1);
    }

    let host = flagHost || 'localhost';
    let port = flagPort ? parseInt(flagPort, 10) : 5432;
    let database = flagDatabase || '';
    let user = flagUser || 'postgres';
    let sslMode: DbEntry['ssl_mode'] = (flagSsl as DbEntry['ssl_mode']) || 'require';
    const sslCert: string | null = flagCert || null;

    if (urlArg) {
      try {
        const u = new URL(urlArg);
        if (u.protocol !== 'postgres:' && u.protocol !== 'postgresql:') {
          console.log(`  ${C.red(S.cross)} URL must begin with postgres:// or postgresql://`);
          exit_(1);
        }
        host = u.hostname || host;
        port = u.port ? parseInt(u.port, 10) : port;
        database = u.pathname ? u.pathname.replace(/^\//, '') : database;
        user = decodeURIComponent(u.username || user);
        if (u.password) {
          // Unreachable: `assertUrlHasNoPassword` refused this value before it
          // was returned. Kept as a fail-closed backstop so no future caller of
          // `resolveSecret` can reintroduce the argv password path.
          printSecretRefusal(assertUrlHasNoPassword(urlArg));
          exit_(1);
        }
        const sslParam = u.searchParams.get('sslmode');
        if (sslParam && ['disable', 'require', 'verify-ca', 'verify-full'].includes(sslParam)) {
          sslMode = sslParam as DbEntry['ssl_mode'];
        }
      } catch (err: unknown) {
        // The URL is echoed redacted: an invalid URL can still be
        // userinfo-bearing, and Node puts the offending input on the error.
        console.log(
          `  ${C.red(S.cross)} Invalid connection URL: ${redactSecrets(
            redactUrlPassword(err instanceof Error ? err.message : String(err)),
          )}`,
        );
        exit_(1);
      }
    }

    const dbAlias = flagAlias || database || 'db';
    const projectName = flagProject || dbAlias;

    if (!isValidIdentifier(dbAlias, 64) || dbAlias.includes(' ')) {
      console.log(
        `  ${C.red(S.cross)} Invalid database alias: "${dbAlias}". Must be 1-64 alphanumeric/dash characters without spaces.`,
      );
      exit_(1);
    }

    if (!isValidIdentifier(projectName, 64) || projectName.includes(' ')) {
      console.log(
        `  ${C.red(S.cross)} Invalid project name: "${projectName}". Must be 1-64 alphanumeric/dash characters without spaces.`,
      );
      exit_(1);
    }

    if (!isValidHostname(host) && !isValidIpv4(host) && !isValidIpv6(host)) {
      console.log(`  ${C.red(S.cross)} Invalid host: "${host}"`);
      exit_(1);
    }

    if (isNaN(port) || port < 1 || port > 65535) {
      console.log(`  ${C.red(S.cross)} Invalid port: "${port}"`);
      exit_(1);
    }

    if (!database || database.length > 63) {
      console.log(`  ${C.red(S.cross)} Database name is required and must be <= 63 characters.`);
      exit_(1);
    }

    if (!user || user.length > 63) {
      console.log(`  ${C.red(S.cross)} Database user is required and must be <= 63 characters.`);
      exit_(1);
    }

    if (passwordEnv && !isValidEnvVarName(passwordEnv)) {
      console.log(`  ${C.red(S.cross)} Invalid env var name: "${passwordEnv}"`);
      exit_(1);
    }

    if (!passwordEnv && !passwordStored) {
      console.log(
        `  ${C.red(S.cross)} A password is required. Pass ${C.cyan(`$${DB_PASSWORD_ENV_VAR} <value>`)}, ${C.cyan('--password-file <path>')}, ${C.cyan('--password-stdin')}, or ${C.cyan('--env <var>')} — or run ${C.cyan('db add')} with no flags for a masked prompt.`,
      );
      console.log(
        `  ${C.dim(`${REFUSED_PASSWORD_ARGV_FLAGS.join('/')} is refused: process.argv is readable by every local user via /proc/<pid>/cmdline.`)}`,
      );
      exit_(1);
    }

    let finalPerm: PermissionLevel | null = null;
    if (flagPerm && ['read_only', 'auto_upgrade', 'manual', 'full'].includes(flagPerm)) {
      finalPerm = flagPerm as PermissionLevel;
    }

    const existing = findDbByProject(projectName);
    if (existing) {
      console.log(
        `  ${C.red(S.cross)} Project "${projectName}" already has database "${existing.db_alias}". Schema Weaver allows 1 DB per project.`,
      );
      exit_(1);
    }

    const entry: Omit<DbEntry, 'created_at'> = {
      project_name: projectName,
      db_alias: dbAlias,
      host,
      port,
      database,
      user,
      password_env: passwordEnv,
      password_stored: passwordStored,
      ssl_mode: sslMode,
      ssl_root_cert: sslCert,
      permission_override: finalPerm,
    };

    if (!skipTest) {
      const spinner = createSpinner();
      spinner.start(`Testing connection to ${C.cyan(dbAlias)} (${host}:${port}/${database})…`);

      const connectPassword = passwordEnv ? process.env[passwordEnv] || '' : passwordStored || '';
      // Everything below may render a `pg` error to the terminal, so the live
      // value — stored or environment-resolved — is on the redaction list. A
      // `pg` auth failure quotes the connection parameters, and nothing here
      // should be the place the password is discovered.
      const redact = (text: string) => redactSecrets(text, passwordStored, connectPassword);

      const poolConfig: PoolConfig = {
        host,
        port,
        database,
        user,
        password: connectPassword,
        connectionTimeoutMillis: 5000,
      };

      const ssl = buildSslConfig(sslMode, sslCert);
      if (ssl) {
        poolConfig.ssl = ssl;
      }

      const pool = new Pool(poolConfig);
      try {
        const res = await pool.query('SELECT version()');
        const raw = res.rows[0]?.version || '';
        const match = raw.match(/PostgreSQL [^\s,]+/);
        const ver = match ? match[0] : 'PostgreSQL';
        spinner.succeed(`Connected. ${C.green(ver)}`);
      } catch (err: unknown) {
        spinner.fail(
          `Connection test failed: ${C.red(redact(err instanceof Error ? err.message : String(err)))}`,
        );
        console.log(`  ${C.yellow('Note:')} Use ${C.cyan('--no-test')} to save anyway.`);
        await pool.end();
        exit_(1);
      } finally {
        await pool.end();
      }
    }

    try {
      addDbEntry(entry);
    } catch (err: unknown) {
      console.log(
        `  ${C.red(S.cross)} Failed to add database: ${redactSecrets(err instanceof Error ? err.message : String(err), passwordStored)}`,
      );
      exit_(1);
    }

    console.log();
    console.log(`  ${check(`Database "${C.cyan(dbAlias)}" added successfully!`)}`);
    console.log();
    console.log(`  ${C.bold('Configuration:')}`);
    console.log(`    Alias:      ${C.white(dbAlias)}`);
    console.log(`    Project:    ${C.white(projectName)}`);
    console.log(`    Host:       ${C.white(`${host}:${port}`)}`);
    console.log(`    Database:   ${C.white(database)}`);
    console.log(`    User:       ${C.white(user)}`);
    console.log(`    SSL:        ${C.white(sslMode)}`);
    // Only the SOURCE is named, never the value. `passwordSource` is an
    // enum-like string chosen above, so there is no path here that can print
    // the secret itself.
    console.log(`    Password:   ${describePasswordSource(passwordEnv, passwordSource)}`);
    console.log();
    exit_(0);
  }

  // Interactive flow
  console.log();
  console.log(C.bold(C.brand('  Add a Database')));
  console.log(separator('', 50));
  console.log();

  let projectName = '';
  for (;;) {
    projectName = await ask('Project name');
    if (projectName.trim() === '') continue;
    if (isValidIdentifier(projectName, 64) && !projectName.includes(' ')) {
      break;
    }
    console.log(`  ${C.red(S.cross)} Use letters, numbers, hyphens, underscores only.`);
  }

  // One-DB-per-project: check before proceeding and offer recovery.
  const existing = findDbByProject(projectName);
  if (existing) {
    console.log();
    console.log(
      `  ${C.yellow(S.warning)} Project "${C.white(projectName)}" already has a database:`,
    );
    console.log(
      `    ${C.cyan(existing.db_alias)}  ${C.dim(`${existing.host}:${existing.port}/${existing.database}`)}`,
    );
    console.log();
    console.log(`  ${C.dim('Schema Weaver allows one database per project.')}`);
    console.log();

    const fix = await askChoice(
      'What would you like to do?',
      ['Use a different project name', 'Remove existing and re-add', 'Cancel'],
      'Use a different project name',
    );

    if (fix === 'Cancel') {
      console.log(`  ${C.dim('Aborted.')}`);
      exit_(0);
    }
    if (fix === 'Remove existing and re-add') {
      const confirm = await askConfirm(
        C.red(`Remove "${existing.db_alias}" and add a new entry?`),
        false,
      );
      if (!confirm) {
        console.log(`  ${C.dim('Aborted.')}`);
        exit_(0);
      }
      removeDbEntry(existing.db_alias);
      console.log(`  ${check(`Removed existing entry ${C.cyan(existing.db_alias)}.`)}`);
      console.log();
    } else {
      console.log();
      for (;;) {
        projectName = await ask('Project name');
        if (
          projectName.trim() === '' &&
          isValidIdentifier(projectName, 64) &&
          !projectName.includes(' ')
        )
          continue;
        if (
          projectName.trim() !== '' &&
          isValidIdentifier(projectName, 64) &&
          !projectName.includes(' ')
        )
          break;
        console.log(`  ${C.red(S.cross)} Use letters, numbers, hyphens, underscores only.`);
      }
    }
  }

  console.log(`  ${check(`Project: ${C.white(projectName)}`)}`);
  console.log();

  let dbAlias = '';
  for (;;) {
    dbAlias = await ask('Database alias');
    if (dbAlias.trim() === '') continue;
    if (isValidIdentifier(dbAlias, 64) && !dbAlias.includes(' ')) {
      break;
    }
    console.log(`  ${C.red(S.cross)} Use letters, numbers, hyphens, underscores only.`);
  }
  console.log(`  ${check(`Alias: ${C.white(dbAlias)}`)}`);
  console.log();

  let host = '';
  for (;;) {
    host = await ask('Host', 'localhost');
    if (host.trim() === '') continue;
    if (isValidHostname(host) || isValidIpv4(host) || isValidIpv6(host)) {
      break;
    }
    console.log(`  ${C.red(S.cross)} Invalid hostname or IP.`);
  }
  console.log(`  ${check(`Host: ${C.white(host)}`)}`);
  console.log();

  let portVal = 5432;
  for (;;) {
    const portStr = await ask('Port', '5432');
    const port = parseInt(portStr, 10);
    if (!isNaN(port) && port >= 1 && port <= 65535) {
      portVal = port;
      break;
    }
    console.log(`  ${C.red(S.cross)} Port must be 1-65535.`);
  }
  console.log(`  ${check(`Port: ${C.white(String(portVal))}`)}`);
  console.log();

  let database = '';
  for (;;) {
    database = await ask('Database name');
    if (database.trim() === '') continue;
    if (database.length <= 63) {
      break;
    }
    console.log(`  ${C.red(S.cross)} Database name too long (max 63).`);
  }
  console.log(`  ${check(`Database: ${C.white(database)}`)}`);
  console.log();

  let user = '';
  for (;;) {
    user = await ask('Username');
    if (user.trim() === '') continue;
    if (user.length <= 63) {
      break;
    }
    console.log(`  ${C.red(S.cross)} Username too long (max 63).`);
  }
  console.log(`  ${check(`User: ${C.white(user)}`)}`);
  console.log();

  // Password: prefer env var, allow stored as fallback
  const passwordChoice = await askChoice(
    'Password storage',
    ['Environment variable', 'Store directly (encrypted on this machine)'],
    'Environment variable',
  );

  let passwordEnv: string | undefined;
  let passwordStored: string | undefined;

  if (passwordChoice === 'Environment variable') {
    const envVar = await ask('Environment variable name', 'DB_PASSWORD');
    if (envVar && /^[A-Z][A-Z0-9_]*$/.test(envVar)) {
      passwordEnv = envVar;
    } else {
      console.log(`  ${C.yellow(S.warning)} Invalid env var name. Using stored password instead.`);
      passwordStored = await askSecret('Password');
    }
  } else {
    passwordStored = await askSecret('Password');
  }

  const sslMode = (await askChoice(
    'SSL mode',
    ['disable', 'require', 'verify-ca', 'verify-full'],
    'require',
  )) as DbEntry['ssl_mode'];

  let sslRootCert: string | null = null;
  if (sslMode !== 'disable') {
    for (;;) {
      const certPath = await ask('SSL root cert path', '');
      if (certPath.trim() === '') {
        sslRootCert = null;
        break;
      }
      if (fs.existsSync(certPath)) {
        sslRootCert = certPath;
        break;
      }
      console.log(`  ${C.red(S.cross)} Cert file not found.`);
    }
  }

  const permOverride = await askChoice(
    'Permission',
    ['read_only', 'auto_upgrade', 'manual', 'full', 'use default'],
    'use default',
  );
  const finalPerm = permOverride === 'use default' ? null : (permOverride as PermissionLevel);

  const entry: Omit<DbEntry, 'created_at'> = {
    project_name: projectName,
    db_alias: dbAlias,
    host,
    port: portVal,
    database,
    user,
    password_env: passwordEnv,
    password_stored: passwordStored,
    ssl_mode: sslMode,
    ssl_root_cert: sslRootCert,
    permission_override: finalPerm,
  };

  // Test connection BEFORE saving
  const spinner = createSpinner();
  spinner.start(`Testing connection to ${C.white(dbAlias)}...`);

  const poolConfig: PoolConfig = {
    host: entry.host,
    port: entry.port,
    database: entry.database,
    user: entry.user,
    password: passwordEnv ? process.env[passwordEnv] || '' : passwordStored || '',
    connectionTimeoutMillis: 5000,
  };

  const ssl = buildSslConfig(entry.ssl_mode, entry.ssl_root_cert);
  if (ssl) {
    poolConfig.ssl = ssl;
  }

  const pool = new Pool(poolConfig);
  let connectionOk = false;
  let connectionError = '';
  let versionStr = '';

  try {
    const result = await Promise.race([
      pool.query('SELECT version();'),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Connection timed out (5s)')), 5000),
      ),
    ]);
    versionStr = result.rows[0]?.version || 'unknown version';
    const match = versionStr.match(/PostgreSQL [^\s,]+/);
    versionStr = match ? match[0] : 'PostgreSQL';
    connectionOk = true;
  } catch (connErr) {
    connectionError = redactSecrets(
      connErr instanceof Error ? connErr.message : String(connErr),
      passwordStored,
    );
  } finally {
    await pool.end();
  }

  if (!connectionOk) {
    spinner.fail(`Connection failed: ${C.red(connectionError)}`);
    console.log();
    const saveAnyway = await askConfirm(C.yellow('Connection failed. Save entry anyway?'), false);
    if (!saveAnyway) {
      console.log(`  ${C.yellow(S.warning)} Aborted. No entry saved.`);
      exit_(0);
    }
  } else {
    spinner.succeed(`Connected. ${C.green(versionStr)}`);
  }

  try {
    addDbEntry(entry);
  } catch (err) {
    console.log(
      `  ${C.red(S.cross)} Error: ${redactSecrets(err instanceof Error ? err.message : String(err), passwordStored)}`,
    );
    exit_(1);
  }

  console.log();
  console.log(`  ${C.green(S.check)} ${C.brightGreen('Database added successfully!')}`);
  console.log();
  console.log(`  ${C.bold('Summary:')}`);
  console.log(`    Project:    ${C.white(projectName)}`);
  console.log(`    Alias:      ${C.white(dbAlias)}`);
  console.log(`    Host:       ${C.white(host)}:${C.white(String(portVal))}`);
  console.log(`    Database:   ${C.white(database)}`);
  console.log(`    User:       ${C.white(user)}`);
  console.log(`    SSL:        ${C.white(sslMode)}`);
  console.log(
    `    Password:   ${passwordEnv ? C.green('env var') : C.yellow('stored (AES-256-GCM at rest)')}`,
  );
  console.log(`    Permission: ${C.yellow(permOverride)}`);
  console.log();
  console.log(`  ${C.dim('Next:')} ${C.cyan('agent start')} ${C.dim('to start the agent.')}`);
  console.log();
  exit_(0);
}
