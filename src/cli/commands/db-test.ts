import { findDbEntry, dbConfigExists, loadDbConfig } from '../../config/db-config';
import { Pool, PoolConfig } from 'pg';
import { isReplMode } from '../prompt';
import { C, S, createSpinner, renderTable } from '../ui';
import { buildSslConfig } from '../../execution/pool';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

interface TestResult {
  alias: string;
  host: string;
  ok: boolean;
  latency: number;
  version: string;
  database: string;
  user: string;
  error: string;
  diagnostics?: {
    serverEncoding: string;
    clientEncoding: string;
    timeZone: string;
    tableCount: number;
    schemas: string[];
    sslMode: string;
  };
}

async function attemptConnect(
  poolConfig: PoolConfig,
  detailed: boolean,
  entry: any,
  startTime: number,
): Promise<TestResult> {
  const pool = new Pool(poolConfig);
  try {
    const result = await Promise.race([
      pool.query('SELECT version(), current_database(), current_user;'),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('connection timed out (5s)')), 5000),
      ),
    ]);
    const latency = Date.now() - startTime;
    const raw = result.rows[0]?.version || 'unknown';
    const match = raw.match(/PostgreSQL [^\s,]+/);
    const versionStr = match ? match[0] : 'PostgreSQL';

    let diagnostics: TestResult['diagnostics'];
    if (detailed) {
      try {
        const settingsRes = await pool.query(
          "SELECT current_setting('server_encoding') AS server_enc, current_setting('client_encoding') AS client_enc, current_setting('TimeZone') AS tz;"
        );
        const tablesRes = await pool.query(
          "SELECT count(*)::int AS count FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema');"
        );
        const schemasRes = await pool.query(
          "SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog', 'information_schema') ORDER BY schema_name;"
        );

        diagnostics = {
          serverEncoding: settingsRes.rows[0]?.server_enc || 'UTF8',
          clientEncoding: settingsRes.rows[0]?.client_enc || 'UTF8',
          timeZone: settingsRes.rows[0]?.tz || 'UTC',
          tableCount: tablesRes.rows[0]?.count || 0,
          schemas: schemasRes.rows.map((r) => r.schema_name),
          sslMode: entry.ssl_mode,
        };
      } catch {
        // Detailed queries are best effort
      }
    }

    return {
      alias: entry.db_alias,
      host: `${poolConfig.host}:${poolConfig.port}`,
      ok: true,
      latency,
      version: versionStr,
      database: result.rows[0]?.current_database || entry.database,
      user: result.rows[0]?.current_user || entry.user,
      error: '',
      diagnostics,
    };
  } finally {
    await pool.end();
  }
}

async function testOne(
  entry: ReturnType<typeof findDbEntry> | null,
  detailed = false,
): Promise<TestResult> {
  if (!entry) {
    return { alias: '-', host: '-', ok: false, latency: 0, version: '', database: '', user: '', error: 'not found' };
  }

  const password =
    entry.password_stored ||
    (entry.password_env ? process.env[entry.password_env] : undefined);

  if (!password) {
    return {
      alias: entry.db_alias,
      host: `${entry.host}:${entry.port}`,
      ok: false,
      latency: 0,
      version: '',
      database: entry.database,
      user: entry.user,
      error: 'password not set (check env var or stored password)',
    };
  }

  const poolConfig: PoolConfig = {
    host: entry.host,
    port: entry.port,
    database: entry.database,
    user: entry.user,
    password,
    connectionTimeoutMillis: 5000,
  };

  const ssl = buildSslConfig(entry.ssl_mode, entry.ssl_root_cert);
  if (ssl) {
    poolConfig.ssl = ssl as any;
  }

  const startTime = Date.now();

  try {
    return await attemptConnect(poolConfig, detailed, entry, startTime);
  } catch (err: any) {
    // Cross-OS fallback: On Linux/macOS, 'localhost' often resolves to IPv6 '::1'.
    // If PostgreSQL is listening on IPv4 127.0.0.1 only, attempt fallback to 127.0.0.1.
    if (
      entry.host.toLowerCase() === 'localhost' &&
      (err?.code === 'ECONNREFUSED' || err?.message?.includes('ECONNREFUSED'))
    ) {
      try {
        return await attemptConnect({ ...poolConfig, host: '127.0.0.1' }, detailed, entry, startTime);
      } catch {
        // Fall back to reporting original error
      }
    }

    return {
      alias: entry.db_alias,
      host: `${entry.host}:${entry.port}`,
      ok: false,
      latency: Date.now() - startTime,
      version: '',
      database: entry.database,
      user: entry.user,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function runDbTest(args: string[]): Promise<void> {
  const testAll = args.includes('--all');
  const detailed = args.includes('--detailed') || args.includes('-d') || args.includes('--verbose');
  const isJson = args.includes('--json') || args.includes('-j');

  if (testAll) {
    if (!dbConfigExists()) {
      console.log(`  ${C.yellow(S.warning)} No databases configured. Run ${C.cyan('db add')} first.`);
      exit_(0);
    }

    const config = loadDbConfig();
    if (config.length === 0) {
      console.log(`  ${C.yellow(S.warning)} No databases configured.`);
      exit_(0);
    }

    console.log();
    console.log(C.bold('  Testing all databases'));
    console.log();

    const spinner = createSpinner();
    if (!isJson) {
      spinner.start(`Testing ${C.white(String(config.length))} databases…`);
    }

    const results = await Promise.all(config.map((db) => testOne(db, detailed)));

    if (!isJson) {
      spinner.stop();
      console.log();
    }

    if (isJson) {
      console.log(JSON.stringify(results, null, 2));
      exit_(results.every((r) => r.ok) ? 0 : 1);
    }

    const rows = results.map((r) => ({
      alias: r.ok ? C.green(r.alias) : C.red(r.alias),
      host: C.dim(r.host),
      status: r.ok
        ? C.green(`${C.green(S.check)} ${r.latency}ms`)
        : C.red(`${S.cross} ${truncate(r.error, 30)}`),
      version: r.ok ? C.white(r.version) : C.dim('-'),
    }));

    console.log(
      renderTable(rows, {
        columns: [
          { key: 'alias', header: 'ALIAS', minWidth: 10, maxWidth: 18, priority: 0 },
          { key: 'host', header: 'HOST', minWidth: 14, maxWidth: 30, priority: 2 },
          { key: 'status', header: 'STATUS', minWidth: 12, maxWidth: 28, priority: 1 },
          { key: 'version', header: 'VERSION', minWidth: 12, maxWidth: 20, priority: 4 },
        ],
      }),
    );

    console.log();
    const ok = results.filter((r) => r.ok).length;
    console.log(
      `  ${ok === config.length
        ? C.green(`${S.check} All ${ok} databases connected successfully.`)
        : C.yellow(`${S.warning} ${ok}/${config.length} databases connected.`)
      }`,
    );
    console.log();
    exit_(ok === config.length ? 0 : 1);
  }

  // Single alias test
  const cleanArgs = args.filter((a) => !a.startsWith('-'));
  const alias = cleanArgs[0];

  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db test <alias> [--detailed]')} ${C.dim('or')} ${C.white('db test --all')}\n`);
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}\n`);
    exit_(1);
  }

  if (!isJson) {
    console.log();
    console.log(`  ${C.bold('Testing Database:')} ${C.cyan(alias)} ${C.dim(`(${entry.host}:${entry.port}/${entry.database})`)}`);
    console.log();
  }

  const spinner = createSpinner();
  if (!isJson) {
    spinner.start('Connecting…');
  }

  const result = await testOne(entry, detailed);

  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
    exit_(result.ok ? 0 : 1);
  }

  if (result.ok) {
    spinner.succeed(`Connected in ${C.green(`${result.latency}ms`)}`);
    console.log();
    console.log(`    ${C.bold('Version:')}    ${C.white(result.version)}`);
    console.log(`    ${C.bold('Database:')}   ${C.white(result.database)}`);
    console.log(`    ${C.bold('User:')}       ${C.white(result.user)}`);
    console.log(`    ${C.bold('SSL Mode:')}   ${entry.ssl_mode === 'disable' ? C.dim('disabled') : C.yellow(entry.ssl_mode)}`);

    if (result.diagnostics) {
      console.log();
      console.log(`  ${C.bold(C.brand('Server Diagnostics:'))}`);
      console.log(`    ${C.bold('Encoding:')}   Server: ${C.white(result.diagnostics.serverEncoding)}, Client: ${C.white(result.diagnostics.clientEncoding)}`);
      console.log(`    ${C.bold('Time Zone:')}  ${C.white(result.diagnostics.timeZone)}`);
      console.log(`    ${C.bold('Tables:')}     ${C.white(String(result.diagnostics.tableCount))} user tables`);
      console.log(`    ${C.bold('Schemas:')}    ${C.white(result.diagnostics.schemas.join(', ') || 'none')}`);
    } else {
      console.log();
      console.log(`  ${C.dim('Tip: Run')} ${C.cyan(`db test ${alias} --detailed`)} ${C.dim('for schema & encoding diagnostics.')}`);
    }
    console.log();
  } else {
    spinner.fail(`Connection failed: ${C.red(result.error)}`);
    console.log();
    exit_(1);
  }
}

export async function runDbPing(args: string[]): Promise<void> {
  return runDbTest(args);
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}
