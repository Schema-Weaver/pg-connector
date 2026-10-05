import * as readline from 'readline';
import { Pool, PoolConfig } from 'pg';
import { findDbEntry, DbEntry } from '../../config/db-config';
import { buildSslConfig } from '../../execution/pool';
import { isReplMode } from '../prompt';
import { C, S, renderTable, clearScreen, createSpinner, terminalWidth, truncateAnsi } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export function createDbPool(entry: DbEntry): Pool {
  const password =
    entry.password_stored ||
    (entry.password_env ? process.env[entry.password_env] : undefined);

  if (!password) {
    throw new Error(
      `Password not available for "${entry.db_alias}". ` +
      (entry.password_env ? `Env var "${entry.password_env}" is not set.` : 'No stored password.')
    );
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

  return new Pool(poolConfig);
}

export async function runDbQuery(args: string[]): Promise<void> {
  const isJson = args.includes('--json') || args.includes('-j');
  const cleanArgs = args.filter((a) => a !== '--json' && a !== '-j');

  const alias = cleanArgs[0];
  const sql = cleanArgs.slice(1).join(' ').trim();

  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db query <alias> "<SQL>"\n')}`);
    exit_(1);
  }

  if (!sql) {
    // If no query provided, redirect to db connect interactive mode
    return runDbConnect([alias]);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}\n`);
    exit_(1);
  }

  let pool: Pool;
  try {
    pool = createDbPool(entry);
  } catch (err: any) {
    console.log(`  ${C.red(S.cross)} ${err.message}\n`);
    exit_(1);
  }

  const spinner = createSpinner();
  if (!isJson) {
    spinner.start(`Executing query on ${C.cyan(alias)}…`);
  }

  const startTime = Date.now();
  try {
    const result = await pool.query(sql);
    const duration = Date.now() - startTime;

    if (!isJson) {
      spinner.stop();
    }

    if (isJson) {
      console.log(
        JSON.stringify(
          {
            alias,
            command: result.command,
            rowCount: result.rowCount,
            durationMs: duration,
            rows: result.rows,
          },
          null,
          2
        )
      );
      exit_(0);
    }

    console.log();
    if (result.rows && result.rows.length > 0) {
      renderSqlResult(result.rows, result.fields.map((f) => f.name));
      console.log();
      console.log(`  ${C.dim(`(${result.rows.length} row${result.rows.length === 1 ? '' : 's'} in ${duration}ms)`)}`);
    } else {
      console.log(`  ${C.green(S.check)} Query executed successfully (${C.dim(`${duration}ms`)})`);
      if (result.rowCount !== null && result.rowCount !== undefined) {
        console.log(`  ${C.dim(`Command:`)} ${C.white(result.command)}  ${C.dim(`Rows affected:`)} ${C.white(String(result.rowCount))}`);
      }
    }
    console.log();
  } catch (err: any) {
    if (!isJson) spinner.stop();
    console.log();
    console.log(`  ${C.red(S.cross)} Query error: ${C.red(err.message)}`);
    if (err.position) {
      console.log(`  ${C.dim(`Position:`)} ${err.position}`);
    }
    console.log();
    exit_(1);
  } finally {
    await pool.end();
  }

  exit_(0);
}

export async function runDbConnect(args: string[]): Promise<void> {
  const alias = args[0];
  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db connect <alias>')}\n`);
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('db list')} ${C.dim('to see available databases.')}\n`);
    exit_(1);
  }

  let pool: Pool;
  try {
    pool = createDbPool(entry);
  } catch (err: any) {
    console.log(`  ${C.red(S.cross)} ${err.message}\n`);
    exit_(1);
  }

  const spinner = createSpinner();
  spinner.start(`Connecting to ${C.cyan(alias)} (${entry.host}:${entry.port}/${entry.database})…`);

  const startTime = Date.now();
  let pgVersion = 'PostgreSQL';
  try {
    const testRes = await pool.query('SELECT version(), current_database(), current_user');
    const latency = Date.now() - startTime;
    const raw = testRes.rows[0]?.version || '';
    const match = raw.match(/PostgreSQL [^\s,]+/);
    if (match) pgVersion = match[0];
    spinner.succeed(`Connected to ${C.cyan(alias)} (${C.green(`${latency}ms`)})`);
  } catch (err: any) {
    spinner.fail(`Failed to connect: ${C.red(err.message)}`);
    await pool.end();
    exit_(1);
  }

  console.log();
  console.log(`  ${C.bold('Database Console')}  ${C.dim(`[${pgVersion}]`)}`);
  console.log(`  ${C.dim(`Host:`)} ${C.white(entry.host)}:${C.white(String(entry.port))}  ${C.dim(`DB:`)} ${C.white(entry.database)}  ${C.dim(`User:`)} ${C.white(entry.user)}`);
  console.log(`  ${C.dim('Type SQL to run, or')} ${C.cyan('\\dt')} ${C.dim('(tables),')} ${C.cyan('\\dn')} ${C.dim('(schemas),')} ${C.cyan('\\l')} ${C.dim('(databases),')} ${C.cyan('exit')} ${C.dim('to quit.')}`);
  console.log();

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `sw-agent (${C.cyan(alias)}) > `,
  });

  rl.prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (!input) {
      rl.prompt();
      continue;
    }

    if (input === 'exit' || input === 'quit' || input === '\\q') {
      break;
    }

    if (input === 'clear') {
      clearScreen();
      rl.prompt();
      continue;
    }

    if (input === 'help' || input === '\\?') {
      console.log();
      console.log(`  ${C.bold('Console Commands:')}`);
      console.log(`    ${C.cyan('\\dt')}          List tables`);
      console.log(`    ${C.cyan('\\dn')}          List schemas`);
      console.log(`    ${C.cyan('\\l')}           List databases`);
      console.log(`    ${C.cyan('clear')}        Clear console screen`);
      console.log(`    ${C.cyan('exit')}         Quit database console`);
      console.log();
      rl.prompt();
      continue;
    }

    let sql = input;
    if (input === '\\dt') {
      sql = `
        SELECT table_schema AS schema, table_name AS table, table_type AS type
        FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY table_schema, table_name;
      `;
    } else if (input === '\\dn') {
      sql = `
        SELECT schema_name AS schema, schema_owner AS owner
        FROM information_schema.schemata
        ORDER BY schema_name;
      `;
    } else if (input === '\\l') {
      sql = `
        SELECT datname AS database, pg_encoding_to_char(encoding) AS encoding
        FROM pg_database
        WHERE datistemplate = false
        ORDER BY datname;
      `;
    }

    const t0 = Date.now();
    try {
      const res = await pool.query(sql);
      const elapsed = Date.now() - t0;
      console.log();
      if (res.rows && res.rows.length > 0) {
        renderSqlResult(res.rows, res.fields.map((f) => f.name));
        console.log();
        console.log(`  ${C.dim(`(${res.rows.length} row${res.rows.length === 1 ? '' : 's'} in ${elapsed}ms)`)}`);
      } else {
        console.log(`  ${C.green(S.check)} Query executed (${C.dim(`${elapsed}ms`)})${res.rowCount !== null ? ` - ${res.rowCount} rows affected` : ''}`);
      }
      console.log();
    } catch (err: any) {
      console.log();
      console.log(`  ${C.red(S.cross)} ${C.red(err.message)}`);
      console.log();
    }

    rl.prompt();
  }

  rl.close();
  await pool.end();
  console.log(`  ${C.dim('Connection closed.')}\n`);
  exit_(0);
}

function renderSqlResult(rows: any[], fieldNames: string[]): void {
  const maxW = Math.max(40, terminalWidth() - 4);
  const formattedRows = rows.map((r) => {
    const rowObj: Record<string, string> = {};
    for (const f of fieldNames) {
      const val = r[f];
      if (val === null || val === undefined) {
        rowObj[f] = C.dim('NULL');
      } else if (typeof val === 'boolean') {
        rowObj[f] = val ? C.green('true') : C.red('false');
      } else if (typeof val === 'object') {
        rowObj[f] = truncateAnsi(JSON.stringify(val), 40);
      } else {
        rowObj[f] = String(val);
      }
    }
    return rowObj;
  });

  const columns = fieldNames.map((name) => ({
    key: name,
    header: name.toUpperCase(),
    minWidth: Math.min(6, name.length),
    maxWidth: Math.max(12, Math.floor(maxW / fieldNames.length)),
    priority: 1,
  }));

  console.log(renderTable(formattedRows, { columns, maxWidth: maxW }));
}
