import { loadDbConfig, dbConfigExists } from '../../config/db-config';
import { isReplMode } from '../prompt';
import { C, S, renderTable, createSpinner } from '../ui';
import { Pool, PoolConfig } from 'pg';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDbLs(args: string[]): Promise<void> {
  if (!dbConfigExists()) {
    console.log(`  ${C.yellow(S.warning)} No databases configured. Run ${C.cyan('db add')} first.`);
    exit_(0);
  }

  const config = loadDbConfig();
  if (config.length === 0) {
    console.log(`  ${C.yellow(S.warning)} No databases configured. Run ${C.cyan('db add')} first.`);
    exit_(0);
  }

  const checkReachable = args.includes('--reachable');

  if (args.includes('--json')) {
    const redacted = config.map((db) => ({
      ...db,
      password_stored: db.password_stored ? '***' : undefined,
    }));
    console.log(JSON.stringify(redacted, null, 2));
    exit_(0);
  }

  console.log();
  console.log(C.bold('  Databases'));
  console.log();

  // If --reachable, ping each DB in parallel and build a status map.
  const reachableMap = new Map<string, boolean>();
  if (checkReachable) {
    const spinner = createSpinner();
    spinner.start('Checking connections…');

    await Promise.all(
      config.map(async (db) => {
        try {
          const password =
            db.password_stored || (db.password_env ? process.env[db.password_env] : undefined);
          if (!password) {
            reachableMap.set(db.db_alias, false);
            return;
          }
          const poolCfg: PoolConfig = {
            host: db.host,
            port: db.port,
            database: db.database,
            user: db.user,
            password,
            connectionTimeoutMillis: 3000,
          };
          if (db.ssl_mode !== 'disable') {
            poolCfg.ssl = {
              rejectUnauthorized:
                db.ssl_mode === 'verify-ca' || db.ssl_mode === 'verify-full',
            };
          }
          const pool = new Pool(poolCfg);
          try {
            await pool.query('SELECT 1');
            reachableMap.set(db.db_alias, true);
          } catch {
            reachableMap.set(db.db_alias, false);
          } finally {
            await pool.end();
          }
        } catch {
          reachableMap.set(db.db_alias, false);
        }
      }),
    );

    spinner.stop();
  }

  const rows = config.map((db) => ({
    _alias: db.db_alias,
    alias: checkReachable
      ? reachableMap.get(db.db_alias)
        ? C.green(db.db_alias)
        : C.red(db.db_alias)
      : C.cyan(db.db_alias),
    project: C.white(db.project_name),
    host: `${db.host}:${db.port}`,
    database: C.white(db.database),
    user: C.white(db.user),
    ssl: db.ssl_mode === 'disable' ? C.dim('none') : C.yellow(db.ssl_mode),
    password: db.password_env ? C.green('env') : C.yellow('stored'),
    permission: db.permission_override
      ? C.yellow(db.permission_override)
      : C.dim('default'),
  }));

  console.log(
    renderTable(rows, {
      columns: [
        { key: 'alias', header: 'ALIAS', minWidth: 10, maxWidth: 18, priority: 0 },
        { key: 'project', header: 'PROJECT', minWidth: 10, maxWidth: 18, priority: 1 },
        { key: 'host', header: 'HOST', minWidth: 14, maxWidth: 30, priority: 2 },
        { key: 'database', header: 'DATABASE', minWidth: 10, maxWidth: 18, priority: 3 },
        { key: 'user', header: 'USER', minWidth: 8, maxWidth: 16, priority: 5 },
        { key: 'ssl', header: 'SSL', minWidth: 6, maxWidth: 12, priority: 7 },
        { key: 'password', header: 'PWD', minWidth: 5, maxWidth: 7, priority: 8 },
        { key: 'permission', header: 'PERM', minWidth: 8, maxWidth: 14, priority: 6 },
      ],
    }),
  );

  console.log();
  if (checkReachable) {
    const ok = [...reachableMap.values()].filter(Boolean).length;
    console.log(
      `  ${C.dim('Reachable:')} ${C.green(`${ok}/${config.length}`)}`,
    );
    console.log();
  }
  console.log(`  ${C.dim('Tip:')} ${C.cyan('db test <alias>')} for details, or ${C.cyan('db test --all')} to test every DB.`);
  console.log();
  exit_(0);
}
