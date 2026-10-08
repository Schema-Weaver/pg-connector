import { findDbEntry, loadDbConfig } from '../../config/db-config';
import { redactSecrets } from '../../config/schema';
import { createDbPool } from './db-query';
import { isReplMode } from '../prompt';
import { C, S, check, warn, terminalWidth, truncateAnsi } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDbShow(args: string[]): Promise<void> {
  const isJson = args.includes('--json') || args.includes('-j');
  const alias = args.find((a) => !a.startsWith('-'));

  if (!alias) {
    console.log();
    console.log(`  ${C.yellow('Usage:')} ${C.white('db show <alias>')} [options]`);
    const all = loadDbConfig();
    if (all.length > 0) {
      console.log(
        `  ${C.dim('Configured databases:')} ${all.map((d) => C.cyan(d.db_alias)).join(', ')}`,
      );
    }
    console.log();
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log();
    console.log(`  ${C.red(S.cross)} Database "${C.white(alias)}" not found.`);
    const all = loadDbConfig();
    if (all.length > 0) {
      console.log(
        `  ${C.dim('Available databases:')} ${all.map((d) => C.cyan(d.db_alias)).join(', ')}`,
      );
    }
    console.log();
    exit_(1);
  }

  // Live connectivity check
  let connected = false;
  let latencyMs = 0;
  let pgVersion = '';
  let connError = '';

  try {
    const pool = createDbPool(entry);
    const start = Date.now();
    try {
      const res = await pool.query('SELECT version()');
      latencyMs = Date.now() - start;
      connected = true;
      const raw = res.rows[0]?.version || '';
      const match = raw.match(/PostgreSQL [^\s,]+/);
      pgVersion = match ? match[0] : 'PostgreSQL';
    } finally {
      await pool.end();
    }
  } catch (err: unknown) {
    connected = false;
    // A thrown value is not guaranteed to be an Error, and a connection
    // failure is only ever reported as text.
    const message =
      err instanceof Error
        ? err.message
        : (err as { message?: string } | null | undefined)?.message;
    connError = redactSecrets(message || String(err), entry.password_stored);
  }

  if (isJson) {
    console.log(
      JSON.stringify(
        {
          alias: entry.db_alias,
          project_name: entry.project_name,
          host: entry.host,
          port: entry.port,
          database: entry.database,
          user: entry.user,
          password_type: entry.password_env ? 'env' : 'stored',
          password_at_rest: entry.password_env ? 'environment_variable' : 'aes_256_gcm_envelope',
          password_env: entry.password_env || null,
          ssl_mode: entry.ssl_mode,
          ssl_root_cert: entry.ssl_root_cert || null,
          permission_override: entry.permission_override || null,
          created_at: entry.created_at,
          reachable: connected,
          latency_ms: connected ? latencyMs : null,
          server_version: connected ? pgVersion : null,
          error: connError || null,
        },
        null,
        2,
      ),
    );
    exit_(0);
  }

  const width = Math.max(40, terminalWidth() - 4);
  const valueWidth = Math.max(20, width - 24);

  console.log();
  console.log(`  ${C.bold(C.brand('Database Details'))} ${C.dim('—')} ${C.white(entry.db_alias)}`);
  console.log();

  const statusText = connected
    ? `${check('Reachable')} ${C.dim(`(${latencyMs}ms, ${pgVersion})`)}`
    : `${warn('Unreachable')} ${C.dim(`(${truncateAnsi(connError, valueWidth)})`)}`;

  const rows = [
    ['Alias', C.cyan(entry.db_alias)],
    ['Project', C.white(entry.project_name)],
    ['Host', C.white(`${entry.host}:${entry.port}`)],
    ['Database', C.white(entry.database)],
    ['User', C.white(entry.user)],
    [
      'Password',
      entry.password_env
        ? C.green(`Environment variable ($${entry.password_env})`)
        : C.yellow('Stored locally as AES-256-GCM ciphertext'),
    ],
    ['SSL Mode', entry.ssl_mode === 'disable' ? C.dim('disabled') : C.yellow(entry.ssl_mode)],
    ['SSL Root Cert', entry.ssl_root_cert ? C.white(entry.ssl_root_cert) : C.dim('none')],
    [
      'Permission',
      entry.permission_override
        ? C.yellow(entry.permission_override)
        : C.dim('Inherited from machine default'),
    ],
    ['Created', C.dim(entry.created_at.slice(0, 19).replace('T', ' '))],
    ['Connection', statusText],
  ];

  for (const [label, value] of rows) {
    console.log(`    ${C.bold(label.padEnd(16))} ${value}`);
  }

  console.log();
  console.log(`  ${C.dim('Quick actions:')}`);
  console.log(`    ${C.cyan(`db test ${entry.db_alias}`)}       Run diagnostics`);
  console.log(`    ${C.cyan(`db connect ${entry.db_alias}`)}    Interactive SQL console`);
  console.log(`    ${C.cyan(`db query ${entry.db_alias} "<SQL>"`)} Run single query`);
  console.log(`    ${C.cyan(`db logs ${entry.db_alias}`)}       View audit logs`);
  console.log(`    ${C.cyan(`db edit ${entry.db_alias}`)}       Modify settings`);
  console.log();

  exit_(0);
}
