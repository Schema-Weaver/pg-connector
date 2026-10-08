import { findDbEntry, loadDbConfig } from '../../config/db-config';
import { runLogs, LogsOptions } from './logs';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDbLogs(args: string[], opts: LogsOptions = {}): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log();
    console.log(`  ${C.bold('Database Logs')}`);
    console.log();
    console.log(`  ${C.dim('Usage:')} ${C.cyan('db logs <alias>')} [options]`);
    console.log();
    console.log(`  ${C.bold('Options:')}`);
    console.log(`    ${C.cyan('-f, --follow')}     Stream new audit logs in real time`);
    console.log(`    ${C.cyan('-l, --limit <n>')}  Number of events to show (default: 20)`);
    console.log(`    ${C.cyan('-q, --search <s')}  Search within query preview or error`);
    console.log(`    ${C.cyan('-a, --action <a>')} Filter by action (query, migration_run, etc.)`);
    console.log(`    ${C.cyan('-d, --decision <d>')} Filter by decision (allow, deny, etc.)`);
    console.log(`    ${C.cyan('-o, --outcome <o>')} Filter by outcome (success, error)`);
    console.log(`    ${C.cyan('-j, --json')}       Output logs in JSON format`);
    console.log();
    exit_(0);
  }

  // Find alias: first non-flag argument
  const alias = args.find((a) => !a.startsWith('-'));
  const remainingArgs = args.filter((a) => a !== alias);

  if (!alias) {
    console.log();
    console.log(`  ${C.yellow('Usage:')} ${C.white('db logs <alias>')} [options]`);
    const all = loadDbConfig();
    if (all.length > 0) {
      console.log(
        `  ${C.dim('Available databases:')} ${all.map((d) => C.cyan(d.db_alias)).join(', ')}`,
      );
    }
    console.log();
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log();
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    const all = loadDbConfig();
    if (all.length > 0) {
      console.log(
        `  ${C.dim('Available databases:')} ${all.map((d) => C.cyan(d.db_alias)).join(', ')}`,
      );
    }
    console.log();
    exit_(1);
  }

  const isJson = args.includes('--json') || args.includes('-j');
  if (!isJson) {
    console.log();
    console.log(
      `  ${C.bold(C.brand('Database Logs'))} ${C.dim('—')} ${C.cyan(alias)} ${C.dim(`(project: ${entry.project_name}, db: ${entry.database})`)}`,
    );
    console.log();
  }

  await runLogs(remainingArgs, {
    ...opts,
    project: entry.project_name,
  });
}
