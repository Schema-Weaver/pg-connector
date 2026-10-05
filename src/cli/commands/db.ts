import { runDbAdd } from './db-add';
import { runDbLs, runDbLs as runDbList } from './db-ls';
import { runDbTest, runDbPing } from './db-test';
import { runDbRemove } from './db-remove';
import { runDbEdit } from './db-edit';
import { runDbQuery, runDbConnect } from './db-query';
import { runDbLogs } from './db-logs';
import { runDbShow } from './db-show';
import { isReplMode } from '../prompt';
import { C } from '../ui';

export {
  runDbAdd,
  runDbLs,
  runDbList,
  runDbTest,
  runDbPing,
  runDbRemove,
  runDbEdit,
  runDbQuery,
  runDbConnect,
  runDbLogs,
  runDbShow,
};

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDb(args: string[] = []): Promise<void> {
  const sub = args[0];
  const rest = args.slice(1);

  if (!sub || sub === 'list' || sub === 'ls') {
    return runDbList(sub ? rest : args);
  }

  if (sub === 'add') {
    return runDbAdd(rest);
  }

  if (sub === 'edit') {
    return runDbEdit(rest);
  }

  if (sub === 'remove' || sub === 'rm') {
    return runDbRemove(rest);
  }

  if (sub === 'test') {
    return runDbTest(rest);
  }

  if (sub === 'ping') {
    return runDbPing(rest);
  }

  if (sub === 'show' || sub === 'info') {
    return runDbShow(rest);
  }

  if (sub === 'logs' || sub === 'log') {
    return runDbLogs(rest);
  }

  if (sub === 'query') {
    return runDbQuery(rest);
  }

  if (sub === 'connect') {
    return runDbConnect(rest);
  }

  if (sub === '--help' || sub === '-h' || sub === 'help') {
    console.log();
    console.log(`  ${C.bold('Database Commands')}`);
    console.log();
    console.log(`    ${C.cyan('db list')}                    List all configured databases (${C.dim('alias: ls')})`);
    console.log(`    ${C.cyan('db show <alias>')}            Show database configuration and live status (${C.dim('alias: info')})`);
    console.log(`    ${C.cyan('db add')}                     Add a database (${C.dim('interactive, --url, or flags')})`);
    console.log(`    ${C.cyan('db edit <alias>')}            Edit a database entry (${C.dim('interactive or flags')})`);
    console.log(`    ${C.cyan('db remove <alias>')}          Remove a database entry (${C.dim('alias: rm')})`);
    console.log(`    ${C.cyan('db test <alias>')}            Test database connection (${C.dim('--detailed, --all')})`);
    console.log(`    ${C.cyan('db ping <alias>')}            Quick connection latency ping`);
    console.log(`    ${C.cyan('db connect <alias>')}         Open interactive SQL console`);
    console.log(`    ${C.cyan('db query <alias> "<SQL>"')}   Execute a query and render results`);
    console.log(`    ${C.cyan('db logs <alias>')}            View audit logs for this database (${C.dim('-f follow, -q search')})`);
    console.log();
    exit_(0);
  }

  // If argument is a flag like --json, default to list
  if (sub.startsWith('-')) {
    return runDbList(args);
  }

  console.log(`  ${C.yellow('Unknown database command:')} ${C.white(sub)}`);
  console.log(`  ${C.dim('Run')} ${C.cyan('sw-agent db --help')} ${C.dim('for usage.')}\n`);
  exit_(1);
}
