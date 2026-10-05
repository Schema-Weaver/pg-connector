import { loadDbConfig, findDbByProject } from '../../config/db-config';
import { C, S, renderTable } from '../ui';
import { isReplMode } from '../prompt';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runProjectList(_args: string[]): Promise<void> {
  const config = loadDbConfig();
  if (config.length === 0) {
    console.log(`  ${C.yellow(S.warning)} No projects yet. Run ${C.cyan('db add')} to add one.`);
    exit_(0);
  }

  console.log();
  console.log(C.bold('  Projects'));
  console.log();

  const rows = config.map((e) => ({
    project: e.project_name,
    alias: e.db_alias,
    host: `${e.host}:${e.port}`,
    database: e.database,
  }));

  console.log(
    renderTable(rows, {
      columns: [
        { key: 'project', header: 'PROJECT', minWidth: 10, maxWidth: 20, priority: 0 },
        { key: 'alias', header: 'ALIAS', minWidth: 10, maxWidth: 18, priority: 1 },
        { key: 'host', header: 'HOST', minWidth: 14, maxWidth: 30, priority: 2 },
        { key: 'database', header: 'DATABASE', minWidth: 10, maxWidth: 20, priority: 3 },
      ],
    })
  );

  console.log();
  exit_(0);
}

export async function runProjectShow(args: string[]): Promise<void> {
  const projectName = args[0];
  if (!projectName) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('project show <name>')}`);
    exit_(1);
  }

  const entry = findDbByProject(projectName) || loadDbConfig().find((db) => db.db_alias === projectName) || null;
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Project "${C.white(projectName)}" not found.`);
    exit_(1);
  }

  console.log();
  console.log(C.bold(`  Project: ${C.white(projectName)}`));
  console.log();
  console.log(`    ${C.bold('Alias:')}      ${C.white(entry.db_alias)}`);
  console.log(`    ${C.bold('Host:')}       ${C.white(`${entry.host}:${entry.port}`)}`);
  console.log(`    ${C.bold('Database:')}   ${C.white(entry.database)}`);
  console.log(`    ${C.bold('User:')}       ${C.white(entry.user)}`);
  console.log(`    ${C.bold('SSL:')}        ${C.white(entry.ssl_mode)}`);
  console.log(`    ${C.bold('Permission:')} ${C.yellow(entry.permission_override || 'default')}`);
  console.log(`    ${C.bold('Created:')}    ${C.dim(entry.created_at)}`);
  console.log();
  exit_(0);
}
