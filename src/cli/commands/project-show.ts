/**
 * @roadmap Cloud project metadata — planned for v0.3.0.
 * Currently functional for locally configured DB entries. Does not yet
 * fetch project metadata, team members, or migration history from the
 * Schema Weaver cloud API.
 */
import * as path from 'path';
import { findDbByProject, loadDbConfig } from '../../config/db-config';
import { getSwAgentDir } from '../../config/paths';
import { readPidFile, isProcessAlive } from '../daemon/pid-file';
import { readStatusFile, isStatusStale } from '../daemon/status-file';
import { isReplMode } from '../prompt';
import { C, S, check, warn } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runProjectShow(args: string[]): Promise<void> {
  const name = args[0];
  if (!name) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('project show <name>')}`);
    exit_(1);
  }

  const entry = findDbByProject(name) || loadDbConfig().find((db) => db.db_alias === name) || null;
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Project "${C.white(name)}" not found.`);
    console.log(`  ${C.dim('Run')} ${C.cyan('project list')} ${C.dim('to see linked projects.')}`);
    exit_(1);
  }

  // Best-effort live agent status.
  let agentState: 'running' | 'unresponsive' | 'stopped' = 'stopped';
  try {
    const swAgentDir = getSwAgentDir();
    const pidInfo = await readPidFile({ path: path.join(swAgentDir, 'sw-agent.pid') });
    if (pidInfo && isProcessAlive(pidInfo.pid)) {
      const status = await readStatusFile({ path: path.join(swAgentDir, 'sw-agent.status') });
      agentState = status && !isStatusStale(status) ? 'running' : 'unresponsive';
    }
  } catch {
    /* ignore — status is best-effort */
  }

  const badge =
    agentState === 'running' ? C.green('● running') :
    agentState === 'unresponsive' ? C.yellow('● unresponsive') :
    C.gray('○ stopped');

  console.log();
  console.log(C.bold('  Project') + ' ' + C.cyan(name) + ' ' + badge);
  console.log();

  console.log(`    ${C.bold('Database:')}   ${C.white(entry.database)}`);
  console.log(`    ${C.bold('Alias:')}       ${C.white(entry.db_alias)}`);
  console.log(`    ${C.bold('Host:')}        ${C.white(`${entry.host}:${entry.port}`)}`);
  console.log(`    ${C.bold('User:')}        ${C.white(entry.user)}`);
  console.log(`    ${C.bold('SSL:')}         ${C.white(entry.ssl_mode)}`);
  console.log(`    ${C.bold('Password:')}   ${entry.password_env ? C.green('env var') : C.yellow('stored')}`);
  console.log(`    ${C.bold('Permission:')} ${C.yellow(entry.permission_override || 'default')}`);
  console.log(`    ${C.bold('Created:')}     ${C.dim(entry.created_at)}`);
  console.log();

  if (agentState === 'running') {
    console.log(`  ${check('Agent is running — this project is reachable from the IDE.')}`);
  } else {
    console.log(`  ${warn(`Agent is ${agentState}. Run ${C.cyan('agent start')} to make it reachable.`)}`);
  }
  console.log();

  exit_(0);
}
