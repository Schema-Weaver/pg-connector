#!/usr/bin/env node
import { VERSION } from '../index';
import { runInit } from './commands/init';
import {
  runDb,
  runDbAdd,
  runDbList,
  runDbTest,
  runDbPing,
  runDbRemove,
  runDbEdit,
  runDbQuery,
  runDbConnect,
  runDbLogs,
  runDbShow,
} from './commands/db';
import { runProjectList, runProjectShow } from './commands/project';
import { runStart, runStop, runStatus, runRestart, runClean, runAgentRotateToken, runAgentUnlink } from './commands/agent';
import { runDoctor } from './commands/doctor';
import { runLogs } from './commands/logs';
import { runAuditVerify } from './commands/audit-verify';
import { runConfig, runConfigShow, runConfigGet, runConfigSet, runConfigPath } from './commands/config';
import { runLink } from './commands/link';
import { runDebug } from './commands/debug';
import { runService } from './commands/service';
import { startInteractive } from './interactive';
import { printBanner } from './banner';
import { C, clearScreen } from './ui';

const HELP_TEXT = `${C.bold('Schema Weaver Connector')} v${VERSION}  ${C.dim('— bridge between your browser IDE and PostgreSQL')}

${C.dim('Usage:')} pg-connector ${C.cyan('<command>')} [options]
${C.dim('Run pg-connector with no arguments to start the interactive REPL.')}
${C.dim('Aliases: schemaweaver, sw-agent, db-connector')}

${C.bold(C.brand('Databases'))}
  ${C.cyan('db list')}            List configured databases          ${C.dim('(alias: ls, db)')}
  ${C.cyan('db show <alias>')}    Show configuration & live status   ${C.dim('(alias: info)')}
  ${C.cyan('db add')}             Add database entry                 ${C.dim('(interactive, --url, or flags)')}
  ${C.cyan('db edit <alias>')}    Edit database configuration        ${C.dim('(interactive or flags)')}
  ${C.cyan('db remove <alias>')}  Remove a database entry            ${C.dim('(alias: rm)')}
  ${C.cyan('db test <alias>')}    Test connection & latency          ${C.dim('(alias: test, --detailed, --all)')}
  ${C.cyan('db ping <alias>')}    Quick connection check             ${C.dim('(alias: ping)')}
  ${C.cyan('db connect <alias>')} Interactive SQL console            ${C.dim('(alias: connect)')}
  ${C.cyan('db query <a> <sql>')} Execute SQL statement & render    ${C.dim('(alias: query, --json)')}
  ${C.cyan('db logs <alias>')}    Audit logs for database project    ${C.dim('(-f follow, -q search)')}

${C.bold(C.brand('Projects'))}
  ${C.cyan('project list')}       List linked projects               ${C.dim('(alias: projects, project)')}
  ${C.cyan('project show <name>')} Show details for a project

${C.bold(C.brand('Agent & Daemon'))}
  ${C.cyan('agent start')}        Start the agent daemon             ${C.dim('(alias: start, up)')}
  ${C.cyan('agent stop')}         Stop the running agent             ${C.dim('(alias: stop, down)')}
  ${C.cyan('agent restart')}      Restart the agent                  ${C.dim('(alias: restart)')}
  ${C.cyan('agent status')}       Show agent + channel + DB status   ${C.dim('(alias: status, ps, top, agent)')}
  ${C.cyan('agent clean')}        Clean stale PID/status and daemon  ${C.dim('(alias: clean, kill)')}
  ${C.cyan('  clean --audit')}    Reset the audit trail + floor anchor${C.dim(' (destructive, needs --force)')}
  ${C.cyan('agent rotate-token')} Mint a new agent token (keeps ID)  ${C.dim('--yes to skip prompt')}
  ${C.cyan('agent unlink')}       Clear this machine's cloud link     ${C.dim('--yes to skip prompt')}

${C.bold(C.brand('Service & Autostart'))}
  ${C.cyan('service install')}    Install 24/7 background service for this OS
  ${C.cyan('service start')}      Start the background service
  ${C.cyan('service status')}     Check service running status
  ${C.cyan('service pm2')}        Show universal PM2 supervisor setup

${C.bold(C.brand('Configuration'))}
  ${C.cyan('config [show]')}      Show machine configuration         ${C.dim('(alias: config, --token to reveal)')}
  ${C.cyan('config get <key>')}   Get config value (${C.dim('agent_token masked')})
  ${C.cyan('config set <k> <v>')} Update config setting (cloud_url, log_level, etc.)
  ${C.cyan('config path')}        Show config & runtime file paths

${C.bold(C.brand('Setup & Ops'))}
  ${C.cyan('init')}               First-time setup on this machine
  ${C.cyan('debug')}              Deep diagnostic debugger for network, TLS, & DBs
  ${C.cyan('doctor')}             Full diagnostic check              ${C.dim('(alias: doc, --fix to self-repair)')}
  ${C.cyan('link <project>')}     Pairing stub for browser projects
  ${C.cyan('logs')}               Interactive log viewer & audit logs ${C.dim('(alias: log, -f follow, -q search)')}
  ${C.cyan('audit verify')}       Verify audit log integrity         ${C.dim('(alias: verify)')}
  ${C.cyan('clear')}              Clear terminal and redraw status
  ${C.cyan('--version')}          Show version                       ${C.dim('(alias: -v)')}
  ${C.cyan('--help')}             Show this help                     ${C.dim('(alias: -h, help)')}
`;

class CLIError extends Error {
  constructor(public readonly exitCode: number, message: string) {
    super(message);
    this.name = 'CLIError';
  }
}

// Legacy colon-form commands, mapped to the new noun-verb form.
const LEGACY: Record<string, string> = {
  'db:ls': 'db list',
  'db:add': 'db add',
  'db:remove': 'db remove',
  'db:rm': 'db remove',
  'db:test': 'db test',
  'db:edit': 'db edit',
  'ls:projects': 'project list',
  'audit:verify': 'audit verify',
  'config:show': 'config show',
};

/** Alias map for quick one-word commands. */
const ALIASES: Record<string, string> = {
  'ls': 'db list',
  'add': 'db add',
  'rm': 'db remove',
  'test': 'db test',
  'ping': 'db ping',
  'edit': 'db edit',
  'query': 'db query',
  'connect': 'db connect',
  'projects': 'project list',
  'start': 'agent start',
  'stop': 'agent stop',
  'status': 'agent status',
  'ps': 'agent status',
  'top': 'agent status',
  'up': 'agent start',
  'down': 'agent stop',
  'restart': 'agent restart',
  'clean': 'agent clean',
  'kill': 'agent clean',
  'conf': 'config show',
  'cfg': 'config show',
  'doc': 'doctor',
  'log': 'logs',
  'verify': 'audit verify',
};

/** Multi-word command router used by the non-interactive (bin) entry point. */
async function runNamed(command: string, rest: string[]): Promise<number> {
  // Two-word command detection
  const twoWordHeads = new Set([
    'db list', 'db add', 'db edit', 'db remove', 'db test', 'db ping',
    'db show', 'db info', 'db logs', 'db query', 'db connect',
    'project list', 'project show',
    'agent start', 'agent stop', 'agent status', 'agent restart', 'agent clean',
    'agent rotate-token', 'agent unlink',
    'config show', 'config get', 'config set', 'config path',
    'audit verify',
  ]);

  let head = command;
  let args = rest;
  if (rest.length > 0) {
    const candidate = `${command} ${rest[0]}`;
    if (twoWordHeads.has(candidate)) {
      head = candidate;
      args = rest.slice(1);
    }
  }

  // If head wasn't a two-word match, check aliases
  if (head === command && ALIASES[command]) {
    head = ALIASES[command];
  }

  // Single-noun defaults
  if (head === 'db') {
    head = args.length === 0 ? 'db list' : 'db';
  }
  if (head === 'agent') head = 'agent status';
  if (head === 'project') head = 'project list';
  if (head === 'audit') head = 'audit verify';
  if (head === 'config') head = 'config';

  switch (head) {
    case 'init': await runInit(args); break;
    case 'db': await runDb(args); break;
    case 'db add': await runDbAdd(args); break;
    case 'db list': await runDbList(args); break;
    case 'db show':
    case 'db info': await runDbShow(args); break;
    case 'db logs': await runDbLogs(args); break;
    case 'db query': await runDbQuery(args); break;
    case 'db connect': await runDbConnect(args); break;
    case 'db remove': await runDbRemove(args); break;
    case 'db test': await runDbTest(args); break;
    case 'db ping': await runDbPing(args); break;
    case 'db edit': await runDbEdit(args); break;
    case 'project list': await runProjectList(args); break;
    case 'project show': await runProjectShow(args); break;
    case 'agent start': await runStart(args); break;
    case 'agent stop': await runStop(args); break;
    case 'agent status': await runStatus(args); break;
    case 'agent restart': await runRestart(args); break;
    case 'agent clean': await runClean(args); break;
    case 'agent rotate-token': await runAgentRotateToken(args); break;
    case 'agent unlink': await runAgentUnlink(args); break;
    case 'doctor': await runDoctor(args); break;
    case 'debug': await runDebug(args); break;
    case 'service': await runService(args); break;
    case 'service install': await runService(['install', ...args]); break;
    case 'service start': await runService(['start', ...args]); break;
    case 'service stop': await runService(['stop', ...args]); break;
    case 'service status': await runService(['status', ...args]); break;
    case 'service uninstall':
    case 'service remove': await runService(['uninstall', ...args]); break;
    case 'service pm2': await runService(['pm2', ...args]); break;
    case 'config': await runConfig(args); break;
    case 'config show': await runConfigShow(args); break;
    case 'config get': await runConfigGet(args); break;
    case 'config set': await runConfigSet(args); break;
    case 'config path': await runConfigPath(); break;
    case 'link': await runLink(args); break;
    case 'logs': await runLogs(args); break;
    case 'audit verify': await runAuditVerify(args); break;
    case 'clear': clearScreen(); printBanner(); break;
    default:
      console.error(`\n  ${C.yellow('Unknown command:')} ${C.white(command)}`);
      console.error(`  ${C.dim('Run')} ${C.cyan('pg-connector --help')} ${C.dim('for usage.')}\n`);
      return 1;
  }
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  const args = argv.slice(2);
  const command = args[0];
  const rest = args.slice(1);

  // Handle --internal-daemon before any command parsing
  if (args.includes('--internal-daemon')) {
    const cleanArgs = args.filter((a) => a !== '--internal-daemon');
    await runStart(cleanArgs);
    return 0;
  }

  // No args, or --interactive / -i → drop into interactive REPL
  if (!command || command === '--interactive' || command === '-i') {
    return startInteractive();
  }

  if (command === '--help' || command === '-h' || command === 'help') {
    console.log(HELP_TEXT);
    return 0;
  }

  if (command === '--version' || command === '-v') {
    console.log(VERSION);
    return 0;
  }

  // Legacy colon-form compatibility.
  if (LEGACY[command]) {
    console.error(`\n  ${C.yellow('Note:')} ${C.dim(`"${command}" is now "${LEGACY[command]}". The old form still works.`)}\n`);
    return runNamed(LEGACY[command], rest);
  }

  try {
    return await runNamed(command, rest);
  } catch (err) {
    if (err instanceof CLIError) {
      return err.exitCode;
    }
    if (err && typeof err === 'object' && '__exitCode' in err) {
      return (err as { __exitCode: number }).__exitCode;
    }
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\n  ${C.red('Error:')} ${message}\n`);
    return 1;
  }
}

// Only auto-run when this module is the entry point, not when imported
if (require.main === module) {
  main(process.argv).then((code) => process.exit(code)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
