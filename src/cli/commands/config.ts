import { loadMachineConfig, saveMachineConfig, MachineConfig, PermissionLevel } from '../../config/machine-config';
import {
  getAgentHome,
  getMachineConfigPath,
  getDbConfigPath,
  getPidFilePath,
  getStatusFilePath,
  getDaemonLogPath,
  getAuditLogPath,
} from '../../config/paths';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

function redactToken(token: string): string {
  if (!token) return '***';
  if (token.length <= 12) return '***';
  return `${token.slice(0, 10)}...${token.slice(-4)}`;
}

export async function runConfigShow(args: string[] = []): Promise<void> {
  try {
    const config = loadMachineConfig();
    const revealToken = args.includes('--token') || args.includes('-t');
    const json = args.includes('--json') || args.includes('-j');

    if (json) {
      console.log(
        JSON.stringify(
          {
            ...config,
            agent_token: revealToken ? config.agent_token : redactToken(config.agent_token),
          },
          null,
          2
        )
      );
      exit_(0);
    }

    console.log();
    console.log(`  ${C.bold(C.brand('Machine Configuration'))}`);
    console.log();
    console.log(`    ${C.bold('Agent ID:')}    ${C.cyan(config.agent_id)}`);
    console.log(`    ${C.bold('Label:')}       ${C.white(config.machine_label)}`);
    console.log(`    ${C.bold('Cloud URL:')}   ${C.white(config.cloud_url)}`);
    console.log(`    ${C.bold('Permission:')}  ${C.yellow(config.default_permission)}`);
    console.log(`    ${C.bold('Log level:')}   ${C.white(config.log_level)}`);
    console.log(
      `    ${C.bold('Token:')}       ${
        revealToken ? C.white(config.agent_token) : C.dim(redactToken(config.agent_token) + ' (use --token to reveal)')
      }`
    );
    console.log(`    ${C.bold('Config path:')} ${C.dim(getMachineConfigPath())}`);

    if (revealToken) {
      console.log();
      console.log(`  ${C.yellow(S.warning)} ${C.yellow('Token revealed because --token was provided.')}`);
    }

    console.log();
  } catch (err: any) {
    console.log(`  ${C.red('Error:')} ${err.message}`);
  }
  exit_(0);
}

export async function runConfigGet(args: string[]): Promise<void> {
  const key = args[0];
  if (!key) {
    console.log(`  ${C.yellow('Usage:')} ${C.cyan('config get <key>')}`);
    console.log(`  ${C.dim('Available keys: agent_id, machine_label, cloud_url, default_permission, log_level, agent_token')}`);
    exit_(1);
  }

  try {
    const config = loadMachineConfig() as Record<string, any>;
    if (!(key in config)) {
      console.log(`  ${C.yellow(S.warning)} Unknown config key: ${C.white(key)}`);
      console.log(`  ${C.dim('Available keys: agent_id, machine_label, cloud_url, default_permission, log_level, agent_token')}`);
      exit_(1);
    }

    let val = config[key];
    if (key === 'agent_token' && !args.includes('--token') && !args.includes('-t')) {
      val = redactToken(val);
    }

    if (args.includes('--json') || args.includes('-j')) {
      console.log(JSON.stringify({ [key]: val }, null, 2));
    } else {
      console.log(typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val));
    }
  } catch (err: any) {
    console.log(`  ${C.red('Error:')} ${err.message}`);
    exit_(1);
  }
  exit_(0);
}

export async function runConfigSet(args: string[]): Promise<void> {
  const key = args[0];
  const value = args[1];

  if (!key || value === undefined) {
    console.log(`  ${C.yellow('Usage:')} ${C.cyan('config set <key> <value>')}`);
    console.log(`  ${C.dim('Modifiable keys: cloud_url, default_permission, log_level, machine_label')}`);
    exit_(1);
  }

  try {
    const config = loadMachineConfig();

    switch (key) {
      case 'cloud_url':
        if (!value.startsWith('wss://') && !value.startsWith('ws://')) {
          console.log(`  ${C.red('Error:')} cloud_url must start with ws:// or wss://`);
          exit_(1);
        }
        config.cloud_url = value;
        break;

      case 'log_level':
        if (!['debug', 'info', 'warn', 'error'].includes(value)) {
          console.log(`  ${C.red('Error:')} log_level must be one of: debug, info, warn, error`);
          exit_(1);
        }
        config.log_level = value as MachineConfig['log_level'];
        break;

      case 'default_permission':
        if (!['read_only', 'auto_upgrade', 'manual', 'full'].includes(value)) {
          console.log(`  ${C.red('Error:')} default_permission must be one of: read_only, auto_upgrade, manual, full`);
          exit_(1);
        }
        config.default_permission = value as PermissionLevel;
        break;

      case 'machine_label':
        if (!/^[a-zA-Z0-9_-]{1,64}$/.test(value)) {
          console.log(`  ${C.red('Error:')} machine_label must be 1-64 alphanumeric characters, dashes or underscores`);
          exit_(1);
        }
        config.machine_label = value;
        break;

      default:
        console.log(`  ${C.yellow(S.warning)} Cannot modify key: ${C.white(key)}`);
        console.log(`  ${C.dim('Modifiable keys: cloud_url, default_permission, log_level, machine_label')}`);
        exit_(1);
    }

    saveMachineConfig(config);
    console.log(`  ${C.green(S.check)} Updated ${C.cyan(key)} = ${C.white(value)}`);
  } catch (err: any) {
    console.log(`  ${C.red('Error:')} ${err.message}`);
    exit_(1);
  }
  exit_(0);
}

export async function runConfigPath(): Promise<void> {
  console.log();
  console.log(`  ${C.bold(C.brand('Configuration & State Paths'))}`);
  console.log();
  console.log(`    ${C.bold('Home directory:')}    ${C.white(getAgentHome())}`);
  console.log(`    ${C.bold('Machine config:')}    ${C.white(getMachineConfigPath())}`);
  console.log(`    ${C.bold('Databases config:')}  ${C.white(getDbConfigPath())}`);
  console.log(`    ${C.bold('PID file:')}          ${C.white(getPidFilePath())}`);
  console.log(`    ${C.bold('Status file:')}        ${C.white(getStatusFilePath())}`);
  console.log(`    ${C.bold('Daemon log:')}         ${C.white(getDaemonLogPath())}`);
  console.log(`    ${C.bold('Audit log:')}          ${C.white(getAuditLogPath())}`);
  console.log();
  exit_(0);
}

export async function runConfig(args: string[] = []): Promise<void> {
  const sub = args[0];
  const rest = args.slice(1);

  if (!sub || sub === 'show') {
    return runConfigShow(sub === 'show' ? rest : args);
  }
  if (sub === 'get') {
    return runConfigGet(rest);
  }
  if (sub === 'set') {
    return runConfigSet(rest);
  }
  if (sub === 'path' || sub === 'paths') {
    return runConfigPath();
  }
  if (sub === '--help' || sub === '-h') {
    console.log();
    console.log(`  ${C.bold('Config Commands')}`);
    console.log();
    console.log(`    ${C.cyan('config [show]')}           Show current machine configuration (${C.dim('--token, --json')})`);
    console.log(`    ${C.cyan('config get <key>')}        Get value of a config key`);
    console.log(`    ${C.cyan('config set <key> <val>')}  Update configuration key`);
    console.log(`    ${C.cyan('config path')}             Show config and state file paths`);
    console.log();
    exit_(0);
  }

  // If argument starts with flag (e.g. --token or --json), run show
  if (sub.startsWith('-')) {
    return runConfigShow(args);
  }

  console.log(`  ${C.yellow('Unknown config subcommand:')} ${C.white(sub)}`);
  console.log(`  ${C.dim('Subcommands: show, get, set, path')}`);
  exit_(1);
}
