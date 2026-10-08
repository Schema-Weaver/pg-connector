import {
  loadMachineConfig,
  mutateMachineConfig,
  SAFEST_PERMISSION,
  MachineConfig,
  PermissionLevel,
} from '../../config/machine-config';
import { isSecureCloudUrl } from '../../config/schema';
import {
  getAgentHome,
  getMachineConfigPath,
  getDbConfigPath,
  getPidFilePath,
  getStatusFilePath,
  getDaemonLogPath,
  getErrorsPath,
  getAuditLogPath,
  getCredentialKeyPath,
} from '../../config/paths';
import { isReplMode, askConfirm, isInteractive } from '../prompt';
import { C, S } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

/** Keeps the REPL/CLI exit sentinel from being swallowed by a catch block. */
function rethrowExit(err: unknown): void {
  if (err && typeof err === 'object' && '__exitCode' in err) {
    throw err;
  }
}

function redactToken(token: string): string {
  if (!token) return '***';
  if (token.length <= 12) return '***';
  return `${token.slice(0, 10)}...${token.slice(-4)}`;
}

/** Flags that print the raw agent token. `--token` is the legacy spelling. */
const REVEAL_FLAGS = ['--reveal', '--token', '-t'];

function wantsReveal(args: string[]): boolean {
  return args.some((a) => REVEAL_FLAGS.includes(a));
}

/**
 * The agent token is a permanent bearer credential. Printing it is allowed,
 * but never silently: the exposure is named on stderr (so a redirected stdout
 * stays clean) and an interactive caller is asked first.
 */
async function confirmReveal(args: string[]): Promise<boolean> {
  console.error(
    `  ${C.yellow(S.warning)} ${C.yellow('Revealing the agent token.')} ${C.yellow('It is a permanent bearer credential: it lands in your shell history,')}`,
  );
  console.error(
    `  ${C.yellow('terminal scrollback and CI job logs. Anyone who reads it can act as this agent.')}`,
  );
  if (args.includes('--yes') || args.includes('-y') || !isInteractive()) return true;
  return askConfirm(C.red('Print the raw agent token to stdout?'), false);
}

export async function runConfigShow(args: string[] = []): Promise<void> {
  try {
    const config = loadMachineConfig();
    const revealToken = wantsReveal(args);
    const json = args.includes('--json') || args.includes('-j');

    if (revealToken && !(await confirmReveal(args))) {
      console.log(`  ${C.yellow(S.warning)} Token not revealed.`);
      exit_(1);
    }

    if (json) {
      console.log(
        JSON.stringify(
          {
            ...config,
            agent_token: revealToken ? config.agent_token : redactToken(config.agent_token),
          },
          null,
          2,
        ),
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
        revealToken
          ? C.white(config.agent_token)
          : C.dim(redactToken(config.agent_token) + ' (use --reveal to print it)')
      }`,
    );
    console.log(`    ${C.bold('Config path:')} ${C.dim(getMachineConfigPath())}`);

    if (revealToken) {
      console.log();
      console.log(
        `  ${C.yellow(S.warning)} ${C.yellow('Token revealed because --token was provided.')}`,
      );
    }

    console.log();
  } catch (err: unknown) {
    rethrowExit(err);
    console.log(`  ${C.red('Error:')} ${err instanceof Error ? err.message : String(err)}`);
  }
  exit_(0);
}

export async function runConfigGet(args: string[]): Promise<void> {
  const key = args[0];
  if (!key) {
    console.log(`  ${C.yellow('Usage:')} ${C.cyan('config get <key>')}`);
    console.log(
      `  ${C.dim('Available keys: agent_id, machine_label, cloud_url, default_permission, log_level, agent_token')}`,
    );
    exit_(1);
  }

  try {
    // `config get` accepts any key, so the validated config is read as a
    // key/value map; the values themselves stay `unknown` and are stringified
    // only at the point of output.
    const config = loadMachineConfig() as unknown as Record<string, unknown>;
    if (!(key in config)) {
      console.log(`  ${C.yellow(S.warning)} Unknown config key: ${C.white(key)}`);
      console.log(
        `  ${C.dim('Available keys: agent_id, machine_label, cloud_url, default_permission, log_level, agent_token')}`,
      );
      exit_(1);
    }

    const val = config[key];
    if (key === 'agent_token') {
      // The token is a permanent bearer credential, so stdout is not assumed
      // to be private: masked by default, and printed only on an explicit
      // --reveal that names the exposure (and is confirmed on a terminal).
      if (!wantsReveal(args)) {
        const masked = redactToken(String(val));
        if (args.includes('--json') || args.includes('-j')) {
          console.log(JSON.stringify({ [key]: masked }, null, 2));
        } else {
          console.log(masked);
        }
        console.log(
          `  ${C.dim('Masked. Pass')} ${C.cyan('--reveal')} ${C.dim('to print the raw token, or use')} ${C.cyan('agent rotate-token')}${C.dim(' to mint a new one.')}`,
        );
        exit_(0);
      }
      if (!(await confirmReveal(args))) {
        console.log(`  ${C.yellow(S.warning)} Token not revealed.`);
        exit_(1);
      }
      if (args.includes('--json') || args.includes('-j')) {
        console.log(JSON.stringify({ [key]: val }, null, 2));
      } else {
        console.log(String(val));
      }
      exit_(0);
    }

    if (args.includes('--json') || args.includes('-j')) {
      console.log(JSON.stringify({ [key]: val }, null, 2));
    } else {
      console.log(typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val));
    }
  } catch (err: unknown) {
    rethrowExit(err);
    console.log(`  ${C.red('Error:')} ${err instanceof Error ? err.message : String(err)}`);
    exit_(1);
  }
  exit_(0);
}

export async function runConfigSet(args: string[]): Promise<void> {
  const key = args[0];
  const value = args[1];
  const allowInsecureTransport = args.includes('--insecure-transport');

  if (!key || value === undefined) {
    console.log(`  ${C.yellow('Usage:')} ${C.cyan('config set <key> <value>')}`);
    console.log(
      `  ${C.dim('Modifiable keys: cloud_url, default_permission, log_level, machine_label')}`,
    );
    console.log(`  ${C.dim('To replace the agent token use')} ${C.cyan('agent rotate-token')}`);
    exit_(1);
  }

  try {
    mutateMachineConfig((config) => {
      switch (key) {
        case 'cloud_url':
          if (!isSecureCloudUrl(value)) {
            console.log(`  ${C.red('Error:')} cloud_url must be a wss:// URL`);
            console.log(
              `  ${C.dim('ws:// and http:// are refused: the agent token would be sent in cleartext.')}`,
            );
            if (allowInsecureTransport) {
              console.log(
                `  ${C.red(S.warning)} ${C.yellow('--insecure-transport')} ${C.yellow('was passed but plaintext cloud URLs are no longer supported.')} ${C.yellow('Use a --relay override on a dev token instead.')}`,
              );
            }
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
            console.log(
              `  ${C.red('Error:')} default_permission must be one of: read_only, auto_upgrade, manual, full`,
            );
            exit_(1);
          }
          if (value !== SAFEST_PERMISSION) {
            console.log(
              `  ${C.yellow(S.warning)} ${C.yellow('Opting out of the least-privileged default:')} ${C.white(value)} ${C.yellow('allows write access to every linked database.')}`,
            );
          }
          config.default_permission = value as PermissionLevel;
          break;

        case 'machine_label':
          if (!/^[a-zA-Z0-9_-]{1,64}$/.test(value)) {
            console.log(
              `  ${C.red('Error:')} machine_label must be 1-64 alphanumeric characters, dashes or underscores`,
            );
            exit_(1);
          }
          config.machine_label = value;
          break;

        case 'agent_token':
          console.log(`  ${C.red('Error:')} agent_token is not directly settable`);
          console.log(
            `  ${C.dim('Use')} ${C.cyan('agent rotate-token')} ${C.dim('to mint a new token (keeps agent_id).')}`,
          );
          exit_(1);
          break;

        default:
          console.log(`  ${C.yellow(S.warning)} Cannot modify key: ${C.white(key)}`);
          console.log(
            `  ${C.dim('Modifiable keys: cloud_url, default_permission, log_level, machine_label')}`,
          );
          exit_(1);
      }
    });
    console.log(`  ${C.green(S.check)} Updated ${C.cyan(key)} = ${C.white(value)}`);
  } catch (err: unknown) {
    rethrowExit(err);
    console.log(`  ${C.red('Error:')} ${err instanceof Error ? err.message : String(err)}`);
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
  console.log(`    ${C.bold('Credential key:')}    ${C.white(getCredentialKeyPath())}`);
  console.log(`    ${C.bold('PID file:')}          ${C.white(getPidFilePath())}`);
  console.log(`    ${C.bold('Status file:')}        ${C.white(getStatusFilePath())}`);
  console.log(`    ${C.bold('Daemon log:')}         ${C.white(getDaemonLogPath())}`);
  console.log(`    ${C.bold('Error log:')}          ${C.white(getErrorsPath())}`);
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
    console.log(
      `    ${C.cyan('config [show]')}           Show current machine configuration (${C.dim('--reveal, --json')})`,
    );
    console.log(
      `    ${C.cyan('config get <key>')}        Get value of a config key (${C.dim('agent_token is masked unless --reveal')})`,
    );
    console.log(
      `    ${C.cyan('config set <key> <val>')}  Update configuration key (${C.dim('cloud_url, default_permission, log_level, machine_label')})`,
    );
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
