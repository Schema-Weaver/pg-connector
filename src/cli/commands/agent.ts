import { runStart } from './start';
import { runStop } from './stop';
import { runStatus } from './status';
import { runClean } from './clean';
import { loadMachineConfig, saveMachineConfig, MachineConfig } from '../../config/machine-config';
import { generateAgentToken, isDevToken, validateAgentTokenFormat } from '../../config/token';
import { redactSecrets } from '../../config/schema';
import { getPidFilePath } from '../../config/paths';
import { isProcessAlive, readPidFile } from '../daemon/pid-file';
import { askConfirm, closePrompts, isReplMode } from '../prompt';
import { C, S, box } from '../ui';

export { runStart, runStop, runStatus, runClean };

function exit_(code: number): never {
  closePrompts();
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runRestart(args: string[]): Promise<void> {
  await runStop(args);
  await runStart(args);
}

/** Result of a token rotation. `token` must be shown to the operator once. */
export interface AgentCommandResult {
  agent_id: string;
  token: string;
  previous_agent_id: string;
  previous_token_masked: string;
}

/** Masks an agent token for display. The full value is never echoed. */
function maskToken(token: string): string {
  if (!token || token.length <= 12) return '***';
  return `${token.slice(0, 10)}...${token.slice(-4)}`;
}

/**
 * Mints a new agent token, keeps `agent_id` stable so cloud-side project links
 * survive, and returns the new token. Never logs the token; callers decide how
 * to display it, and it must be displayed exactly once.
 */
export function rotateAgentToken(): AgentCommandResult {
  let config: MachineConfig;
  try {
    config = loadMachineConfig();
  } catch (err) {
    throw new Error(
      `Cannot rotate the agent token: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const previous = config.agent_token;
  const previousAgentId = config.agent_id;
  const next = generateAgentToken();
  if (!validateAgentTokenFormat(next)) {
    throw new Error('Generated token failed its own format check; refusing to write it.');
  }
  if (next === previous) {
    throw new Error('Generated token matched the current token; refusing to write it.');
  }

  config.agent_token = next;
  saveMachineConfig(config);

  return {
    agent_id: config.agent_id,
    token: next,
    previous_agent_id: previousAgentId,
    previous_token_masked: maskToken(previous),
  };
}

async function agentRunning(): Promise<boolean> {
  const info = await readPidFile({ path: getPidFilePath() });
  return info !== null && isProcessAlive(info.pid);
}

function printTokenOnce(token: string, heading: string): void {
  console.log();
  console.log(
    box(`  ${C.bold(heading)}\n\n  ${C.white(token)}`, {
      style: 'single',
      borderColor: C.brand,
      width: 54,
    }),
  );
  console.log();
}

/**
 * `sw-agent agent rotate-token` — issues a replacement token for this agent
 * without changing `agent_id`.
 */
export async function runAgentRotateToken(args: string[] = []): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log();
    console.log(`  ${C.bold('Rotate the agent token')}`);
    console.log();
    console.log(`    ${C.cyan('agent rotate-token')} [--yes]`);
    console.log();
    console.log(
      `  ${C.dim('Mints a new token, prints it once, and keeps agent_id so cloud-side')}`,
    );
    console.log(`  ${C.dim('project links are not orphaned.')}`);
    console.log();
    exit_(0);
  }

  let config: MachineConfig;
  try {
    config = loadMachineConfig();
  } catch (err) {
    console.log(`  ${C.red(S.cross)} ${redact(err, '')}`);
    console.log(`  ${C.dim('Run')} ${C.cyan('init')} ${C.dim('first.')}`);
    exit_(1);
  }

  const wasRunning = await agentRunning();

  console.log();
  console.log(`  ${C.bold('Rotate agent token')}`);
  console.log(`    Agent: ${C.cyan(config.agent_id)}`);
  console.log(`    Old:   ${C.dim(maskToken(config.agent_token))}`);
  console.log();

  if (isDevToken(config.agent_token)) {
    console.log(
      `  ${C.yellow(S.warning)} ${C.yellow('This machine is using the local development token, which is not a secret.')}`,
    );
    console.log();
  }

  if (wasRunning) {
    console.log(
      `  ${C.yellow(S.warning)} ${C.yellow('A running agent keeps using the old token until it is restarted.')}`,
    );
    console.log();
  }

  const confirmed =
    args.includes('--yes') || args.includes('-y')
      ? true
      : await askConfirm(
          C.red('Rotate now? The old token stops being used by this machine.'),
          false,
        );
  if (!confirmed) {
    console.log(`  ${C.dim('Aborted. Token unchanged.')}`);
    console.log();
    exit_(0);
  }

  let result: AgentCommandResult;
  try {
    result = rotateAgentToken();
  } catch (err) {
    console.log(`  ${C.red(S.cross)} ${redact(err, '')}`);
    exit_(1);
  }

  printTokenOnce(result.token, 'New agent token');

  console.log(
    `  ${C.green(S.check)} Token rotated. ${C.dim('Agent ID unchanged:')} ${C.cyan(result.agent_id)}`,
  );
  console.log();
  console.log(
    `  ${C.yellow(S.warning)} ${C.brightYellow('Shown once. Update the IDE/browser pairing with it now.')}`,
  );
  console.log(`  ${C.dim('Rotate again if it reaches a log, a backup, or a shell history file.')}`);
  if (wasRunning) {
    console.log(
      `  ${C.dim('Next:')} ${C.cyan('agent restart')} ${C.dim('so the running agent picks up the new token.')}`,
    );
  }
  console.log();
  console.log(
    `  ${C.dim('The cloud cannot revoke the old token from here; see')} ${C.cyan('agent unlink --help')}${C.dim('.')}`,
  );
  console.log();
  exit_(0);
}

/**
 * `sw-agent agent unlink` — drops this machine's local link to the cloud by
 * rotating the token away and clearing the credential from local state.
 */
export async function runAgentUnlink(args: string[] = []): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log();
    console.log(`  ${C.bold('Unlink this agent from the cloud')}`);
    console.log();
    console.log(`    ${C.cyan('agent unlink')} [--yes]`);
    console.log();
    console.log(
      `  ${C.dim('Rotates the local token so this machine can no longer authenticate,')}`,
    );
    console.log(`  ${C.dim('and keeps agent_id so cloud-side project links are not orphaned.')}`);
    console.log();
    console.log(`  ${C.yellow('Note:')} this does not revoke the old token on the server.`);
    console.log(`  ${C.dim('An operator must remove this agent from the cloud console as well.')}`);
    console.log();
    exit_(0);
  }

  let config: MachineConfig;
  try {
    config = loadMachineConfig();
  } catch (err) {
    console.log(`  ${C.red(S.cross)} ${redact(err, '')}`);
    exit_(1);
  }

  const wasRunning = await agentRunning();

  console.log();
  console.log(`  ${C.bold('Unlink agent')} ${C.cyan(config.agent_id)}`);
  console.log();
  console.log(
    `  ${C.dim('A new local token will be generated; the current one stops being used here.')}`,
  );
  console.log(
    `  ${C.yellow('Server-side revocation is out of scope for the CLI: remove this agent in the cloud console too.')}`,
  );
  if (wasRunning) {
    console.log(
      `  ${C.yellow(S.warning)} ${C.yellow('An agent is running (pid file present). Stop it with')} ${C.cyan('agent stop')} ${C.yellow('after unlinking.')}`,
    );
  }
  console.log();

  const confirmed =
    args.includes('--yes') || args.includes('-y')
      ? true
      : await askConfirm(C.red('Unlink this agent?'), false);
  if (!confirmed) {
    console.log(`  ${C.dim('Aborted. Nothing changed.')}`);
    console.log();
    exit_(0);
  }

  try {
    rotateAgentToken();
  } catch (err) {
    console.log(`  ${C.red(S.cross)} ${redact(err, '')}`);
    exit_(1);
  }

  console.log();
  console.log(
    `  ${C.green(S.check)} ${C.brightGreen('Local link cleared.')} ${C.dim('A fresh token was generated and not printed.')}`,
  );
  console.log(
    `  ${C.dim('Re-link with')} ${C.cyan('config show --reveal')} ${C.dim('or')} ${C.cyan('init')}${C.dim('.')}`,
  );
  console.log();
  exit_(0);
}

function redact(err: unknown, token: string): string {
  const message = err instanceof Error ? err.message : String(err);
  return redactSecrets(message, token);
}
