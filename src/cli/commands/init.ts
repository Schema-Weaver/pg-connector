import * as os from 'os';
import { ask, askChoice, askConfirm, isReplMode } from '../prompt';
import {
  createDefaultMachineConfig,
  saveMachineConfig,
  machineConfigExists,
} from '../../config/machine-config';
import { getMachineConfigPath, getSwAgentDir } from '../../config/paths';
import { generateAgentToken } from '../../config/token';
import { C, S, separator, check, arrow, box } from '../ui';
import { copyToClipboard } from '../ui/clipboard';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runInit(_args: string[]): Promise<void> {
  if (machineConfigExists()) {
    const overwrite = await askConfirm(
      C.yellow('Config already exists. Overwrite?'),
      false,
    );
    if (!overwrite) {
      console.log(`  ${C.yellow(S.warning)} Aborted.`);
      exit_(0);
    }
  }

  console.log();
  console.log(C.bold(C.brand('  Schema Weaver Agent — First Time Setup')));
  console.log(separator('', 50));
  console.log();

  // Step 1: Machine label
  const defaultLabel = os.hostname().toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '');
  let machineLabel = '';
  for (;;) {
    machineLabel = await ask('Machine label', defaultLabel);
    if (
      machineLabel.trim() !== '' &&
      /^[a-zA-Z0-9_-]+$/.test(machineLabel) &&
      machineLabel.length <= 64
    ) {
      break;
    }
    console.log(
      `  ${C.red(S.cross)} Use letters, numbers, hyphens, underscores only (max 64 chars).`,
    );
  }
  console.log(`  ${check(`Machine label: ${C.white(machineLabel)}`)}`);
  console.log();

  // Step 2: Cloud URL
  let cloudUrl = '';
  for (;;) {
    cloudUrl = await ask('Cloud URL', 'wss://api.schemaweaver.dev');
    if (
      cloudUrl.trim() !== '' &&
      (cloudUrl.startsWith('wss://') || cloudUrl.startsWith('ws://'))
    ) {
      break;
    }
    console.log(`  ${C.red(S.cross)} URL must start with wss:// or ws://`);
  }
  console.log(`  ${check(`Cloud URL: ${C.white(cloudUrl)}`)}`);
  console.log();

  // Step 3: Agent permission
  const permOptions = ['read_only', 'auto_upgrade', 'manual', 'full'];
  const permAnswer = await askChoice('Permission level', permOptions, 'auto_upgrade');
  console.log(`  ${check(`Permission: ${C.yellow(permAnswer)}`)}`);
  console.log();

  // Step 4: Log level
  const logOptions = ['debug', 'info', 'warn', 'error'];
  const logLevel = await askChoice('Log level', logOptions, 'info');
  console.log(`  ${check(`Log level: ${C.white(logLevel)}`)}`);
  console.log();

  // Step 5: Generate token locally (no cloud interaction needed)
  const token = generateAgentToken();

  const config = createDefaultMachineConfig({
    machineLabel,
    cloudUrl,
    permission: permAnswer as any,
    token,
  });

  config.log_level = logLevel as any;

  // Summary — Agent ID and Token each in their own highlighted box.
  console.log(separator('Summary', 50));
  console.log();

  console.log(
    box(`  ${C.bold('Agent ID')}\n\n  ${C.cyan(config.agent_id)}`, {
      style: 'single',
      borderColor: C.brand,
      width: 54,
    }),
  );
  console.log();

  console.log(
    box(`  ${C.bold('Token')}  ${C.dim('(use this to link the IDE)')}\n\n  ${C.white(token)}`, {
      style: 'single',
      borderColor: C.brand,
      width: 54,
    }),
  );
  console.log();

  // Attempt clipboard copy of the token.
  const clip = copyToClipboard(token);
  if (clip.copied) {
    console.log(
      `  ${C.green(S.check)} ${C.brightGreen('Token copied to clipboard')} ${C.dim(`(via ${clip.method})`)}`,
    );
  } else {
    console.log(`  ${C.dim('Tip:')} ${C.white('Select and copy the token above manually.')}`);
  }

  console.log();
  console.log(`  ${C.yellow(S.warning)} ${C.brightYellow('Token shown once. Keep it safe to link browser projects.')}`);
  console.log();

  console.log(`  ${C.bold('Paths:')}`);
  console.log(`    Config: ${C.dim(getMachineConfigPath())}`);
  console.log(`    Home:   ${C.dim(getSwAgentDir())}`);
  console.log();

  const save = await askConfirm(C.brand('Save configuration?'), true);
  if (save) {
    saveMachineConfig(config);
    console.log();
    console.log(`  ${C.green(S.check)} ${C.brightGreen('Configuration saved successfully!')}`);
    console.log();
    console.log(C.bold('  Next steps:'));
    console.log(arrow('db add      — Add a database', C.cyan));
    console.log(arrow('agent start — Start the agent', C.cyan));
    console.log(arrow('agent status— Check agent status', C.cyan));
    console.log();
  } else {
    console.log();
    console.log(`  ${C.yellow(S.warning)} Setup aborted. No changes were made.`);
    console.log();
  }

  exit_(0);
}
