import * as os from 'os';
import * as path from 'path';
import { ask, askChoice, askConfirm, isReplMode } from '../prompt';
import {
  createDefaultMachineConfig,
  saveMachineConfig,
  machineConfigExists,
  SAFEST_PERMISSION,
  MachineConfig,
  PermissionLevel,
} from '../../config/machine-config';
import { isSecureCloudUrl } from '../../config/schema';
import { getMachineConfigPath, getSwAgentDir } from '../../config/paths';
import { generateAgentToken } from '../../config/token';
import { ensureAuditDir } from '../../audit/files';
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
    const overwrite = await askConfirm(C.yellow('Config already exists. Overwrite?'), false);
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
  const defaultLabel = os
    .hostname()
    .toLowerCase()
    .replace(/[^a-zA-Z0-9_-]/g, '');
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
    if (isSecureCloudUrl(cloudUrl.trim())) {
      cloudUrl = cloudUrl.trim();
      break;
    }
    console.log(`  ${C.red(S.cross)} URL must be wss:// with an explicit authority.`);
    console.log(
      `  ${C.dim('ws:// and http:// are refused: the agent token is a permanent bearer credential.')}`,
    );
  }
  console.log(`  ${check(`Cloud URL: ${C.white(cloudUrl)}`)}`);
  console.log();

  // Step 3: Agent permission — least privilege is the default and anything
  // above it is an explicit, announced opt-out.
  const permOptions = ['read_only', 'auto_upgrade', 'manual', 'full'];
  const permAnswer = await askChoice('Permission level', permOptions, SAFEST_PERMISSION);
  if (permAnswer !== SAFEST_PERMISSION) {
    console.log();
    console.log(
      `  ${C.yellow(S.warning)} ${C.brightYellow('Non-default permission selected:')} ${C.white(permAnswer)}`,
    );
    console.log(
      `  ${C.yellow('This grants write access to every database linked to this agent.')}`,
    );
    console.log(
      `  ${C.dim('Revoke later with')} ${C.cyan('config set default_permission read_only')}${C.dim('.')}`,
    );
  }
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
    permission: permAnswer as PermissionLevel,
    token,
  });

  config.log_level = logLevel as MachineConfig['log_level'];

  // Summary — Agent ID and Token each in their own highlighted box.
  console.log(separator('Summary', 50));
  console.log();

  console.log(
    box(
      `  ${C.bold('Agent ID')}\n\n  ${C.cyan(config.agent_id)}\n\n  ${C.dim('Cloud URL')}  ${C.white(config.cloud_url)}\n  ${C.dim('Permission')}  ${C.white(config.default_permission)}`,
      {
        style: 'single',
        borderColor: C.brand,
        width: 54,
      },
    ),
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
  console.log(
    `  ${C.yellow(S.warning)} ${C.brightYellow('Token shown once. Keep it safe to link browser projects.')}`,
  );
  console.log();

  console.log(`  ${C.bold('Paths:')}`);
  console.log(`    Config: ${C.dim(getMachineConfigPath())}`);
  console.log(`    Home:   ${C.dim(getSwAgentDir())}`);
  console.log();

  const save = await askConfirm(C.brand('Save configuration?'), true);
  if (save) {
    try {
      saveMachineConfig(config);
    } catch (err) {
      console.log();
      console.log(
        `  ${C.red(S.cross)} ${C.red('Failed to save configuration:')} ${err instanceof Error ? err.message : String(err)}`,
      );
      console.log();
      exit_(1);
    }
    // Provision the audit directory as part of setup (C-06). On a clean install
    // the first *writer* created it with a regular file's mode (0o600), which is
    // untraversable, so every append failed EACCES and the only thing that
    // repaired it was `doctor` — a troubleshooting command. The writer now
    // creates and self-heals the mode itself, but a fresh install should be
    // correct from the first write. A failure here is a warning, never a failed
    // setup: the operator must not be blocked from completing setup by a
    // directory the writer repairs on its own.
    try {
      await ensureAuditDir(path.join(getSwAgentDir(), 'audit'));
    } catch (err) {
      console.log();
      console.log(
        `  ${C.yellow(S.warning)} ${C.yellow('Could not pre-create the audit directory:')} ${err instanceof Error ? err.message : String(err)}`,
      );
      console.log(`  ${C.dim('Setup continues. The audit writer repairs the mode itself;')}`);
      console.log(`  ${C.dim('run')} ${C.cyan('doctor')}${C.dim(' to verify the audit trail.')}`);
    }
    const persisted = config;
    console.log();
    console.log(`  ${C.green(S.check)} ${C.brightGreen('Configuration saved successfully!')}`);
    console.log();
    console.log(C.bold('  Written to') + ` ${C.white(getMachineConfigPath())}`);
    console.log(
      `  ${C.dim('Permission:')} ${C.white(persisted.default_permission)}  ${C.dim('Cloud:')} ${C.white(persisted.cloud_url)}  ${C.dim('Agent:')} ${C.white(persisted.agent_id)}`,
    );
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
