/**
 * @roadmap Cloud project pairing — planned for v0.3.0.
 * Currently a stub that prints the agent ID and a message directing users
 * to manual IDE pairing via `config show --token`.
 */
import { loadMachineConfig } from '../../config/machine-config';
import { closePrompts, isReplMode } from '../prompt';
import { C, S } from '../ui';

export interface LinkOptions {
  project?: string;
}

function exit_(code: number): never {
  closePrompts();
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runLink(args: string[], opts: LinkOptions = {}): Promise<void> {
  const project = opts.project ?? args[0];

  let machineConfig;
  try {
    machineConfig = loadMachineConfig();
  } catch {
    console.log(`  ${C.red(S.cross)} Machine config not found. Run ${C.cyan('init')} first.`);
    exit_(1);
  }

  if (!project) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('link <project>')}`);
    exit_(1);
  }

  console.log();
  console.log(C.bold(C.brand('  Project Linking')));
  console.log();
  console.log(`    ${C.bold('Project:')} ${C.white(project)}`);
  console.log(`    ${C.bold('Agent:')}   ${C.cyan(machineConfig.agent_id)}`);
  console.log();
  console.log(`  ${C.yellow(S.warning)} ${C.yellow('Cloud project pairing is not implemented in this package yet.')}`);
  console.log(`  ${C.dim('Use')} ${C.cyan('config show --token')} ${C.dim('to reveal the token for manual IDE pairing.')}`);
  console.log();

  exit_(0);
}
