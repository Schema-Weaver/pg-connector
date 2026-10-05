import { askConfirm, closePrompts, isReplMode } from '../prompt';
import { removeDbEntry, findDbEntry } from '../../config/db-config';
import { C, S, check, cross } from '../ui';

function exit_(code: number): never {
  closePrompts();
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDbRemove(args: string[]): Promise<void> {
  const skipConfirm = args.includes('--yes') || args.includes('-y');
  const alias = args.find((a) => a !== '--yes' && a !== '-y');

  if (!alias) {
    console.log(`  ${C.yellow('Usage:')} ${C.white('db remove <alias> [--yes]')}`);
    exit_(1);
  }

  const entry = findDbEntry(alias);
  if (!entry) {
    console.log(`  ${C.red(S.cross)} Database alias "${C.white(alias)}" not found.`);
    exit_(1);
  }

  console.log();
  console.log(`  ${C.bold('Remove database')} ${C.white(alias)}`);
  console.log(`    Project: ${C.white(entry.project_name)}`);
  console.log(`    Host:    ${C.dim(`${entry.host}:${entry.port}`)}`);
  console.log();

  let doRemove = skipConfirm;
  if (!doRemove) {
    doRemove = await askConfirm(C.red('Are you sure?'), false);
  }

  if (doRemove) {
    const removed = removeDbEntry(alias);
    if (removed) {
      console.log(`  ${check(`Removed ${C.white(alias)}.`)}`);
    } else {
      console.log(`  ${cross('Failed to remove database.')}`);
      exit_(1);
    }
  } else {
    console.log(`  ${C.dim('Aborted.')}`);
  }

  console.log();
  exit_(0);
}
