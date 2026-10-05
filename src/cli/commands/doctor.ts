import { loadMachineConfig } from '../../config/machine-config';
import { loadDatabasesConfig } from '../../config/db-config';
import { getSwAgentDir } from '../../config/paths';
import { DoctorCheck, runAllChecks, DoctorContext } from '../doctor/checks';
import { runAllFixes, FixResult } from '../doctor/fixes';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface DoctorOptions {
  json?: boolean;
}

export async function runDoctor(args: string[], opts: DoctorOptions = {}): Promise<void> {
  const json = opts.json || args.includes('--json') || args.includes('-j');
  const fix = args.includes('--fix');

  const swAgentDir = getSwAgentDir();
  let machineConfig = null;
  let databasesConfig = null;

  try {
    machineConfig = loadMachineConfig();
  } catch { /* ignore */ }

  try {
    databasesConfig = loadDatabasesConfig();
  } catch { /* ignore */ }

  const ctx: DoctorContext = {
    swAgentDir,
    machineConfig,
    databasesConfig,
    nodeVersion: process.version,
    platform: process.platform,
  };

  console.log();
  console.log(C.bold(C.brand('  SW Agent Diagnostics')));
  console.log();

  const checks = await runAllChecks(ctx);

  if (json) {
    console.log(JSON.stringify({ checks }, null, 2));
  } else {
    printResults(checks);
  }

  const hasFail = checks.some((c) => c.status === 'fail');
  const hasWarn = checks.some((c) => c.status === 'warn');

  console.log();
  if (hasFail) {
    console.log(`  ${C.red(S.cross)} ${C.brightRed('Some checks failed. Please fix the issues above.')}`);
  } else if (hasWarn) {
    console.log(`  ${C.yellow(S.warning)} ${C.yellow('Some checks passed with warnings.')}`);
  } else {
    console.log(`  ${C.green(S.check)} ${C.brightGreen('All checks passed!')}`);
  }
  console.log();

  // Self-repair mode: attempt safe fixes for stale files, missing dirs, perms.
  if (fix) {
    const fixes = await runAllFixes(ctx);
    console.log(C.bold(C.brand('  Self-repair')));
    console.log();
    if (json) {
      console.log(JSON.stringify({ checks, fixes }, null, 2));
    } else {
      printFixResults(fixes);
    }
    const applied = fixes.filter((f) => f.applied).length;
    console.log();
    if (applied > 0) {
      console.log(`  ${C.green(S.check)} Applied ${C.white(String(applied))} fix(es). Re-run ${C.cyan('doctor')} to verify.`);
    } else {
      console.log(`  ${C.dim('Nothing to fix — environment is already clean.')}`);
    }
    console.log();
  }

  exit_(hasFail ? 1 : 0);
}

function printFixResults(fixes: FixResult[]): void {
  const maxNameLen = Math.max(...fixes.map((f) => f.name.length));
  for (const f of fixes) {
    const name = f.name.padEnd(maxNameLen + 2);
    const detail = f.detail ? `  ${C.dim(f.detail)}` : '';
    if (f.applied) {
      console.log(`  ${C.green(S.check)} ${C.dim(name)}${detail}`);
    } else {
      console.log(`  ${C.gray(S.dotSmall)} ${C.dim(name)}${detail}`);
    }
  }
}

function printResults(checks: DoctorCheck[]): void {
  const maxNameLen = Math.max(...checks.map((c) => c.name.length));

  for (const checkItem of checks) {
    const name = checkItem.name.padEnd(maxNameLen + 2);
    const detail = checkItem.detail ? `  ${C.dim(checkItem.detail)}` : '';

    if (checkItem.status === 'pass') {
      console.log(`  ${C.green(S.check)} ${C.dim(name)}${detail}`);
    } else if (checkItem.status === 'fail') {
      console.log(`  ${C.red(S.cross)} ${C.white(name)}${detail}`);
    } else {
      console.log(`  ${C.yellow(S.warning)} ${C.white(name)}${detail}`);
    }
  }
}
