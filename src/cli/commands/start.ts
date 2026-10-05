import { spawn } from 'child_process';
import * as path from 'path';
import { loadMachineConfig } from '../../config/machine-config';
import { loadDatabasesConfig } from '../../config/db-config';
import { getDaemonLogPath, getPidFilePath, getStatusFilePath, getSwAgentDir } from '../../config/paths';
import { readPidFile, isProcessAlive } from '../daemon/pid-file';
import { waitForAgentReady } from '../daemon/readiness';
import { runAgent } from '../daemon/runtime';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface StartOptions {
  daemon?: boolean;
  relayUrl?: string;
}

export async function runStart(args: string[], opts: StartOptions = {}): Promise<void> {
  const foreground = args.includes('--foreground') || args.includes('--fg') || process.env.SW_AGENT_DAEMON === '1';
  const daemon = !foreground && (opts.daemon ?? true);

  const swAgentDir = getSwAgentDir();
  const pidFile = getPidFilePath();
  const statusFile = getStatusFilePath();
  const auditDir = path.join(swAgentDir, 'audit');

  const machineConfig = loadMachineConfig();
  if (!machineConfig) {
    console.log(`  ${C.red(S.cross)} Machine config not found. Run ${C.cyan('init')} first.`);
    exit_(1);
  }

  let relayUrl = opts.relayUrl;
  const relayIdx = args.indexOf('--relay');
  if (relayIdx !== -1 && relayIdx + 1 < args.length) {
    relayUrl = args[relayIdx + 1];
  }
  if (!relayUrl) {
    relayUrl = machineConfig.cloud_url;
  }

  let autoExitMs: number | undefined;
  const autoExitIdx = args.indexOf('--auto-exit');
  if (autoExitIdx !== -1 && autoExitIdx + 1 < args.length) {
    autoExitMs = parseInt(args[autoExitIdx + 1], 10);
  }

  const existingPid = await readPidFile({ path: pidFile });
  if (existingPid && isProcessAlive(existingPid.pid)) {
    console.log(`  ${C.yellow(S.warning)} Agent already running (pid ${C.white(String(existingPid.pid))})`);
    exit_(1);
  }

  if (daemon) {
    const nodePath = process.execPath;
    const scriptPath = path.resolve(__dirname, '..', 'index.js');
    const relayArgs = relayUrl ? ['--relay', relayUrl] : [];
    const autoExitArgs = autoExitMs ? ['--auto-exit', String(autoExitMs)] : [];

    const child = spawn(nodePath, [scriptPath, '--internal-daemon', ...relayArgs, ...autoExitArgs], {
      detached: true,
      stdio: 'ignore',
      env: {
        ...process.env,
        SW_AGENT_DAEMON: '1',
      },
    });
    child.unref();

    // Wait for the detached daemon to actually become ready before returning,
    // so an immediately-following `status` reflects the real running state.
    const spinner = createSpinner();
    spinner.start(`Starting daemon (pid ${C.white(String(child.pid))})...`);

    const result = await waitForAgentReady(pidFile, statusFile, { timeoutMs: 8_000 });

    if (result.ready) {
      spinner.succeed(`Agent ready (pid ${C.white(String(result.pid))}, ${C.green(`${result.waitedMs}ms`)})`);
    } else {
      spinner.fail(`Daemon did not become ready: ${C.red(result.reason)}`);
      console.log(`  ${C.dim('Check logs at')} ${C.dim(getDaemonLogPath())}`);
      console.log(`  ${C.dim('Or run')} ${C.cyan('doctor')} ${C.dim('for diagnostics.')}`);
    }
    console.log();
    exit_(result.ready ? 0 : 1);
  }

  handleInternalDaemon();

  const databasesConfig = loadDatabasesConfig() || { databases: [] };

  console.log();
  console.log(`  ${C.bold(C.brand('Starting SW Agent'))}`);
  console.log(`    Agent ID: ${C.cyan(machineConfig.agent_id)}`);
  console.log(`    Cloud:    ${C.dim(relayUrl)}`);
  console.log(`    Databases: ${C.white(String(databasesConfig.databases.length))}`);
  console.log();

  const exitCode = await runAgent({
    machineConfig,
    databasesConfig,
    relayUrl,
    auditDir,
    statusFile,
    pidFile,
    foreground: true,
    autoExitMs,
  });

  exit_(exitCode);
}

function handleInternalDaemon(): void {
  if (process.env.SW_AGENT_DAEMON === '1') {
    setupDaemonLogging();
  }
}

function setupDaemonLogging(): void {
  const fs = require('fs');
  const swAgentDir = getSwAgentDir();
  const logFile = path.join(swAgentDir, 'daemon.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });

  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);

  process.stdout.write = (...args: any[]) => logStream.write(...args);
  process.stderr.write = (...args: any[]) => logStream.write(...args);

  // Keep original for emergency
  (process.stdout as any).__originalWrite = origStdout;
  (process.stderr as any).__originalWrite = origStderr;
}
