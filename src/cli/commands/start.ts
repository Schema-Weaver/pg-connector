import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { loadMachineConfig, PermissionLevel } from '../../config/machine-config';
import { loadDatabasesConfig } from '../../config/db-config';
import {
  getDaemonLogPath,
  getPidFilePath,
  getStatusFilePath,
  getSwAgentDir,
} from '../../config/paths';
import { readPidFile, isProcessAlive } from '../daemon/pid-file';
import { waitForAgentReady } from '../daemon/readiness';
import { buildDaemonChildEnv } from '../daemon/state';
import {
  runAgent,
  resolveRelayOverride,
  relayHostMismatchWarning,
  redactUrlForDisplay,
} from '../daemon/runtime';
import { probeAuditDir } from '../../audit/files';
import { loadAuditKey, type ChainVerifyResult } from '../../audit/chain';
import { verifyAuditDirCached } from '../../audit/verify-cache';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

/**
 * Permission levels where an agent that cannot record what it does must not run.
 * `read_only`/`auto_upgrade` still start, loudly, because refusing there would
 * leave an operator with no way to diagnose or repair anything.
 */
const AUDIT_REQUIRED_LEVELS: PermissionLevel[] = ['full', 'manual'];

export interface StartOptions {
  daemon?: boolean;
  relayUrl?: string;
}

interface AuditStartupCheck {
  probe: Awaited<ReturnType<typeof probeAuditDir>>;
  /** Chain verdict for an existing log; null when there was nothing to check. */
  chain: ChainVerifyResult | null;
  /**
   * Files whose verdict was carried over from an earlier check in this process
   * instead of being re-read. Always zero for a one-shot `start`, because the
   * cache is per process and in memory.
   */
  chainReusedFiles: number;
  keyError: string | null;
}

/**
 * Startup gate for the audit path: the directory must be usable, the key must
 * load, and any existing log must agree with its anchor. "Audit loss is never
 * silent" is only enforceable if a bad audit path stops the agent.
 *
 * Verification goes through the cached whole-log walk (`verifyAuditDirCached`)
 * rather than a bare `verifyAuditLog`. This is a *repeated* check in one process
 * only when an operator re-runs `start` from the interactive shell; the cache
 * lives in memory and is never written next to the log, so it can only ever
 * skip a file that is byte-identical to one this process already verified, from
 * the same signing key, at the same point in the chain, with the tail record and
 * both anchors re-read from disk. `sw-agent audit verify` deliberately does not
 * use it: that command is the authoritative one.
 */
async function auditStartupCheck(swAgentDir: string, auditDir: string): Promise<AuditStartupCheck> {
  const probe = await probeAuditDir(auditDir);
  if (!probe.ok) return { probe, chain: null, chainReusedFiles: 0, keyError: null };

  let keyError: string | null = null;
  try {
    loadAuditKey({ dir: swAgentDir });
  } catch (err: unknown) {
    keyError = err instanceof Error ? err.message : String(err);
  }

  if (!auditLogExists(auditDir)) {
    return { probe, chain: null, chainReusedFiles: 0, keyError };
  }
  if (keyError) return { probe, chain: null, chainReusedFiles: 0, keyError };

  try {
    const verification = await verifyAuditDirCached(auditDir, { keyDir: swAgentDir });
    return {
      probe,
      chain: {
        intact: verification.intact,
        reason: verification.reason,
        detail: verification.detail,
        events: verification.events,
      },
      chainReusedFiles: verification.intact ? verification.cached_files.length : 0,
      keyError,
    };
  } catch (err: unknown) {
    return {
      probe,
      chain: null,
      chainReusedFiles: 0,
      keyError: `chain verification failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function auditLogExists(auditDir: string): boolean {
  try {
    const entries = fs.readdirSync(auditDir);
    return entries.some((e) => e === 'audit.jsonl' || /^audit-\d+\.jsonl$/.test(e));
  } catch {
    return false;
  }
}

export async function runStart(args: string[], opts: StartOptions = {}): Promise<void> {
  const foreground =
    args.includes('--foreground') || args.includes('--fg') || process.env.SW_AGENT_DAEMON === '1';
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

  // Validate the relay override with the same rule `cloud_url` must satisfy, and
  // refuse loudly rather than silently connecting somewhere else. This runs
  // before the daemon is spawned so the override cannot reach the detached
  // child unvalidated, and before anything is printed back to the operator.
  try {
    const relay = resolveRelayOverride(relayUrl, machineConfig.cloud_url);
    relayUrl = relay.url;
    if (relay.hostChanged && relay.configuredHost && relay.relayHost) {
      console.error();
      console.error(relayHostMismatchWarning(relay.configuredHost, relay.relayHost));
      console.error();
    }
  } catch (err) {
    console.log();
    console.log(
      `  ${C.red(S.cross)} ${C.brightRed('INVALID RELAY URL')} ${C.dim(`(${redactUrlForDisplay(String(relayUrl ?? ''))})`)}`,
    );
    console.log(`      ${err instanceof Error ? err.message : String(err)}`);
    console.log(
      `      ${C.dim('The agent token is a permanent credential, so only wss:// is accepted.')}`,
    );
    console.log();
    exit_(1);
  }

  let autoExitMs: number | undefined;
  const autoExitIdx = args.indexOf('--auto-exit');
  if (autoExitIdx !== -1 && autoExitIdx + 1 < args.length) {
    autoExitMs = parseInt(args[autoExitIdx + 1], 10);
  }

  const existingPid = await readPidFile({ path: pidFile });
  if (existingPid && isProcessAlive(existingPid.pid)) {
    console.log(
      `  ${C.yellow(S.warning)} Agent already running (pid ${C.white(String(existingPid.pid))})`,
    );
    exit_(1);
  }

  const auditCheck = await auditStartupCheck(swAgentDir, auditDir);
  if (!reportAuditStartupCheck(auditCheck, machineConfig.default_permission)) {
    exit_(1);
  }

  if (daemon) {
    const nodePath = process.execPath;
    const scriptPath = path.resolve(__dirname, '..', 'index.js');
    const relayArgs = relayUrl ? ['--relay', relayUrl] : [];
    const autoExitArgs = autoExitMs ? ['--auto-exit', String(autoExitMs)] : [];

    // The child is spawned from an allow-list, not from a spread of this
    // process's environment. Copying the whole environment handed the detached
    // daemon every variable the operator's shell happened to contain, including
    // the seven that change security posture — so `stripUnrecognisedSecurityEnv()`
    // in the child was the only thing standing between an inherited
    // `SW_PG_POOL_MAX` and a reconfigured agent.
    const childEnv = buildDaemonChildEnv(process.env, { agentHome: swAgentDir });
    for (const refused of childEnv.refused) {
      console.log(`  Ignoring ${refused.name}: ${refused.effect}`);
    }

    const child = spawn(
      nodePath,
      [scriptPath, '--internal-daemon', ...relayArgs, ...autoExitArgs],
      {
        detached: true,
        stdio: 'ignore',
        env: childEnv.env,
      },
    );
    child.unref();

    // Wait for the detached daemon to actually become ready before returning,
    // so an immediately-following `status` reflects the real running state.
    const spinner = createSpinner();
    spinner.start(`Starting daemon (pid ${C.white(String(child.pid))})...`);

    const result = await waitForAgentReady(pidFile, statusFile, { timeoutMs: 8_000 });

    if (result.ready) {
      spinner.succeed(
        `Agent ready (pid ${C.white(String(result.pid))}, ${C.green(`${result.waitedMs}ms`)})`,
      );
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
  console.log(`    Cloud:    ${C.dim(redactUrlForDisplay(relayUrl))}`);
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

/**
 * Audit loss must never be silent. On `full` and `manual` an agent that cannot
 * record what it does is refused outright; on read-only levels it still starts,
 * but says so loudly.
 *
 * @returns true when startup may continue.
 */
function reportAuditStartupCheck(
  check: AuditStartupCheck,
  permissionLevel: PermissionLevel,
): boolean {
  const problem = auditProblem(check);
  if (check.chainReusedFiles > 0) {
    console.log();
    console.log(
      `      ${C.dim(`${check.chainReusedFiles} audit file(s) were unchanged since an earlier check in this session and were not re-read.`)}`,
    );
  }
  if (!problem) return true;

  const required = AUDIT_REQUIRED_LEVELS.includes(permissionLevel);

  console.log();
  console.log(`  ${C.red(S.cross)} ${C.brightRed('AUDIT LOG UNAVAILABLE')}`);
  console.log(`      ${C.dim(check.probe.dir)}`);
  console.log(`      ${C.yellow(problem)}`);

  if (required) {
    console.log();
    console.log(
      `      ${C.bold('Refusing to start.')} Permission level is ${C.cyan(permissionLevel)}; every action must be auditable.`,
    );
    console.log(
      `      Fix the audit directory (it must be a directory with mode ${C.white('0700')} and writable)`,
    );
    console.log(
      `      and, if a log exists, run ${C.cyan('sw-agent audit verify')} to see why it does not check out.`,
    );
    console.log(`      ${C.dim('Run sw-agent doctor to repair directory modes.')}`);
    console.log();
    return false;
  }

  console.log();
  console.log(
    `      ${C.yellow(S.warning)} Continuing without audit recording. Actions at level ${C.cyan(permissionLevel)} will NOT be logged.`,
  );
  console.log();
  return true;
}

/** Returns a human-readable problem, or null when the audit path is good. */
function auditProblem(check: AuditStartupCheck): string | null {
  if (!check.probe.ok) return check.probe.reason ?? 'audit directory is not usable';
  if (check.probe.repaired) {
    console.log(
      `  ${C.yellow(S.warning)} Repaired audit directory mode to ${C.white('0700')} (it was untraversable).`,
    );
  }
  if (check.keyError) return check.keyError;
  if (check.chain && !check.chain.intact) {
    const where = check.chain.reason ? ` (${check.chain.reason})` : '';
    return `existing audit log does not verify${where}${check.chain.detail ? `: ${check.chain.detail}` : ''}`;
  }
  return null;
}

function handleInternalDaemon(): void {
  if (process.env.SW_AGENT_DAEMON === '1') {
    setupDaemonLogging();
  }
}

function setupDaemonLogging(): void {
  const swAgentDir = getSwAgentDir();
  const logFile = path.join(swAgentDir, 'daemon.log');
  const logStream = fs.createWriteStream(logFile, { flags: 'a' });
  redirectToLog(process.stdout, logStream);
  redirectToLog(process.stderr, logStream);
}

/**
 * Sends a stream's output to the daemon log, keeping the original writer
 * reachable on `__originalWrite` for emergency output.
 */
function redirectToLog(stream: NodeJS.WriteStream, logStream: fs.WriteStream): void {
  type WriteArgs = [
    chunk: string | Uint8Array,
    encoding?: BufferEncoding,
    cb?: (err?: Error | null) => void,
  ];
  const target = stream as NodeJS.WriteStream & { __originalWrite?: typeof stream.write };
  target.__originalWrite = target.write.bind(stream);
  target.write = ((...args: WriteArgs) =>
    logStream.write(args[0], args[1] ?? 'utf8', args[2])) as typeof stream.write;
}
