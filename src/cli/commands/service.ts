import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execFileSync } from 'child_process';
import { atomicWriteFile } from '../../config/atomic-write';
import { getAgentHome, getCredentialKeyPath } from '../../config/paths';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

/**
 * Runs a service manager. Always receives an argument array and never a shell
 * string: `execSync(\`launchctl load ${path}\`)` runs the interpolated path
 * through /bin/sh, and the path is derived from $HOME, so a $HOME containing
 * `;` is arbitrary command execution as the invoking user.
 */
export type ServiceCommandExecutor = (file: string, args: readonly string[]) => string;

/**
 * The failure shape thrown by `execFileSync`: an `Error` that also carries the
 * child's captured `stdout`/`stderr` when the pipes are read. An injected test
 * executor may throw anything, so this is asserted, not proven by a guard.
 */
type CommandFailure = Error & { stdout?: string };

let commandExecutor: ServiceCommandExecutor | null = null;

function runCommand(file: string, args: readonly string[]): string {
  if (commandExecutor) return commandExecutor(file, args);
  return execFileSync(file, [...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Test seam: replaces the process spawner. Pass null to restore the real one. */
export function setServiceCommandExecutor(executor: ServiceCommandExecutor | null): void {
  commandExecutor = executor;
}

/** Throws unless `target` resolves strictly under `home`. */
export function assertPathUnderHome(target: string, home: string): void {
  const resolvedHome = path.resolve(home);
  const resolved = path.resolve(target);
  if (resolved !== resolvedHome && !resolved.startsWith(resolvedHome + path.sep)) {
    throw new Error(
      `Refusing to use ${resolved}: it resolves outside the home directory (${resolvedHome})`,
    );
  }
}

const LAUNCH_AGENT_FILE = 'dev.schemaweaver.pg-connector.plist';
const LAUNCH_AGENT_LABEL = 'dev.schemaweaver.pg-connector';

/**
 * The LaunchAgent plist path, validated to be inside the home directory.
 * Returns null instead of throwing so callers can report the refusal.
 */
export function resolveLaunchAgentPath(home: string = os.homedir()): string | null {
  const plistPath = path.join(home, 'Library', 'LaunchAgents', LAUNCH_AGENT_FILE);
  try {
    assertPathUnderHome(plistPath, home);
  } catch {
    return null;
  }
  return plistPath;
}

export function buildLaunchctlInvocation(
  action: 'load' | 'unload',
  plistPath: string,
): { file: string; args: string[] } {
  return { file: 'launchctl', args: [action, plistPath] };
}

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

function getNodePath(): string {
  try {
    return process.execPath;
  } catch {
    return 'node';
  }
}

function getCliEntryPath(): string {
  return path.resolve(__dirname, '..', 'index.js');
}

/* ------------------------------------------------------------------ */
/* The generated systemd user unit                                     */
/* ------------------------------------------------------------------ */

export interface SystemdUnitInputs {
  /** Absolute path to the node binary the unit runs. */
  nodePath: string;
  /** Absolute path to the compiled CLI entry point. */
  cliPath: string;
  /**
   * The operator's real home directory.
   *
   * Emitted as `Environment=HOME=` because the daemon does not only read the
   * agent home from the environment: `getCredentialKeyPath()` is
   * `path.join(os.homedir(), '.sw-agent-credential.key')`, so the key that
   * decrypts every stored database password is derived from HOME and NOT from
   * the agent home. Without this line a systemd user manager that resolved HOME
   * differently from the operator's shell would leave the 24/7 service unable
   * to decrypt anything the CLI had stored — the same class of split-brain as
   * the `PG_CONNECTOR_HOME` pin it replaces.
   */
  userHome: string;
  /**
   * The already-resolved, ABSOLUTE agent home this service must run against.
   *
   * Emitted as `SW_AGENT_HOME`, which is the variable `getAgentHome()` reads and
   * the one `buildDaemonChildEnv()` pins for a detached child. It must never be
   * `PG_CONNECTOR_HOME`: that variable is in `UNRECOGNISED_SECURITY_ENV` and is
   * DELETED from `process.env` by `stripUnrecognisedSecurityEnv()` at daemon
   * startup, so a unit that pinned it ran the operator's configured home in the
   * foreground and `~/.sw-agent` for the whole of its unattended life — a
   * different config, a different `allowed_databases`, a different audit
   * directory and a different audit key.
   */
  agentHome: string;
}

/**
 * Every path the daemon must be able to WRITE while the unit's filesystem
 * namespace is active.
 *
 * `ProtectSystem=strict` makes the ENTIRE filesystem read-only except `/dev`,
 * `/proc`, `/sys` and whatever `ReadWritePaths=` re-opens; `ProtectHome=read-only`
 * separately makes `$HOME`, `/root` and `/run/user/<uid>` read-only. So this is
 * not "the agent home plus whatever is convenient" — every writable path the
 * daemon touches has to be listed or the daemon fails at runtime, and it fails
 * at the worst possible moment (mid-write to the audit chain).
 *
 * What the daemon writes:
 *
 *  - The agent home: `sw-agent.pid`, `sw-agent.status`, `daemon.log`,
 *    `errors.jsonl` and the whole `audit/` directory (log, archives, chain head,
 *    floor, and the `.write_test` preflight probe). All under one path.
 *  - `~/.sw-agent-credential.key`, the at-rest encryption key for database
 *    passwords. It lives OUTSIDE the agent home on purpose, so a backup or
 *    snapshot of the agent home cannot carry the key that decrypts the file
 *    sitting next to it — which means `ProtectHome=read-only` covers it and it
 *    MUST be listed, or the daemon can neither read an existing key nor create
 *    one on first run.
 *
 * What it deliberately does NOT list: `$HOME` itself. Listing the home directory
 * would re-open everything `ProtectHome=read-only` just closed and turn the
 * directive into decoration, so the credential key is listed as the FILE, not
 * as its parent directory.
 *
 * `PrivateTmp=true` supplies a writable private `/tmp` and `/var/tmp`, which is
 * why no other path needs to appear here.
 */
export function systemdReadWritePaths(agentHome: string, credentialKeyPath: string): string[] {
  const paths: string[] = [];
  for (const candidate of [path.resolve(agentHome), path.resolve(credentialKeyPath)]) {
    if (!paths.includes(candidate)) paths.push(candidate);
  }
  return paths;
}

/**
 * Renders the systemd user unit.
 *
 * Pure: no filesystem, no environment, no clock. Everything the operator's
 * security posture depends on — the pinned agent home, the pinned HOME, and the
 * hardening directives — is therefore assertable without installing anything,
 * which is the only way a regression here can be caught by a test.
 *
 * The hardening set is the UNION of what this generator and
 * `scripts/generate-systemd-service.mjs` each emitted, so the two produce an
 * equivalent unit and neither loses a directive: `NoNewPrivileges`,
 * `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths` and
 * `PrivateTmp`, plus the start-limit, journal-routing and graceful-shutdown
 * directives. `User=`/`Group=` are intentionally absent: those belong to a
 * system unit, and a user unit runs as the invoking user by definition.
 */
export function renderSystemdUnitFile(inputs: SystemdUnitInputs): string {
  const { nodePath, cliPath, userHome, agentHome } = inputs;
  const readWrite = systemdReadWritePaths(agentHome, getCredentialKeyPath());

  return `[Unit]
Description=Schema Weaver Database Connector
Documentation=https://schemaweaver.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${nodePath} ${cliPath} --internal-daemon agent start
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# --- Agent home -------------------------------------------------
# HOME is pinned first, then SW_AGENT_HOME. PG_CONNECTOR_HOME is deliberately
# absent: the daemon DELETES it from process.env at startup, so a unit that
# pinned it ran a different config, a different allowed_databases scope, a
# different audit directory and a different audit key than the operator's CLI.
# HOME matters independently because the credential key is derived from
# os.homedir(), not from the agent home.
Environment=HOME=${userHome}
Environment=SW_AGENT_HOME=${agentHome}
Environment=NODE_ENV=production

# --- Security hardening --------------------------------------------------
# NoNewPrivileges: nothing in the daemon can gain privileges it did not start
#   with, so a setuid binary reached through a bug adds nothing.
# ProtectSystem=strict: the whole filesystem is read-only except the paths
#   re-opened by ReadWritePaths.
# ProtectHome=read-only: $HOME, /root and /run/user/$UID cannot be written, so
#   a bug that reaches a file outside the agent home cannot damage it. Reads are
#   still allowed, which is what keeps a node installation under $HOME working.
# ReadWritePaths: every path the daemon actually writes - the agent home (pid,
#   status, daemon.log, errors.jsonl, audit/) and the credential key file,
#   which is outside the agent home by design.
# PrivateTmp: a private /tmp and /var/tmp, so a temp file the daemon creates is
#   not visible to another local user.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${readWrite.join(' ')}
PrivateTmp=true

# --- Logging -------------------------------------------------------------
StandardOutput=journal
StandardError=journal
SyslogIdentifier=schemaweaver

# --- Graceful shutdown ---------------------------------------------------
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=default.target
`;
}

/** Path of the generated systemd user unit, validated to be inside `$HOME`. */
export function resolveSystemdServicePath(home: string = os.homedir()): string {
  return path.join(home, '.config', 'systemd', 'user', 'schemaweaver.service');
}

/**
 * The `Environment=` assignments in a rendered unit, as name to value.
 *
 * Parsed from the TEXT rather than from the inputs, so a test can prove what
 * systemd will actually apply — including that `PG_CONNECTOR_HOME` is absent.
 */
export function parseUnitEnvironment(unit: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const rawLine of unit.split('\n')) {
    const match = /^Environment=([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(rawLine.trim());
    if (match) env[match[1]] = match[2];
  }
  return env;
}

export async function runService(args: string[] = []): Promise<void> {
  const action = args[0] || 'help';
  const platform = process.platform;

  console.log();
  console.log(`  ${C.bold(C.brand('Schema Weaver Connector — 24/7 Autostart Service'))}`);
  console.log();

  if (action === 'install') {
    await installService(platform);
  } else if (action === 'uninstall' || action === 'remove') {
    await uninstallService(platform);
  } else if (action === 'status') {
    await statusService(platform);
  } else if (action === 'start') {
    await startService(platform);
  } else if (action === 'stop') {
    await stopService(platform);
  } else if (action === 'pm2') {
    showPm2Instructions();
  } else {
    showServiceHelp();
  }

  console.log();
  exit_(0);
}

/**
 * Installs the OS autostart service.
 *
 * Exported (rather than module-private) so a test can drive the exact write
 * path with an explicit platform instead of only through `process.platform`.
 */
export async function installService(platform: NodeJS.Platform): Promise<void> {
  const nodePath = getNodePath();
  const cliPath = getCliEntryPath();
  const home = getAgentHome();
  const userHome = os.homedir();

  if (platform === 'linux') {
    const servicePath = resolveSystemdServicePath(userHome);
    try {
      assertPathUnderHome(servicePath, userHome);
    } catch (err) {
      console.log(`  ${C.red(S.cross)} ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    fs.mkdirSync(path.dirname(servicePath), { recursive: true });

    const unit = renderSystemdUnitFile({ nodePath, cliPath, userHome, agentHome: home });

    // The repo's atomic writer, not a bare `writeFileSync`. Two reasons: a
    // `mode` passed to `writeFileSync` applies only on CREATE, so a unit left
    // behind by an older build kept whatever mode it had; and a bare write
    // follows a symlink planted at the unit path, letting another local user
    // decide what `systemctl --user enable` later reads. The writer also fsyncs
    // and renames, so a crash cannot leave a half-written unit for systemd.
    try {
      atomicWriteFile(servicePath, unit, 0o600);
    } catch (err: unknown) {
      console.log(
        `  ${C.red(S.cross)} Failed to write ${servicePath}: ${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }
    console.log(
      `  ${C.green(S.check)} Created systemd user service: ${C.dim(servicePath)} ${C.dim('(mode 0600)')}`,
    );
    console.log();
    console.log(`  ${C.dim('Agent home pinned as SW_AGENT_HOME:')} ${C.white(home)}`);
    console.log(
      `  ${C.dim('Every path the daemon writes is in ReadWritePaths=, including the credential key:')}`,
    );
    console.log(`    ${C.dim(systemdReadWritePaths(home, getCredentialKeyPath()).join('\n    '))}`);
    console.log();
    console.log(`  ${C.bold('To activate 24/7 auto-start, run:')}`);
    console.log(`    ${C.cyan('systemctl --user daemon-reload')}`);
    console.log(`    ${C.cyan('systemctl --user enable --now schemaweaver')}`);
    console.log();
    console.log(`  ${C.bold('To check live logs:')}`);
    console.log(`    ${C.cyan('journalctl --user -u schemaweaver -f')}`);
  } else if (platform === 'darwin') {
    const plistPath = resolveLaunchAgentPath();
    if (!plistPath) {
      console.log(
        `  ${C.red(S.cross)} Refusing to write a LaunchAgent outside the home directory.`,
      );
      return;
    }
    fs.mkdirSync(path.dirname(plistPath), { recursive: true });

    // Same pinning as the systemd unit: HOME first (the credential key is
    // derived from it), then the resolved agent home. No PG_CONNECTOR_HOME.
    const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.schemaweaver.pg-connector</string>
  <key>ProgramArguments</key>
  <array>
    <string>${nodePath}</string>
    <string>${cliPath}</string>
    <string>--internal-daemon</string>
    <string>agent</string>
    <string>start</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>${userHome}</string>
    <key>SW_AGENT_HOME</key>
    <string>${home}</string>
    <key>NODE_ENV</key>
    <string>production</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${path.join(home, 'daemon.log')}</string>
  <key>StandardErrorPath</key>
  <string>${path.join(home, 'daemon.log')}</string>
</dict>
</plist>
`;
    // `mode` on create only, but a plist holds no secret, so the exposure is the
    // `Umask` default rather than a credential. Atomic write so an enable can
    // never read a half-written plist.
    atomicWriteFile(plistPath, plist, 0o600);
    console.log(`  ${C.green(S.check)} Created macOS LaunchAgent: ${C.dim(plistPath)}`);
    console.log();
    console.log(`  ${C.dim('Agent home pinned as SW_AGENT_HOME:')} ${C.white(home)}`);
    console.log();
    console.log(`  ${C.bold('To activate 24/7 background service, run:')}`);
    console.log(`    ${C.cyan(`launchctl load ${plistPath}`)}`);
  } else if (platform === 'win32') {
    console.log(
      `  ${C.bold('Windows Scheduled Task Setup (Starts on Logon & Runs in Background)')}`,
    );
    console.log();
    console.log(`  ${C.bold('Pin the agent home first, so the task and the CLI agree:')}`);
    console.log(`    ${C.cyan(`setx SW_AGENT_HOME "${home}"`)}`);
    console.log(`    ${C.dim('Never PG_CONNECTOR_HOME: the daemon deletes it at startup.')}`);
    console.log();
    const taskCmd = `schtasks /create /tn "SchemaWeaverConnector" /tr "\\"${nodePath}\\" \\"${cliPath}\\" --internal-daemon agent start" /sc onlogon /rl highest /f`;
    console.log(`  Run the following in an elevated PowerShell/Command Prompt:`);
    console.log(`    ${C.cyan(taskCmd)}`);
    console.log();
    console.log(`  ${C.bold('To start the task immediately:')}`);
    console.log(`    ${C.cyan('schtasks /run /tn "SchemaWeaverConnector"')}`);
  } else {
    showPm2Instructions();
  }
}

export async function uninstallService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    const servicePath = path.join(
      os.homedir(),
      '.config',
      'systemd',
      'user',
      'schemaweaver.service',
    );
    if (fs.existsSync(servicePath)) {
      try {
        runCommand('systemctl', ['--user', 'stop', 'schemaweaver']);
      } catch {}
      try {
        runCommand('systemctl', ['--user', 'disable', 'schemaweaver']);
      } catch {}
      fs.unlinkSync(servicePath);
      try {
        runCommand('systemctl', ['--user', 'daemon-reload']);
      } catch {}
      console.log(`  ${C.green(S.check)} Removed systemd user service.`);
    } else {
      console.log(`  ${C.yellow(S.warning)} systemd service file not found.`);
    }
  } else if (platform === 'darwin') {
    const plistPath = resolveLaunchAgentPath();
    if (!plistPath) {
      console.log(
        `  ${C.red(S.cross)} Refusing to use a LaunchAgent path outside the home directory.`,
      );
    } else if (fs.existsSync(plistPath)) {
      try {
        runCommand('launchctl', buildLaunchctlInvocation('unload', plistPath).args);
      } catch {}
      fs.unlinkSync(plistPath);
      console.log(`  ${C.green(S.check)} Removed macOS LaunchAgent.`);
    } else {
      console.log(`  ${C.yellow(S.warning)} LaunchAgent plist not found.`);
    }
  } else if (platform === 'win32') {
    console.log(`  To delete the Windows Scheduled Task:`);
    console.log(`    ${C.cyan('schtasks /delete /tn "SchemaWeaverConnector" /f')}`);
  }
}

export async function statusService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      const out = runCommand('systemctl', ['--user', 'status', 'schemaweaver']);
      console.log(out);
    } catch (err: unknown) {
      const failure = err as CommandFailure;
      console.log(failure.stdout || failure.message);
    }
  } else if (platform === 'darwin') {
    try {
      const out = runCommand('launchctl', ['list']);
      const line = String(out)
        .split('\n')
        .find((l) => l.includes(LAUNCH_AGENT_LABEL));
      if (line) {
        console.log(`  ${C.green(S.check)} Service running in launchd: ${line.trim()}`);
      } else {
        console.log(`  ${C.dim('Service not currently registered in launchctl.')}`);
      }
    } catch {
      console.log(`  ${C.dim('Service not currently registered in launchctl.')}`);
    }
  } else {
    showServiceHelp();
  }
}

export async function startService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      runCommand('systemctl', ['--user', 'start', 'schemaweaver']);
      console.log(`  ${C.green(S.check)} systemd service started.`);
    } catch (err: unknown) {
      console.log(`  ${C.red(S.cross)} Failed to start: ${(err as CommandFailure).message}`);
    }
  } else if (platform === 'darwin') {
    const plistPath = resolveLaunchAgentPath();
    if (!plistPath) {
      console.log(
        `  ${C.red(S.cross)} Refusing to load a LaunchAgent from outside the home directory.`,
      );
      return;
    }
    try {
      runCommand('launchctl', buildLaunchctlInvocation('load', plistPath).args);
      console.log(`  ${C.green(S.check)} LaunchAgent loaded.`);
    } catch (err: unknown) {
      console.log(`  ${C.red(S.cross)} Failed to load: ${(err as CommandFailure).message}`);
    }
  } else {
    console.log(
      `  ${C.dim('Use pg-connector agent start or PM2 for foreground/background execution.')}`,
    );
  }
}

export async function stopService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      runCommand('systemctl', ['--user', 'stop', 'schemaweaver']);
      console.log(`  ${C.green(S.check)} systemd service stopped.`);
    } catch (err: unknown) {
      console.log(`  ${C.red(S.cross)} Failed to stop: ${(err as CommandFailure).message}`);
    }
  } else if (platform === 'darwin') {
    const plistPath = resolveLaunchAgentPath();
    if (!plistPath) {
      console.log(
        `  ${C.red(S.cross)} Refusing to unload a LaunchAgent from outside the home directory.`,
      );
      return;
    }
    try {
      runCommand('launchctl', buildLaunchctlInvocation('unload', plistPath).args);
      console.log(`  ${C.green(S.check)} LaunchAgent unloaded.`);
    } catch (err: unknown) {
      console.log(`  ${C.red(S.cross)} Failed to unload: ${(err as CommandFailure).message}`);
    }
  }
}

function showPm2Instructions(): void {
  console.log(`  ${C.bold('Universal PM2 Setup (Works on Linux, macOS, and Windows)')}`);
  console.log();
  console.log(`  1. Install PM2:`);
  console.log(`     ${C.cyan('npm install -g pm2')}`);
  console.log();
  console.log(`  2. Start connector with crash-restart supervisor:`);
  console.log(`     ${C.cyan('pm2 start pg-connector --name schemaweaver -- start')}`);
  console.log();
  console.log(`  3. Save and configure autostart on system boot:`);
  console.log(`     ${C.cyan('pm2 save')}`);
  console.log(`     ${C.cyan('pm2 startup')}`);
  console.log();
  console.log(`  4. View live logs:`);
  console.log(`     ${C.cyan('pm2 logs schemaweaver')}`);
}

function showServiceHelp(): void {
  console.log(`  ${C.bold('Usage:')} pg-connector service ${C.cyan('<action>')}`);
  console.log();
  console.log(`  ${C.bold('Actions:')}`);
  console.log(
    `    ${C.cyan('install')}     Install 24/7 background service for current OS (systemd / launchd / Task Scheduler)`,
  );
  console.log(`    ${C.cyan('start')}       Start the installed OS service`);
  console.log(`    ${C.cyan('stop')}        Stop the installed OS service`);
  console.log(`    ${C.cyan('status')}      Check service running status`);
  console.log(`    ${C.cyan('uninstall')}   Remove the OS service`);
  console.log(`    ${C.cyan('pm2')}         Show PM2 process supervisor configuration`);
}
