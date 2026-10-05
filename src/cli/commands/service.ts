import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { getAgentHome } from '../../config/paths';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

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

async function installService(platform: NodeJS.Platform): Promise<void> {
  const nodePath = getNodePath();
  const cliPath = getCliEntryPath();
  const home = getAgentHome();

  if (platform === 'linux') {
    const userSystemdDir = path.join(os.homedir(), '.config', 'systemd', 'user');
    fs.mkdirSync(userSystemdDir, { recursive: true });
    const servicePath = path.join(userSystemdDir, 'schemaweaver.service');

    const unit = `[Unit]
Description=Schema Weaver Database Connector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${nodePath} ${cliPath} --internal-daemon agent start
Restart=on-failure
RestartSec=10
Environment=PG_CONNECTOR_HOME=${home}
Environment=NODE_ENV=production

[Install]
WantedBy=default.target
`;
    fs.writeFileSync(servicePath, unit, 'utf8');
    console.log(`  ${C.green(S.check)} Created systemd user service: ${C.dim(servicePath)}`);
    console.log();
    console.log(`  To activate 24/7 auto-start, run:`);
    console.log(`    ${C.cyan('systemctl --user daemon-reload')}`);
    console.log(`    ${C.cyan('systemctl --user enable --now schemaweaver')}`);
    console.log();
    console.log(`  To check live logs:`);
    console.log(`    ${C.cyan('journalctl --user -u schemaweaver -f')}`);
  } else if (platform === 'darwin') {
    const launchAgentsDir = path.join(os.homedir(), 'Library', 'LaunchAgents');
    fs.mkdirSync(launchAgentsDir, { recursive: true });
    const plistPath = path.join(launchAgentsDir, 'dev.schemaweaver.pg-connector.plist');

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
    fs.writeFileSync(plistPath, plist, 'utf8');
    console.log(`  ${C.green(S.check)} Created macOS LaunchAgent: ${C.dim(plistPath)}`);
    console.log();
    console.log(`  To activate 24/7 background service, run:`);
    console.log(`    ${C.cyan(`launchctl load ${plistPath}`)}`);
  } else if (platform === 'win32') {
    console.log(`  ${C.bold('Windows Scheduled Task Setup (Starts on Logon & Runs in Background)')}`);
    console.log();
    const taskCmd = `schtasks /create /tn "SchemaWeaverConnector" /tr "\\"${nodePath}\\" \\"${cliPath}\\" --internal-daemon agent start" /sc onlogon /rl highest /f`;
    console.log(`  Run the following in an elevated PowerShell/Command Prompt:`);
    console.log(`    ${C.cyan(taskCmd)}`);
    console.log();
    console.log(`  To start the task immediately:`);
    console.log(`    ${C.cyan('schtasks /run /tn "SchemaWeaverConnector"')}`);
  } else {
    showPm2Instructions();
  }
}

async function uninstallService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    const servicePath = path.join(os.homedir(), '.config', 'systemd', 'user', 'schemaweaver.service');
    if (fs.existsSync(servicePath)) {
      try { execSync('systemctl --user stop schemaweaver', { stdio: 'ignore' }); } catch {}
      try { execSync('systemctl --user disable schemaweaver', { stdio: 'ignore' }); } catch {}
      fs.unlinkSync(servicePath);
      try { execSync('systemctl --user daemon-reload', { stdio: 'ignore' }); } catch {}
      console.log(`  ${C.green(S.check)} Removed systemd user service.`);
    } else {
      console.log(`  ${C.yellow(S.warning)} systemd service file not found.`);
    }
  } else if (platform === 'darwin') {
    const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'dev.schemaweaver.pg-connector.plist');
    if (fs.existsSync(plistPath)) {
      try { execSync(`launchctl unload ${plistPath}`, { stdio: 'ignore' }); } catch {}
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

async function statusService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      const out = execSync('systemctl --user status schemaweaver', { encoding: 'utf8' });
      console.log(out);
    } catch (err: any) {
      console.log(err.stdout || err.message);
    }
  } else if (platform === 'darwin') {
    try {
      const out = execSync('launchctl list | grep dev.schemaweaver.pg-connector', { encoding: 'utf8' });
      console.log(`  ${C.green(S.check)} Service running in launchd: ${out.trim()}`);
    } catch {
      console.log(`  ${C.dim('Service not currently registered in launchctl.')}`);
    }
  } else {
    showServiceHelp();
  }
}

async function startService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      execSync('systemctl --user start schemaweaver');
      console.log(`  ${C.green(S.check)} systemd service started.`);
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to start: ${err.message}`);
    }
  } else if (platform === 'darwin') {
    const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'dev.schemaweaver.pg-connector.plist');
    try {
      execSync(`launchctl load ${plistPath}`);
      console.log(`  ${C.green(S.check)} LaunchAgent loaded.`);
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to load: ${err.message}`);
    }
  } else {
    console.log(`  ${C.dim('Use pg-connector agent start or PM2 for foreground/background execution.')}`);
  }
}

async function stopService(platform: NodeJS.Platform): Promise<void> {
  if (platform === 'linux') {
    try {
      execSync('systemctl --user stop schemaweaver');
      console.log(`  ${C.green(S.check)} systemd service stopped.`);
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to stop: ${err.message}`);
    }
  } else if (platform === 'darwin') {
    const plistPath = path.join(os.homedir(), 'Library', 'LaunchAgents', 'dev.schemaweaver.pg-connector.plist');
    try {
      execSync(`launchctl unload ${plistPath}`);
      console.log(`  ${C.green(S.check)} LaunchAgent unloaded.`);
    } catch (err: any) {
      console.log(`  ${C.red(S.cross)} Failed to unload: ${err.message}`);
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
  console.log(`    ${C.cyan('install')}     Install 24/7 background service for current OS (systemd / launchd / Task Scheduler)`);
  console.log(`    ${C.cyan('start')}       Start the installed OS service`);
  console.log(`    ${C.cyan('stop')}        Stop the installed OS service`);
  console.log(`    ${C.cyan('status')}      Check service running status`);
  console.log(`    ${C.cyan('uninstall')}   Remove the OS service`);
  console.log(`    ${C.cyan('pm2')}         Show PM2 process supervisor configuration`);
}
