#!/usr/bin/env node

/**
 * Generates a systemd service unit file for running the Schema Weaver
 * database connector as a 24/7 background daemon on Linux (EC2, VPC, etc.).
 *
 * Usage:
 *   node scripts/generate-systemd-service.mjs [--user <username>] [--output <path>]
 *
 * Defaults:
 *   --user   : current user ($USER)
 *   --output : ./schemaweaver.service (stdout if omitted and piped)
 */

import { writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';

function getNodePath() {
  try {
    return execSync('which node', { encoding: 'utf8' }).trim();
  } catch {
    return '/usr/bin/node';
  }
}

function getGlobalBinPath() {
  try {
    return execSync('npm root -g', { encoding: 'utf8' }).trim()
      .replace(/\/lib\/node_modules$/, '/bin');
  } catch {
    return '/usr/local/bin';
  }
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = { user: process.env.USER || 'root', output: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--user' && args[i + 1]) opts.user = args[++i];
    if (args[i] === '--output' && args[i + 1]) opts.output = args[++i];
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv);
  const nodePath = getNodePath();
  const binDir = getGlobalBinPath();
  const home = homedir();

  const unit = `[Unit]
Description=Schema Weaver Database Connector (sw-agent)
Documentation=https://schemaweaver.vivekmind.com
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${opts.user}
Group=${opts.user}
Environment=NODE_ENV=production
Environment=HOME=${home}
Environment=SW_AGENT_HOME=${home}/.sw-agent

# The CLI entry point with --internal-daemon flag
ExecStart=${nodePath} ${binDir}/schemaweaver --internal-daemon agent start
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${home}/.sw-agent
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=schemaweaver

# Graceful shutdown
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
`;

  if (opts.output) {
    const outPath = resolve(opts.output);
    await writeFile(outPath, unit, 'utf8');
    console.log(`[systemd] Service file written to: ${outPath}`);
    console.log();
    console.log('To install:');
    console.log(`  sudo cp ${outPath} /etc/systemd/system/schemaweaver.service`);
    console.log('  sudo systemctl daemon-reload');
    console.log('  sudo systemctl enable schemaweaver');
    console.log('  sudo systemctl start schemaweaver');
    console.log();
    console.log('To check status:');
    console.log('  sudo systemctl status schemaweaver');
    console.log('  journalctl -u schemaweaver -f');
  } else {
    process.stdout.write(unit);
  }
}

main().catch((err) => {
  console.error('[systemd] Error:', err.message);
  process.exit(1);
});
