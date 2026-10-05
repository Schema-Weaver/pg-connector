import * as fs from 'fs';
import { VERSION } from '../index';
import { getMachineConfigPath, getSwAgentDir } from '../config/paths';
import { loadDbConfig } from '../config/db-config';
import { formatDuration, resolveAgentRuntimeState } from './daemon/state';
import { C, S, terminalWidth, truncateAnsi } from './ui';

interface BannerState {
  initialized: boolean;
  agentId: string | null;
  configDir: string;
  relayHost: string | null;
  dbCount: number;
  runtime: ReturnType<typeof resolveAgentRuntimeState>;
}

const WIDE_LOGO = [
  ' ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗███████╗ ██████╗ ██████╗ ',
  '██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚═██╔══╝██╔═══██╗██╔══██╗',
  '██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║       ██║   ██║   ██║██████╔╝',
  '██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║       ██║   ██║   ██║██╔══██╗',
  '╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗  ██║   ╚██████╔╝██║  ██║',
  ' ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝',
];

const MEDIUM_LOGO = [
  '  █▀▀ █▀█ █▄ █ █▄ █ █▀▀ █▀▀ ▀█▀ █▀█ █▀█',
  '  █▄▄ █▄█ █ ▀█ █ ▀█ ██▄ █▄▄  █  █▄█ █▀▄',
];

function readBannerState(): BannerState {
  const configDir = getSwAgentDir();
  const configPath = getMachineConfigPath();

  let initialized = false;
  let agentId: string | null = null;
  let relayHost: string | null = null;

  try {
    if (fs.existsSync(configPath)) {
      const raw = JSON.parse(stripBom(fs.readFileSync(configPath, 'utf8')));
      initialized = true;
      agentId = typeof raw.agent_id === 'string' ? raw.agent_id : null;
      const url = typeof raw.cloud_url === 'string' ? raw.cloud_url : '';
      try {
        relayHost = new URL(url).host || url;
      } catch {
        relayHost = url || null;
      }
    }
  } catch {
    initialized = false;
  }

  let dbCount = 0;
  try {
    dbCount = loadDbConfig().length;
  } catch {
    dbCount = 0;
  }

  return {
    initialized,
    agentId,
    configDir,
    relayHost,
    dbCount,
    runtime: resolveAgentRuntimeState(),
  };
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}

function statusBadge(state: BannerState['runtime']): string {
  if (state.kind === 'running') return `${C.green(S.dot)} running`;
  if (state.kind === 'starting') return `${C.yellow(S.dot)} starting`;
  if (state.kind === 'unresponsive') return `${C.yellow(S.dot)} unresponsive`;
  return `${C.dim(S.dot)} stopped`;
}

function logoLines(width: number): string[] {
  if (width >= 78) return WIDE_LOGO;
  if (width >= 42) return MEDIUM_LOGO;
  return ['  CONNECTOR'];
}

export function printBanner(): void {
  const state = readBannerState();
  const width = terminalWidth();
  const usable = Math.max(24, width - 2);

  console.log();
  for (const line of logoLines(width)) {
    console.log(C.brand(truncateAnsi(line, usable)));
  }
  console.log(`  ${C.dim(truncateAnsi('Secure bridge between Schema Weaver and PostgreSQL', usable - 2))}`);
  console.log(`  ${C.dim(`v${VERSION}`)}`);
  console.log();

  if (state.initialized && state.agentId) {
    const pidText = state.runtime.pid ? C.dim(` pid ${state.runtime.pid}`) : '';
    const uptimeText =
      state.runtime.running && state.runtime.uptime_sec !== null
        ? C.dim(` up ${formatDuration(state.runtime.uptime_sec)}`)
        : '';

    console.log(`  ${C.bold('Agent')}     ${C.white(state.agentId)}  ${statusBadge(state.runtime)}${pidText}${uptimeText}`);
    if (state.relayHost) {
      console.log(`  ${C.bold('Relay')}     ${C.dim(truncateAnsi(state.relayHost, Math.max(10, usable - 14)))}`);
    }
    console.log(`  ${C.bold('Databases')} ${C.white(String(state.dbCount))}  ${C.dim(state.configDir)}`);
  } else {
    console.log(`  ${C.dim('Not initialized.')} Run ${C.cyan('init')} ${C.dim('to set up this machine.')}`);
  }

  console.log();

  if (!state.initialized) {
    console.log(`  ${C.cyan(S.arrow)} Run ${C.cyan('init')} to create a local agent token.`);
  } else if (state.dbCount === 0) {
    console.log(`  ${C.cyan(S.arrow)} Run ${C.cyan('db add')} to register a PostgreSQL database.`);
  } else if (!state.runtime.running) {
    console.log(`  ${C.cyan(S.arrow)} Run ${C.cyan('agent start')} to begin listening.`);
  }
  console.log();
}
