import { resolveAgentRuntimeState, formatDuration, formatTimestamp } from '../daemon/state';
import { isReplMode } from '../prompt';
import { C, S, check, warn, truncateAnsi, terminalWidth } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runStatus(args: string[]): Promise<void> {
  const json = args.includes('--json') || args.includes('-j');
  const state = resolveAgentRuntimeState();

  if (json) {
    console.log(JSON.stringify({
      running: state.running,
      healthy: state.healthy,
      state: state.kind,
      pid: state.pid,
      version: state.version,
      started_at: state.started_at,
      uptime_sec: state.uptime_sec,
      last_heartbeat: state.last_heartbeat,
      channels: state.status?.channels ?? null,
      stats: state.status?.stats ?? null,
      config: state.status?.config ?? null,
      last_error: state.status?.last_error ?? null,
    }, null, 2));
    exit_(state.running && state.healthy ? 0 : 1);
  }

  console.log();
  console.log(formatStatusOutput(state));
  console.log();
  exit_(state.running && state.healthy ? 0 : 1);
}

function formatStatusOutput(state: ReturnType<typeof resolveAgentRuntimeState>): string {
  const lines: string[] = [];
  const width = terminalWidth();
  const valueWidth = Math.max(16, width - 28);

  lines.push(C.brand(C.bold('  Agent Status')));
  lines.push('');

  const statusText = state.kind === 'running'
    ? check('Running')
    : state.kind === 'starting'
      ? warn('Starting')
      : state.kind === 'unresponsive'
        ? warn('Unresponsive')
        : C.dim(`${S.dot} Stopped`);

  const rows = [
    ['State', statusText],
    ['PID', state.pid !== null ? C.white(String(state.pid)) : C.dim('-')],
    ['Version', state.version ? C.white(state.version) : C.dim('-')],
    ['Started', state.started_at ? C.white(formatTimestamp(state.started_at)) : C.dim('-')],
    ['Uptime', state.uptime_sec !== null ? C.white(formatDuration(state.uptime_sec)) : C.dim('-')],
    ['Heartbeat', state.last_heartbeat ? C.white(formatTimestamp(state.last_heartbeat)) : C.dim('-')],
  ];

  if (state.status_mismatch) {
    rows.push(['Status file', C.yellow('PID mismatch, ignoring stale status')]);
  } else if (state.running && !state.status) {
    rows.push(['Status file', C.yellow('Waiting for first heartbeat')]);
  }

  for (const [label, value] of rows) {
    lines.push(kv(label, value, valueWidth));
  }

  if (state.status?.channels) {
    lines.push('');
    lines.push(C.bold('  Channels'));
    lines.push('');
    lines.push(kv('SSE', channelState(state.status.channels.sse), valueWidth));
    lines.push(kv('WSS', channelState(state.status.channels.wss), valueWidth));
    if (state.status.channels.last_sse_reconnect) {
      lines.push(kv('Last reconnect', C.dim(state.status.channels.last_sse_reconnect), valueWidth));
    }
  }

  if (state.status?.config) {
    lines.push('');
    lines.push(C.bold('  Configuration'));
    lines.push('');
    lines.push(kv('Databases', C.white(String(state.status.config.databases)), valueWidth));
    lines.push(kv('Projects', C.white(String(state.status.config.projects)), valueWidth));
    lines.push(kv('Revision', C.dim(String(state.status.config.revision)), valueWidth));
  }

  if (state.status?.stats) {
    lines.push('');
    lines.push(C.bold('  Activity'));
    lines.push('');
    const stats = state.status.stats;
    lines.push(kv('Queries', C.white(String(stats.queries_served)), valueWidth));
    lines.push(kv('Streams', C.white(String(stats.streams_served)), valueWidth));
    lines.push(kv('Migrations', C.white(String(stats.migrations_run)), valueWidth));
    lines.push(kv('Cancellations', C.white(String(stats.cancellations)), valueWidth));
    lines.push(kv('Denied', C.yellow(String(stats.permission_denies)), valueWidth));
    lines.push(kv('Audit events', C.white(String(stats.audit_events_written)), valueWidth));
  }

  if (state.status?.last_error) {
    lines.push('');
    lines.push(C.bold(C.red('  Last Error')));
    lines.push('');
    lines.push(kv('Time', C.white(formatTimestamp(state.status.last_error.ts)), valueWidth));
    lines.push(kv('Code', C.yellow(state.status.last_error.code), valueWidth));
    lines.push(kv('Message', C.white(truncateAnsi(state.status.last_error.message, valueWidth)), valueWidth));
  }

  return lines.join('\n');
}

function kv(label: string, value: string, valueWidth: number): string {
  return `    ${C.bold(label.padEnd(14))} ${truncateAnsi(value, valueWidth)}`;
}

function channelState(state: string): string {
  if (state === 'connected') return C.green('connected');
  if (state === 'connecting') return C.yellow('connecting');
  if (state === 'idle') return C.dim('idle');
  if (state === 'disconnected') return C.dim('disconnected');
  return C.red(state);
}
