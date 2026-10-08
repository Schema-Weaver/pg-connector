import { resolveAgentRuntimeState, formatDuration, formatTimestamp } from '../daemon/state';
import { getErrorLogStats } from '../daemon/error-tracker';
import { isReplMode } from '../prompt';
import { C, S, check, warn, cross, truncateAnsi, terminalWidth } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatMode(mode: number | null | undefined): string {
  if (typeof mode !== 'number' || !Number.isFinite(mode)) return '-';
  return '0o' + (mode & 0o777).toString(8);
}

/**
 * The audit writer's health reduced to what is safe to print.
 *
 * A status file is a wire format read across daemon versions, so the `audit`
 * block may be absent entirely, partial, or written by a build that shaped it
 * differently. Every field is therefore read defensively and coerced to
 * something printable: a status file this command cannot understand must
 * degrade to fewer facts, never to a crash on the operator's screen.
 */
interface AuditHealthView {
  /** False when the writer reported a problem, or reported nothing at all. */
  healthy: boolean;
  /** The faults behind an unhealthy verdict, in the order they should be read. */
  faults: string[];
  dir: string;
  dirMode: string;
  fileMode: string;
  eventsWritten: string;
  eventsFailed: number;
  dropped: number;
  lastWrite: string;
  chainId: string;
  seq: string;
  retainedFrom: string;
  lastError: string | null;
  /** True when the block said nothing about writability. */
  unreported: boolean;
}

function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function auditHealthView(raw: unknown): AuditHealthView {
  const audit = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const writable = audit.writable;
  const chainError = text(audit.chain_error);
  const lastError = text(audit.last_error);
  const dropped = count(audit.dropped);
  const eventsFailed = count(audit.events_failed);

  // A latched chain error outranks an unwritable directory; lost records outrank
  // both. A block that never mentioned writability has not established that the
  // writer is working, so it is a fault rather than an assumed pass.
  const faults: string[] = [];
  if (chainError) faults.push(chainError);
  if (writable === true) {
    if (dropped > 0) faults.push(`${dropped} record(s) dropped`);
    else if (eventsFailed > 0) faults.push(`${eventsFailed} append(s) failed`);
  } else if (writable === false) {
    faults.push(lastError ? `not writable: ${lastError}` : 'not writable');
  } else {
    faults.push('writer health not reported');
  }

  return {
    healthy: faults.length === 0,
    faults,
    dir: text(audit.dir) ?? '-',
    dirMode: formatMode(audit.dir_mode as number | null | undefined),
    fileMode: formatMode(audit.file_mode as number | null | undefined),
    eventsWritten: String(count(audit.events_written)),
    eventsFailed,
    dropped,
    lastWrite: text(audit.last_write_at) ? formatTimestamp(text(audit.last_write_at)!) : '-',
    chainId: text(audit.chain_id) ?? 'none',
    seq: `seq ${count(audit.seq)}`,
    retainedFrom:
      typeof audit.retained_from_seq === 'number' ? `seq ${audit.retained_from_seq}` : 'whole log',
    lastError,
    unreported: writable !== true && writable !== false,
  };
}

export async function runStatus(args: string[]): Promise<void> {
  const json = args.includes('--json') || args.includes('-j');
  const state = resolveAgentRuntimeState();
  const errors = getErrorLogStats();

  if (json) {
    console.log(
      JSON.stringify(
        {
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
          audit: state.status?.audit ?? null,
          config: state.status?.config ?? null,
          errors_log: errors,
          last_error: state.status?.last_error ?? null,
        },
        null,
        2,
      ),
    );
    exit_(state.running && state.healthy ? 0 : 1);
  }

  console.log();
  console.log(formatStatusOutput(state, errors));
  console.log();
  exit_(state.running && state.healthy ? 0 : 1);
}

function formatStatusOutput(
  state: ReturnType<typeof resolveAgentRuntimeState>,
  errors: ReturnType<typeof getErrorLogStats>,
): string {
  const lines: string[] = [];
  const width = terminalWidth();
  const valueWidth = Math.max(16, width - 28);

  lines.push(C.brand(C.bold('  Agent Status')));
  lines.push('');

  const statusText =
    state.kind === 'running'
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
    [
      'Heartbeat',
      state.last_heartbeat ? C.white(formatTimestamp(state.last_heartbeat)) : C.dim('-'),
    ],
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
    const auditFailed = stats.audit_events_failed ?? 0;
    lines.push(
      kv(
        'Audit failed',
        auditFailed > 0 ? C.yellow(String(auditFailed)) : C.white('0'),
        valueWidth,
      ),
    );
  }

  if (state.status?.audit) {
    const audit = auditHealthView(state.status.audit);
    const { healthy } = audit;

    lines.push('');
    lines.push(C.bold(healthy ? '  Audit Trail' : C.red('  Audit Trail')));
    lines.push('');
    lines.push(kv('State', healthy ? check('Healthy') : cross('UNHEALTHY'), valueWidth));
    if (!healthy) {
      lines.push(kv('Problem', C.brightRed(audit.faults.join('; ')), valueWidth));
    }
    lines.push(kv('Path', C.white(audit.dir), valueWidth));
    lines.push(
      kv(
        'Modes',
        `${C.white(audit.dirMode)} ${C.dim('dir')}  ${C.white(audit.fileMode)} ${C.dim('files')}`,
        valueWidth,
      ),
    );
    lines.push(kv('Written', C.white(audit.eventsWritten), valueWidth));
    lines.push(
      kv(
        'Failed',
        audit.eventsFailed > 0 ? C.yellow(String(audit.eventsFailed)) : C.white('0'),
        valueWidth,
      ),
    );
    lines.push(
      kv(
        'Dropped',
        audit.dropped > 0 ? C.brightRed(String(audit.dropped)) : C.white('0'),
        valueWidth,
      ),
    );
    lines.push(
      kv('Last write', audit.lastWrite === '-' ? C.dim('-') : C.white(audit.lastWrite), valueWidth),
    );
    lines.push(kv('Chain', `${C.white(audit.chainId)} ${C.dim(audit.seq)}`, valueWidth));
    lines.push(
      kv(
        'Retained from',
        audit.retainedFrom === 'whole log'
          ? C.dim(audit.retainedFrom)
          : C.white(audit.retainedFrom),
        valueWidth,
      ),
    );
    if (audit.lastError && !audit.unreported) {
      lines.push(kv('Last error', C.red(truncateAnsi(audit.lastError, valueWidth)), valueWidth));
    }
    lines.push(
      C.dim(
        '    Audit loss must be zero: a non-zero dropped count is history that no longer exists.',
      ),
    );
  }

  if (state.status?.last_error) {
    lines.push('');
    lines.push(C.bold(C.red('  Last Error')));
    lines.push('');
    lines.push(kv('Time', C.white(formatTimestamp(state.status.last_error.ts)), valueWidth));
    lines.push(kv('Code', C.yellow(state.status.last_error.code), valueWidth));
    lines.push(
      kv('Message', C.white(truncateAnsi(state.status.last_error.message, valueWidth)), valueWidth),
    );
  }

  lines.push('');
  lines.push(C.bold('  Error Log'));
  lines.push('');
  lines.push(kv('Path', C.white(errors.path), valueWidth));
  lines.push(
    kv(
      'Size',
      `${C.white(formatBytes(errors.size_bytes))} ${C.dim(`(${errors.records} record(s), ${errors.archives} archive(s))`)}`,
      valueWidth,
    ),
  );
  if (errors.last_error_ts) {
    lines.push(kv('Latest', C.dim(formatTimestamp(errors.last_error_ts)), valueWidth));
  }
  lines.push(C.dim('    Rotated at 2 MiB with 3 archives. SQL and absolute paths are stripped.'));

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
