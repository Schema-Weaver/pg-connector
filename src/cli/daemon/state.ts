import * as fs from 'fs';
import { getPidFilePath, getStatusFilePath } from '../../config/paths';
import { isProcessAlive, PidFile } from './pid-file';
import { DaemonStatus, isStatusStale } from './status-file';

export type AgentRuntimeKind = 'stopped' | 'starting' | 'running' | 'unresponsive';

export interface AgentRuntimeState {
  kind: AgentRuntimeKind;
  running: boolean;
  healthy: boolean;
  pid: number | null;
  version: string | null;
  started_at: string | null;
  uptime_sec: number | null;
  last_heartbeat: string | null;
  status: DaemonStatus | null;
  pidFile: PidFile | null;
  status_mismatch: boolean;
}

export function resolveAgentRuntimeState(now = new Date()): AgentRuntimeState {
  const pidInfo = readJsonFile<PidFile>(getPidFilePath());
  const statusInfo = readJsonFile<DaemonStatus>(getStatusFilePath());

  let kind: AgentRuntimeKind = 'stopped';
  let running = false;
  let healthy = false;
  let pid: number | null = null;
  let version: string | null = null;
  let startedAt: string | null = null;
  let uptimeSec: number | null = null;
  let lastHeartbeat: string | null = null;
  let statusMismatch = false;

  if (pidInfo) {
    pid = pidInfo.pid;
    version = pidInfo.version;
    startedAt = pidInfo.started_at;
    running = isProcessAlive(pidInfo.pid);

    if (startedAt) {
      const startedMs = new Date(startedAt).getTime();
      if (Number.isFinite(startedMs)) {
        uptimeSec = Math.max(0, Math.floor((now.getTime() - startedMs) / 1000));
      }
    }
  }

  if (!running) {
    kind = 'stopped';
  } else if (!statusInfo) {
    kind = 'starting';
  } else if (statusInfo.pid !== pid) {
    statusMismatch = true;
    kind = 'unresponsive';
  } else {
    lastHeartbeat = statusInfo.last_heartbeat;
    const stale = isStatusStale(statusInfo, now);
    kind = stale ? 'unresponsive' : 'running';
    healthy = !stale;
  }

  return {
    kind,
    running,
    healthy,
    pid,
    version,
    started_at: startedAt,
    uptime_sec: uptimeSec,
    last_heartbeat: lastHeartbeat,
    status: statusInfo,
    pidFile: pidInfo,
    status_mismatch: statusMismatch,
  };
}

function readJsonFile<T>(file: string): T | null {
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

export function formatDuration(sec: number): string {
  const hours = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const secs = Math.floor(sec % 60);
  if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export function formatTimestamp(ts: string): string {
  return ts.replace('T', ' ').slice(0, 19);
}
