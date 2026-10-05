import * as fs from 'fs';
import * as path from 'path';

export interface DaemonStatus {
  pid: number;
  started_at: string;
  last_heartbeat: string;
  version: string;
  channels: {
    sse: 'connecting' | 'connected' | 'disconnected' | 'error';
    wss: 'idle' | 'connecting' | 'connected' | 'disconnected' | 'error';
    last_sse_reconnect?: string;
    last_wss_session?: string;
  };
  stats: {
    queries_served: number;
    streams_served: number;
    migrations_run: number;
    cancellations: number;
    permission_denies: number;
    audit_events_written: number;
    audit_buffer_overflows: number;
  };
  config?: {
    databases: number;
    projects: number;
    revision: number;
  };
  last_error?: {
    ts: string;
    code: string;
    message: string;
  };
}

export interface StatusFileOptions {
  path: string;
}

import * as crypto from 'crypto';

export async function writeStatusFile(opts: StatusFileOptions, status: DaemonStatus): Promise<void> {
  const dir = path.dirname(opts.path);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
  
  const tmpPath = opts.path + '.tmp.' + crypto.randomBytes(8).toString('hex');
  await fs.promises.writeFile(tmpPath, JSON.stringify(status, null, 2), {
    mode: 0o600,
    encoding: 'utf8',
  });
  
  for (let i = 0; i < 10; i++) {
    try {
      await fs.promises.rename(tmpPath, opts.path);
      return;
    } catch (err) {
      if (i === 9) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

export async function readStatusFile(opts: StatusFileOptions): Promise<DaemonStatus | null> {
  for (let i = 0; i < 10; i++) {
    try {
      const content = await fs.promises.readFile(opts.path, 'utf8');
      return JSON.parse(content) as DaemonStatus;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        return null;
      }
      if (i === 9) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  return null;
}

export function isStatusStale(status: DaemonStatus, now: Date = new Date()): boolean {
  const heartbeatTime = new Date(status.last_heartbeat).getTime();
  const nowTime = now.getTime();
  const ageMs = nowTime - heartbeatTime;
  return ageMs > 90_000;
}
