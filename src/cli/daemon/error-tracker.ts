import * as fs from 'fs';
import * as path from 'path';
import { getSwAgentDir } from '../../config/paths';

export interface ErrorRecord {
  ts: string;
  level: 'error' | 'warn' | 'fatal';
  op?: string;
  code?: string;
  message: string;
  stack?: string;
  agent_id?: string;
  pid: number;
}

let initialized = false;
let agentId: string | undefined;

/**
 * Track an error to the local errors.jsonl log. Structured, one JSON object
 * per line, never throws. This is the per-operation error record the user can
 * inspect with `sw-agent doctor` and that later ships to the cloud.
 */
export function trackError(err: unknown, opts: { op?: string; level?: 'error' | 'warn' | 'fatal' } = {}): void {
  try {
    const isErr = err instanceof Error;
    const record: ErrorRecord = {
      ts: new Date().toISOString(),
      level: opts.level ?? 'error',
      op: opts.op,
      code: isErr ? (err as any).code : undefined,
      message: isErr ? err.message : String(err),
      stack: isErr ? err.stack : undefined,
      agent_id: agentId,
      pid: process.pid,
    };

    const errorsPath = getErrorsPath();
    const dir = path.dirname(errorsPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.appendFileSync(errorsPath, JSON.stringify(record) + '\n', {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch {
    // Never let error-tracking itself throw.
  }
}

/** Path to the local errors log file. */
export function getErrorsPath(): string {
  return path.join(getSwAgentDir(), 'errors.jsonl');
}

/**
 * Install process-level handlers that capture uncaught exceptions and
 * unhandled promise rejections so a crash still leaves a forensic trace
 * in errors.jsonl. Safe to call once per process.
 */
export function installGlobalHandlers(currentAgentId?: string): void {
  if (initialized) return;
  initialized = true;
  agentId = currentAgentId;

  process.on('uncaughtException', (err) => {
    trackError(err, { op: 'uncaughtException', level: 'fatal' });
  });

  process.on('unhandledRejection', (reason) => {
    trackError(reason, { op: 'unhandledRejection', level: 'error' });
  });
}

/** Read recent error records from the local log, newest last. */
export async function readRecentErrors(limit: number): Promise<ErrorRecord[]> {
  try {
    const content = await fs.promises.readFile(getErrorsPath(), 'utf8');
    const lines = content.split('\n').filter(Boolean);
    const records: ErrorRecord[] = [];
    for (const line of lines) {
      try {
        records.push(JSON.parse(line) as ErrorRecord);
      } catch {
        // ignore malformed
      }
    }
    return records.slice(-limit);
  } catch {
    return [];
  }
}
