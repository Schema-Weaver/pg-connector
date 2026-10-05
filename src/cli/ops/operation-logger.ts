import * as fs from 'fs';
import * as path from 'path';
import { getSwAgentDir } from '../../config/paths';
import { CloudClient, deriveHttpBase } from '../../audit/cloud-client';

export type OpStatus = 'started' | 'ok' | 'error';

export interface OperationEvent {
  ts: string;
  op: string;
  status: OpStatus;
  target?: string;
  duration_ms?: number;
  error?: string;
  agent_id?: string;
}

const OPERATIONS_PATH_SUFFIX = 'operations.jsonl';
const OPERATIONS_INGEST_PATH = '/api/agent/operations/ingest';

let client: CloudClient | null = null;
let agentId: string | undefined;

/**
 * Operation logger — records CLI/lifecycle operations (init, db add/remove,
 * agent start/stop, config changes) so the browser UI can show what was
 * performed on this machine. Two sinks:
 *
 *   1. Local: ~/.sw-agent/operations.jsonl (always, synchronous append).
 *   2. Cloud: POST /api/agent/operations/ingest (best-effort, batched).
 *
 * The cloud sink is fire-and-forget; if the endpoint isn't live yet, events
 * still persist locally and are delivered once the backend ships.
 */
export function initOperationLogger(opts: {
  enabled: boolean;
  cloudUrl?: string;
  token?: string;
  agentId?: string;
}): void {
  agentId = opts.agentId;
  if (!opts.enabled || !opts.token || opts.token === 'swagt_DEV_LOCAL_ONLY') {
    client = null;
    return;
  }
  const baseUrl = opts.cloudUrl ? deriveHttpBase(opts.cloudUrl) : undefined;
  if (!baseUrl) {
    client = null;
    return;
  }
  client = new CloudClient({
    baseUrl,
    token: opts.token,
    agentId: opts.agentId || 'unknown',
  });
  client.start();
}

/** Path to the local operations log. */
export function getOperationsPath(): string {
  return path.join(getSwAgentDir(), OPERATIONS_PATH_SUFFIX);
}

/** Record an operation event to local + cloud. Never throws. */
export function logOperation(event: OperationEvent): void {
  // Local sink — synchronous, reliable.
  try {
    const p = getOperationsPath();
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
    fs.appendFileSync(p, JSON.stringify(event) + '\n', { encoding: 'utf8', mode: 0o600 });
  } catch {
    // never let logging break the operation
  }

  // Cloud sink — best-effort.
  try {
    client?.enqueue(OPERATIONS_INGEST_PATH, event);
  } catch {
    /* ignore */
  }
}

/** Flush + close the cloud client. Call on daemon/REPL shutdown. */
export async function shutdownOperationLogger(): Promise<void> {
  if (client) {
    await client.shutdown();
    client = null;
  }
}

/**
 * Wrap an async operation so it emits `started` and `ok`/`error` events
 * automatically. Returns whatever the wrapped function returns (or rethrows
 * after logging the error).
 */
export async function withOperation<T>(
  op: string,
  target: string | undefined,
  fn: () => Promise<T>,
): Promise<T> {
  const start = Date.now();
  logOperation({ ts: new Date(start).toISOString(), op, status: 'started', target, agent_id: agentId });
  try {
    const result = await fn();
    logOperation({
      ts: new Date().toISOString(),
      op,
      status: 'ok',
      target,
      duration_ms: Date.now() - start,
      agent_id: agentId,
    });
    return result;
  } catch (err) {
    logOperation({
      ts: new Date().toISOString(),
      op,
      status: 'error',
      target,
      duration_ms: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
      agent_id: agentId,
    });
    throw err;
  }
}

/** Read recent operation events from the local log, newest last. */
export async function readRecentOperations(limit: number): Promise<OperationEvent[]> {
  try {
    const content = await fs.promises.readFile(getOperationsPath(), 'utf8');
    const lines = content.split('\n').filter(Boolean);
    const events: OperationEvent[] = [];
    for (const line of lines) {
      try {
        events.push(JSON.parse(line) as OperationEvent);
      } catch {
        // ignore malformed
      }
    }
    return events.slice(-limit);
  } catch {
    return [];
  }
}
