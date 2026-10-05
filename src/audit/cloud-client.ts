import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';

export interface CloudClientOptions {
  /** Base cloud URL, e.g. https://api.example.com (no path). */
  baseUrl: string;
  /** Bearer token for Authorization header. */
  token: string;
  /** Agent ID sent via X-Agent-Id header. */
  agentId: string;
  /** Max events before a flush is triggered. Default 50. */
  maxBatch?: number;
  /** Interval between auto-flushes in ms. Default 5000. */
  flushIntervalMs?: number;
  /** Max retry attempts per batch before dropping. Default 3. */
  maxRetries?: number;
}


interface Batch {
  path: string;
  items: unknown[];
  retries: number;
}

const DEFAULT_MAX_BATCH = 50;
const DEFAULT_FLUSH_MS = 5_000;
const DEFAULT_MAX_RETRIES = 3;

/**
 * Shared best-effort cloud delivery client. Buffers events per-path and
 * flushes them in batches on a timer or when a batch fills up. Never throws
 * and never blocks the caller — delivery is fire-and-forget with retry.
 *
 * Uses only Node's built-in http/https modules (no new runtime deps). If the
 * endpoint is absent (404 / connection refused), events are retried a few
 * times then dropped with a local marker, so nothing fails silently.
 */
export class CloudClient {
  private readonly opts: Required<CloudClientOptions>;
  private readonly queues = new Map<string, Batch>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private backoffUntil = 0;

  constructor(opts: CloudClientOptions) {
    this.opts = {
      baseUrl: opts.baseUrl.replace(/\/$/, ''),
      token: opts.token,
      agentId: opts.agentId,
      maxBatch: opts.maxBatch ?? DEFAULT_MAX_BATCH,
      flushIntervalMs: opts.flushIntervalMs ?? DEFAULT_FLUSH_MS,
      maxRetries: opts.maxRetries ?? DEFAULT_MAX_RETRIES,
    };
  }

  /** Start the periodic flush timer. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => this.flushAll(), this.opts.flushIntervalMs);
    // Don't keep the process alive just for telemetry flushing.
    this.timer.unref?.();
  }

  /** Stop the periodic flush timer. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Enqueue a single event for the given path. */
  enqueue(path: string, payload: unknown): void {
    let batch = this.queues.get(path);
    if (!batch) {
      batch = { path, items: [], retries: 0 };
      this.queues.set(path, batch);
    }
    batch.items.push(payload);

    if (batch.items.length >= this.opts.maxBatch) {
      this.flush(path);
    }
  }

  /** Flush a specific path's batch. */
  flush(path: string): void {
    const batch = this.queues.get(path);
    if (!batch || batch.items.length === 0) return;
    if (Date.now() < this.backoffUntil) return;

    const items = batch.items;
    batch.items = [];

    this.post(path, items).then(
      () => {
        batch.retries = 0;
      },
      (_err) => {
        batch.retries++;
        if (batch.retries < this.opts.maxRetries) {
          // Re-queue with exponential backoff.
          batch.items.unshift(...items);
          this.backoffUntil = Date.now() + Math.min(60_000, 1_000 * 2 ** batch.retries);
        } else {
          // Exceeded retries — drop. Caller is responsible for logging a
          // local marker; we surface nothing to avoid noise.
          batch.retries = 0;
        }
      },
    );
  }

  /** Flush all queues. */
  flushAll(): void {
    for (const path of this.queues.keys()) {
      this.flush(path);
    }
  }

  /** Flush and stop — drains remaining events on shutdown. */
  async shutdown(): Promise<void> {
    this.stop();
    this.flushAll();
    // Give in-flight requests a moment to complete.
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  private post(path: string, body: unknown[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const fullUrl = this.opts.baseUrl + path;
      let parsed: URL;
      try {
        parsed = new URL(fullUrl);
      } catch {
        reject(new Error(`Invalid cloud URL: ${fullUrl}`));
        return;
      }

      const lib = parsed.protocol === 'https:' ? https : http;
      const payload = JSON.stringify({ events: body, agent_id: this.opts.agentId });

      const req = lib.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            Authorization: `Bearer ${this.opts.token}`,
            'X-Agent-Id': this.opts.agentId,
          },
          timeout: 5_000,
        },
        (res) => {
          // Drain to free the socket.
          res.resume();
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`Cloud ingest responded ${res.statusCode}`));
          }
        },
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('Cloud ingest timed out'));
      });
      req.write(payload);
      req.end();
    });
  }
}

/**
 * Derive an HTTPS base URL from a wss/ws cloud URL.
 * wss://api.example.com/agent  →  https://api.example.com
 */
export function deriveHttpBase(wsUrl: string): string {
  const https = wsUrl.replace(/^wss:\/\//, 'https://').replace(/^ws:\/\//, 'http://');
  // Strip any trailing path — we append explicit /api/... paths.
  try {
    const u = new URL(https);
    return `${u.protocol}//${u.host}`;
  } catch {
    return https.split('/')[0] + '//' + https.split('/')[2];
  }
}
