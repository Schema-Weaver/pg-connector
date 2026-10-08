import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { toHttpUrl, TransportGuardOptions } from '../channels/reconnect';
import { deriveRelayCredential } from '../config/token';

export interface CloudClientOptions {
  /** Base cloud URL, e.g. https://api.example.com (no path). Must be TLS. */
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
  /**
   * Allow a cleartext `http:` target. Only wire this to an explicit,
   * non-persisted operator flag (`--insecure-transport`).
   */
  allowInsecureTransport?: boolean;
  /**
   * Hard cap on records buffered per path. Past it the **oldest** records are
   * dropped, because an unbounded queue during a cloud outage is unbounded
   * memory in the daemon (finding M-07). Default 2000.
   */
  maxQueueItems?: number;
  /** Max concurrent in-flight POSTs, across all paths. Default 4. */
  maxInflight?: number;
  /**
   * Hard deadline for one POST, in ms. An endpoint that accepts the connection
   * and never answers is torn down after this, so it cannot hold an in-flight
   * slot forever. Default 5000.
   */
  requestTimeoutMs?: number;
  /**
   * Called whenever records are dropped. This is the local marker hook: a
   * caller that owns a durable log passes a writer here so a loss is recorded
   * rather than inferred (finding M-23). Never allowed to throw into the queue.
   */
  onDrop?: (drop: CloudDrop) => void;
}

export type CloudDropReason = 'queue_overflow' | 'retries_exhausted';

export interface CloudDrop {
  path: string;
  /** How many records were dropped. */
  count: number;
  reason: CloudDropReason;
  /** In-flight POSTs when the drop happened, for context in the marker. */
  inflight: number;
}

export interface CloudPathStats {
  queued: number;
  inflight_batches: number;
  dropped: number;
  delivered: number;
  failures: number;
  /** Remaining backoff for this path, in ms. */
  backoff_remaining_ms: number;
}

export interface CloudClientStats {
  paths: number;
  queued: number;
  inflight: number;
  /** Records dropped and never delivered. Not silent: see `onDrop`. */
  dropped: number;
  delivered: number;
  failures: number;
  per_path: Record<string, CloudPathStats>;
}

interface Batch {
  path: string;
  items: unknown[];
  retries: number;
  inflight: number;
  dropped: number;
  delivered: number;
  failures: number;
}

const DEFAULT_MAX_BATCH = 50;
const DEFAULT_FLUSH_MS = 5_000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_QUEUE_ITEMS = 2_000;
const DEFAULT_MAX_INFLIGHT = 4;
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
/** Backoff applied when a flush is skipped only because a slot was busy. */
const INFLIGHT_BUSY_BACKOFF_MS = 250;

/**
 * Shared best-effort cloud delivery client. Buffers events per-path and
 * flushes them in batches on a timer or when a batch fills up. Never throws
 * and never blocks the caller — delivery is fire-and-forget with retry.
 *
 * Uses only Node's built-in http/https modules (no new runtime deps).
 *
 * Loss policy — bounded on every axis, and never silent (findings M-07, M-23):
 *   - a path buffers at most `maxQueueItems` records; past that the **oldest**
 *     are dropped, so a cloud ingest outage cannot grow the daemon's heap
 *   - backoff is per path, so one failing endpoint does not stall telemetry
 *     for every other endpoint
 *   - at most `maxInflight` POSTs are outstanding, so `post()` promises cannot
 *     pile up unboundedly
 *   - every drop is counted, reported through `getStats()`, and handed to the
 *     `onDrop` marker hook. Records lost this way are counted, not discarded
 *     quietly: the counter is the local marker, and callers with a durable log
 *     record the drop themselves through `onDrop`.
 */
export class CloudClient {
  private readonly opts: Required<Omit<CloudClientOptions, 'onDrop'>> &
    Pick<CloudClientOptions, 'onDrop'>;
  private readonly queues = new Map<string, Batch>();
  private timer: ReturnType<typeof setInterval> | null = null;
  /** Per path: milliseconds during which that path must not be flushed. */
  private readonly backoff = new Map<string, number>();
  private inflight = 0;
  private dropped = 0;
  private delivered = 0;
  private failures = 0;
  private lastDropReport = new Map<string, string>();

  constructor(opts: CloudClientOptions) {
    // Audit H-03: validate at construction, before any batch can be queued, so
    // a plaintext ingest URL can never become the bearer token's destination.
    const parsed = toHttpUrl(opts.baseUrl.replace(/\/$/, ''), {
      allowInsecure: opts.allowInsecureTransport === true,
      context: 'cloud telemetry client',
    });
    // Explicit paths are appended per request; a base query/fragment would
    // swallow them.
    parsed.search = '';
    parsed.hash = '';
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    const baseUrl = parsed.toString().replace(/\/$/, '');

    this.opts = {
      baseUrl,
      token: opts.token,
      agentId: opts.agentId,
      maxBatch: opts.maxBatch ?? DEFAULT_MAX_BATCH,
      flushIntervalMs: opts.flushIntervalMs ?? DEFAULT_FLUSH_MS,
      maxRetries: opts.maxRetries ?? DEFAULT_MAX_RETRIES,
      allowInsecureTransport: opts.allowInsecureTransport === true,
      maxQueueItems: normalizePositive(opts.maxQueueItems, DEFAULT_MAX_QUEUE_ITEMS),
      maxInflight: normalizePositive(opts.maxInflight, DEFAULT_MAX_INFLIGHT),
      requestTimeoutMs: normalizePositive(opts.requestTimeoutMs, DEFAULT_REQUEST_TIMEOUT_MS),
      onDrop: opts.onDrop,
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

  /**
   * Enqueue a single event for the given path.
   *
   * Never throws and never blocks. The queue is capped: when it is full the
   * oldest records are dropped and counted, which is the only bounded choice
   * when the destination is unavailable — an unbounded queue just moves the
   * outage into the daemon's heap (finding M-07).
   */
  enqueue(path: string, payload: unknown): void {
    const batch = this.batchFor(path);

    if (batch.items.length >= this.opts.maxQueueItems) {
      const dropCount = batch.items.length - this.opts.maxQueueItems + 1;
      const dropped = batch.items.splice(0, dropCount);
      this.recordDrop(path, dropped.length, 'queue_overflow');
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
    if (Date.now() < this.backoffUntil(path)) return;

    if (this.inflight >= this.opts.maxInflight) {
      // Every POST slot is busy. Leave the batch buffered and try again on the
      // next tick rather than opening an unbounded number of sockets.
      this.setBackoff(path, INFLIGHT_BUSY_BACKOFF_MS);
      return;
    }

    const items = batch.items;
    batch.items = [];
    batch.inflight++;
    this.inflight++;

    this.post(path, items).then(
      () => {
        this.settle(batch, items.length, null);
        batch.retries = 0;
      },
      (_err) => {
        batch.retries++;
        batch.failures++;
        this.failures++;
        if (batch.retries < this.opts.maxRetries) {
          // Re-queue at the front: newer records must not overtake older ones.
          // The cap still applies — splice so the head cannot grow past it.
          const room = this.opts.maxQueueItems - batch.items.length;
          const keep = items.length > room ? items.slice(items.length - room) : items;
          const evicted = items.length - keep.length;
          batch.items.unshift(...keep);
          if (evicted > 0) this.recordDrop(path, evicted, 'queue_overflow');
          this.setBackoff(path, Math.min(60_000, 1_000 * 2 ** batch.retries));
        } else {
          // Retries exhausted: counted and reported, not discarded quietly.
          this.recordDrop(path, items.length, 'retries_exhausted');
          batch.retries = 0;
        }
        this.settle(batch, items.length, _err);
      },
    );
  }

  /** Flush all queues. */
  flushAll(): void {
    for (const path of this.queues.keys()) {
      this.flush(path);
    }
  }

  /**
   * Delivery accounting. `dropped` is the number of records that were buffered
   * and never delivered; it is cumulative for the life of the client.
   */
  getStats(): CloudClientStats {
    const per_path: Record<string, CloudPathStats> = {};
    let queued = 0;
    for (const [path, batch] of this.queues) {
      queued += batch.items.length;
      per_path[path] = {
        queued: batch.items.length,
        inflight_batches: batch.inflight,
        dropped: batch.dropped,
        delivered: batch.delivered,
        failures: batch.failures,
        backoff_remaining_ms: Math.max(0, this.backoffUntil(path) - Date.now()),
      };
    }
    return {
      paths: this.queues.size,
      queued,
      inflight: this.inflight,
      dropped: this.dropped,
      delivered: this.delivered,
      failures: this.failures,
      per_path,
    };
  }

  /** Flush and stop — drains remaining events on shutdown. */
  async shutdown(): Promise<void> {
    this.stop();
    this.flushAll();
    // Give in-flight requests a moment to complete.
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  private batchFor(path: string): Batch {
    let batch = this.queues.get(path);
    if (!batch) {
      batch = { path, items: [], retries: 0, inflight: 0, dropped: 0, delivered: 0, failures: 0 };
      this.queues.set(path, batch);
    }
    return batch;
  }

  private settle(batch: Batch, count: number, _err: unknown): void {
    batch.inflight--;
    this.inflight--;
    if (_err === null) {
      batch.delivered += count;
      this.delivered += count;
    }
  }

  private setBackoff(path: string, ms: number): void {
    const until = Date.now() + ms;
    const current = this.backoff.get(path) ?? 0;
    if (until > current) this.backoff.set(path, until);
  }

  private backoffUntil(path: string): number {
    return this.backoff.get(path) ?? 0;
  }

  private recordDrop(path: string, count: number, reason: CloudDropReason): void {
    if (count <= 0) return;
    const batch = this.batchFor(path);
    batch.dropped += count;
    this.dropped += count;

    // One complaint per path per reason, so an outage is visible without
    // turning into its own denial of service.
    const key = `${path}:${reason}`;
    if (this.lastDropReport.get(key) !== reason) {
      this.lastDropReport.set(key, reason);
      console.error(
        `[audit] cloud telemetry dropped ${count} record(s) on ${path} (${reason}); ` +
          `total dropped ${this.dropped}. Queued: ${batch.items.length}.`,
      );
    }

    try {
      this.opts.onDrop?.({ path, count, reason, inflight: this.inflight });
    } catch (err: unknown) {
      // Rate limited with the drop notice: a broken marker must not turn a
      // telemetry outage into a log flood.
      const markerKey = `${path}:${reason}:marker`;
      if (this.lastDropReport.get(markerKey) !== 'marker') {
        this.lastDropReport.set(markerKey, 'marker');
        console.error('[audit] cloud drop marker failed:', err);
      }
    }
  }

  private post(path: string, body: unknown[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const fullUrl = this.opts.baseUrl + path;
      let parsed: URL;
      try {
        // Re-validated per request: the guard is the only thing standing
        // between the agent token and a cleartext socket.
        parsed = toHttpUrl(fullUrl, {
          allowInsecure: this.opts.allowInsecureTransport,
          context: 'cloud telemetry ingest',
        });
      } catch (err) {
        reject(err);
        return;
      }

      // Unreachable unless the constructor accepted an explicit insecure opt-in.
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
            // Derived, never the raw agent token.
            Authorization: `Bearer ${deriveRelayCredential(this.opts.token)}`,
            'X-Agent-Id': this.opts.agentId,
          },
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

      // Timeouts must be armed explicitly: the `timeout` request option is not
      // honoured by every Node version, and an endpoint that accepts the
      // connection and never answers would otherwise hold an in-flight slot
      // for the life of the process (finding M-07).
      const deadline = setTimeout(() => {
        req.destroy(new Error(`Cloud ingest timed out after ${this.opts.requestTimeoutMs}ms`));
      }, this.opts.requestTimeoutMs);
      deadline.unref?.();
      const clearDeadline = () => clearTimeout(deadline);
      req.on('close', clearDeadline);
      req.on('error', (err) => {
        clearDeadline();
        reject(err);
      });
      req.on('timeout', () => {
        req.destroy(new Error('Cloud ingest timed out'));
      });
      req.write(payload);
      req.end();
    });
  }
}

function normalizePositive(value: number | undefined, fallback: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 1) return fallback;
  return Math.floor(value);
}

/**
 * Derive an HTTPS base URL from a wss/ws cloud URL.
 * wss://api.example.com/agent  →  https://api.example.com
 *
 * Audit H-03: the returned scheme is derived through the shared transport
 * guard, never guessed. A `ws://`/`http://` input throws
 * `TransportSecurityError` rather than silently yielding a plaintext base
 * (the previous `ws:// → http://` mapping) or an unparseable
 * `split('/')[0] + '//' + split('/')[2]` fragment.
 */
export function deriveHttpBase(wsUrl: string, opts: TransportGuardOptions = {}): string {
  const parsed = toHttpUrl(wsUrl, {
    allowInsecure: opts.allowInsecure,
    context: opts.context ?? 'cloud telemetry base URL',
  });
  return `${parsed.protocol}//${parsed.host}`;
}
