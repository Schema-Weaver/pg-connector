import { AuditEvent } from './types';
import { CloudClient, CloudDrop, CloudClientStats, deriveHttpBase } from './cloud-client';
import { isDevToken } from '../config/token';

export interface CloudWriterConfig {
  enabled: boolean;
  /** Optional explicit ingest URL. If omitted, derived from cloud_url. */
  url?: string;
  /** wss/ws cloud URL — used to derive the HTTPS ingest base when url absent. */
  cloudUrl?: string;
  agent_token: string;
  agent_id?: string;
  /**
   * Called when a record is dropped instead of delivered. Wire this to a
   * durable local log so cloud-ingest loss is recorded rather than counted
   * (finding M-23).
   */
  onDrop?: (drop: CloudDrop) => void;
}

export interface CloudWriterResult {
  status: 'disabled' | 'not_configured' | 'queued' | 'dropped';
  /** Records dropped so far, when a client is attached. */
  dropped?: number;
}

const AUDIT_INGEST_PATH = '/api/agent/audit/ingest';

/**
 * Cloud audit writer. Buffers audit events and ships them to the cloud ingest
 * endpoint through the shared `CloudClient`, which batches them, retries a
 * failed batch a bounded number of times, and drops the oldest records once its
 * queue is full.
 *
 * What this class actually does when delivery fails, so callers know what they
 * are relying on:
 *   - `log()` never throws and never blocks. It returns `queued` as soon as the
 *     record is in the client's buffer.
 *   - `disabled` when `enabled` is false, `not_configured` when no client could
 *     be built (no URL, or a development token). The record is simply not
 *     buffered; nothing is retried, because there is nowhere to retry to.
 *   - Records the client later cannot deliver are counted here, exposed through
 *     {@link CloudAuditWriter.dropped} and {@link CloudAuditWriter.stats}, and
 *     handed to `onDrop` so an owner with a durable log can record the loss.
 *     There is no in-memory retry marker of its own.
 *
 * The local audit log is the durable record; this is best-effort egress.
 */
export class CloudAuditWriter {
  private readonly config: CloudWriterConfig;
  private client: CloudClient | null = null;
  private droppedCount = 0;

  constructor(config: CloudWriterConfig) {
    this.config = config;
    this.initClient();
  }

  private initClient(): void {
    if (!this.config.enabled) return;

    const token = this.config.agent_token;
    // Single shared dev-token predicate: this check was inlined here and in the
    // operation logger while `isDevToken()` sat unused (finding M-22/M-23).
    if (!token || isDevToken(token)) return;

    let baseUrl = this.config.url;
    if (!baseUrl && this.config.cloudUrl) {
      baseUrl = deriveHttpBase(this.config.cloudUrl);
    }
    if (!baseUrl) return;

    this.client = new CloudClient({
      baseUrl,
      token,
      agentId: this.config.agent_id || 'unknown',
      onDrop: (drop) => {
        this.droppedCount += drop.count;
        this.config.onDrop?.(drop);
      },
    });
    this.client.start();
  }

  async log(event: AuditEvent): Promise<CloudWriterResult> {
    if (!this.config.enabled) {
      return { status: 'disabled' };
    }

    if (!this.client) {
      // No ingest endpoint was resolved, so there is nowhere to buffer to.
      // Reported per call: the sink counts these, and suppressing the repeat
      // here would hide a permanent misconfiguration.
      return { status: 'not_configured', dropped: this.droppedCount };
    }

    try {
      this.client.enqueue(AUDIT_INGEST_PATH, event);
      return { status: 'queued', dropped: this.droppedCount };
    } catch {
      this.droppedCount++;
      return { status: 'dropped', dropped: this.droppedCount };
    }
  }

  /** Records buffered for cloud delivery that were dropped instead. */
  get dropped(): number {
    return this.droppedCount;
  }

  /** Queue / inflight / drop accounting, or `null` when no client is attached. */
  stats(): CloudClientStats | null {
    return this.client ? this.client.getStats() : null;
  }

  /** Flush and close the underlying client. Called on shutdown. */
  async flush(): Promise<void> {
    if (this.client) {
      await this.client.shutdown();
    }
  }
}
