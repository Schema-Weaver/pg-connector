import { AuditEvent } from './types';
import { CloudClient, deriveHttpBase } from './cloud-client';

export interface CloudWriterConfig {
  enabled: boolean;
  /** Optional explicit ingest URL. If omitted, derived from cloud_url. */
  url?: string;
  /** wss/ws cloud URL — used to derive the HTTPS ingest base when url absent. */
  cloudUrl?: string;
  agent_token: string;
  agent_id?: string;
}

export interface CloudWriterResult {
  status: 'disabled' | 'not_configured' | 'queued' | 'dropped';
}

const AUDIT_INGEST_PATH = '/api/agent/audit/ingest';

/**
 * Cloud audit writer. Buffers audit events and ships them to the cloud
 * ingest endpoint via the shared CloudClient (batched, retried, never
 * blocking). Falls back gracefully when no URL is configured.
 */
export class CloudAuditWriter {
  private readonly config: CloudWriterConfig;
  private client: CloudClient | null = null;
  private warnedNotConfigured = false;
  private droppedCount = 0;

  constructor(config: CloudWriterConfig) {
    this.config = config;
    this.initClient();
  }

  private initClient(): void {
    if (!this.config.enabled) return;

    const token = this.config.agent_token;
    if (!token || token === 'swagt_DEV_LOCAL_ONLY') return;

    let baseUrl = this.config.url;
    if (!baseUrl && this.config.cloudUrl) {
      baseUrl = deriveHttpBase(this.config.cloudUrl);
    }
    if (!baseUrl) return;

    this.client = new CloudClient({
      baseUrl,
      token,
      agentId: this.config.agent_id || 'unknown',
    });
    this.client.start();
  }

  async log(event: AuditEvent): Promise<CloudWriterResult> {
    if (!this.config.enabled) {
      return { status: 'disabled' };
    }

    if (!this.client) {
      if (!this.warnedNotConfigured) {
        // Avoid log spam — surface once.
        this.warnedNotConfigured = true;
      }
      return { status: 'not_configured' };
    }

    try {
      this.client.enqueue(AUDIT_INGEST_PATH, event);
      return { status: 'queued' };
    } catch {
      this.droppedCount++;
      return { status: 'dropped' };
    }
  }

  /** Flush and close the underlying client. Called on shutdown. */
  async flush(): Promise<void> {
    if (this.client) {
      await this.client.shutdown();
    }
  }
}
