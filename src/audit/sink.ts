import * as crypto from 'crypto';
import { AuditEvent, AuditFilter, AuditQueryResult } from './types';
import { computeHash } from './chain';
import { LocalAuditWriter } from './local-writer';
import { CloudAuditWriter } from './cloud-writer';

export interface AuditSinkOptions {
  agentId: string;
  localWriter: LocalAuditWriter;
  cloudWriter: CloudAuditWriter;
  bufferSize?: number;
}

type PendingEvent = Omit<AuditEvent, 'id' | 'ts' | 'agent_id' | 'prev_hash' | 'hash'> & { id?: string };

interface QueueEntry {
  work: () => Promise<void>;
  resolve: () => void;
  reject: (err: any) => void;
}

export class AuditSink {
  private readonly opts: Required<AuditSinkOptions>;
  private queue: QueueEntry[] = [];
  private draining = false;
  private lastHash: string = '0'.repeat(64);
  private pendingFlush: (() => void) | null = null;
  private overflowDroppedCount = 0;

  constructor(opts: AuditSinkOptions) {
    const envBuffer = process.env.SW_AGENT_AUDIT_BUFFER;
    const parsedBuffer = envBuffer ? parseInt(envBuffer, 10) : undefined;
    this.opts = {
      agentId: opts.agentId,
      localWriter: opts.localWriter,
      cloudWriter: opts.cloudWriter,
      bufferSize: opts.bufferSize ?? parsedBuffer ?? 1024,
    };
  }

  log(partial: PendingEvent): void {
    void this.enqueueWork(async () => {
      const event = this.buildEvent(partial);
      await this.opts.localWriter.append(event);
      this.lastHash = event.hash;
      void this.opts.cloudWriter.log(event).catch(err => {
        console.error('[audit] cloud write failed:', err);
      });
    }).catch(err => {
      console.error('[audit] write failed:', err);
    });
  }

  async logSync(partial: PendingEvent): Promise<void> {
    await this.enqueueWork(async () => {
      const event = this.buildEvent(partial);
      await this.opts.localWriter.append(event);
      this.lastHash = event.hash;
      void this.opts.cloudWriter.log(event).catch(err => {
        console.error('[audit] cloud write failed:', err);
      });
    });
  }

  async query(filter: AuditFilter): Promise<AuditQueryResult> {
    const allEvents = await this.opts.localWriter.readAll();
    
    let filtered = allEvents;
    
    if (filter.project) {
      filtered = filtered.filter(e => e.project === filter.project);
    }
    if (filter.user_id) {
      filtered = filtered.filter(e => e.user_id === filter.user_id);
    }
    if (filter.action) {
      filtered = filtered.filter(e => e.action === filter.action);
    }
    if (filter.decision) {
      filtered = filtered.filter(e => e.decision === filter.decision);
    }
    if (filter.outcome) {
      filtered = filtered.filter(e => e.outcome === filter.outcome);
    }
    if (filter.since) {
      const sinceTs = new Date(filter.since).getTime();
      filtered = filtered.filter(e => new Date(e.ts).getTime() >= sinceTs);
    }
    if (filter.until) {
      const untilTs = new Date(filter.until).getTime();
      filtered = filtered.filter(e => new Date(e.ts).getTime() < untilTs);
    }
    
    const total = filtered.length;
    const limit = Math.min(filter.limit ?? 100, 1000);
    const events = filtered.slice(0, limit);
    
    let chainIntact = true;
    let brokenAt: number | undefined;
    
    for (let i = 0; i < allEvents.length; i++) {
      const event = allEvents[i];
      const { hash: storedHash, ...eventWithoutHash } = event;
      
      if (i === 0) {
        if (event.prev_hash !== '0'.repeat(64)) {
          chainIntact = false;
          brokenAt = i;
          break;
        }
      } else {
        if (event.prev_hash !== allEvents[i - 1].hash) {
          chainIntact = false;
          brokenAt = i;
          break;
        }
      }
      
      const expectedHash = computeHash(eventWithoutHash as Omit<AuditEvent, 'hash'>);
      if (storedHash !== expectedHash) {
        chainIntact = false;
        brokenAt = i;
        break;
      }
    }
    
    return {
      events,
      total,
      chain_intact: chainIntact,
      broken_at: brokenAt,
    };
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0 && !this.draining) {
      return;
    }
    
    return new Promise(resolve => {
      this.pendingFlush = resolve;
      this.drain();
    });
  }

  private buildEvent(partial: PendingEvent): AuditEvent {
    const prevHash = this.lastHash;
    const event: Omit<AuditEvent, 'hash'> = {
      id: partial.id || crypto.randomUUID(),
      ts: new Date().toISOString(),
      agent_id: this.opts.agentId,
      project: partial.project,
      user_id: partial.user_id,
      role: partial.role,
      action: partial.action,
      decision: partial.decision,
      outcome: partial.outcome,
      permission_level: partial.permission_level,
      prev_hash: prevHash,
    };
    
    if (partial.statement_fingerprint !== undefined) {
      event.statement_fingerprint = partial.statement_fingerprint;
    }
    if (partial.statement_preview !== undefined) {
      event.statement_preview = partial.statement_preview;
    }
    if (partial.denial_reason !== undefined) {
      event.denial_reason = partial.denial_reason;
    }
    if (partial.error_code !== undefined) {
      event.error_code = partial.error_code;
    }
    if (partial.duration_ms !== undefined) {
      event.duration_ms = partial.duration_ms;
    }
    if (partial.rows_affected !== undefined) {
      event.rows_affected = partial.rows_affected;
    }
    if (partial.rows_returned !== undefined) {
      event.rows_returned = partial.rows_returned;
    }
    if (partial.migration_plan_id !== undefined) {
      event.migration_plan_id = partial.migration_plan_id;
    }
    
    const hash = computeHash(event);
    
    return {
      ...event,
      hash,
    };
  }

  private enqueueWork(work: () => Promise<void>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.queue.length >= this.opts.bufferSize) {
        this.overflowDroppedCount += this.queue.length;
        
        const oldQueue = this.queue;
        this.queue = [];
        for (const entry of oldQueue) {
          entry.reject(new Error('Audit event dropped due to buffer overflow'));
        }
        
        const overflowEvent: PendingEvent = {
          action: 'audit_overflow',
          decision: 'deny',
          outcome: 'n/a',
          denial_reason: 'buffer_overflow',
          project: '__system__',
          user_id: '__system__',
          role: 'admin',
          permission_level: 'full',
          statement_preview: `${this.overflowDroppedCount} events dropped due to audit buffer overflow`,
        };
        
        this.queue.push({
          work: async () => {
            const event = this.buildEvent(overflowEvent);
            await this.opts.localWriter.append(event);
            this.lastHash = event.hash;
            void this.opts.cloudWriter.log(event).catch(err => {
              console.error('[audit] cloud write failed:', err);
            });
          },
          resolve: () => {},
          reject: () => {},
        });
        
        this.overflowDroppedCount = 0;
      }
      
      this.queue.push({ work, resolve, reject });
      void this.drain();
    });
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    
    while (this.queue.length > 0) {
      const entry = this.queue.shift()!;
      try {
        await entry.work();
        entry.resolve();
      } catch (err) {
        console.error('[audit] write failed:', err);
        entry.reject(err);
      }
    }
    
    this.draining = false;
    
    if (this.pendingFlush) {
      const resolve = this.pendingFlush;
      this.pendingFlush = null;
      resolve();
    }
  }
}
