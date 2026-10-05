import { AgentMessage, Role, createMessage } from '../protocol/envelope';
import { ApprovalResponseEvent, EventPayload } from '../protocol/messages';
import { ManualApprovalResult } from './types';

import { AuditSink } from '../audit/sink';

export interface ManualApprovalOptions {
  /** Timeout for approval. Default 60_000 ms. */
  timeoutMs?: number;
  /** Called to send a message to the browser. */
  send: (msg: AgentMessage) => Promise<void>;
  /** Called to register a pending approval (for tracking). */
  onPending?: (requestId: string, expiresAt: number) => void;
  /** Called when approval is resolved (for tracking). */
  onResolved?: (requestId: string, result: ManualApprovalResult) => void;
  /** Optional audit sink for logging decisions and outcomes. */
  auditSink?: AuditSink;
}

interface PendingApproval {
  requestId: string;
  resolve: (result: ManualApprovalResult) => void;
  timer: NodeJS.Timeout;
  expiresAt: number;
}

export class ManualApprovalHandler {
  private pending: Map<string, PendingApproval> = new Map();
  private readonly timeoutMs: number;
  private readonly send: (msg: AgentMessage) => Promise<void>;
  private readonly onPending?: (requestId: string, expiresAt: number) => void;
  private readonly onResolved?: (requestId: string, result: ManualApprovalResult) => void;
  private readonly auditSink?: AuditSink;

  constructor(opts: ManualApprovalOptions) {
    const envTimeout = process.env.SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS;
    const parsedTimeout = envTimeout ? parseInt(envTimeout, 10) : undefined;
    this.timeoutMs = opts.timeoutMs ?? parsedTimeout ?? 60_000;
    this.send = opts.send;
    this.onPending = opts.onPending;
    this.onResolved = opts.onResolved;
    this.auditSink = opts.auditSink;
  }

  /**
   * Request approval for a query.
   * Sends approval_required event to browser.
   * Returns a promise that resolves when:
   *   - User approves (approved=true)
   *   - User denies (approved=false)
   *   - Timeout expires (approved=false, reason='timeout')
   */
  requestApproval(params: {
    request_id: string;
    sql: string;
    sql_preview: string;
    intent: 'write' | 'ddl' | 'migration';
    db_alias: string;
    project: string;
    user: { id: string; role: string };
  }): Promise<ManualApprovalResult> {
    const expiresAt = Date.now() + this.timeoutMs;

    const eventMsg = createMessage<EventPayload>('event', {
      project: params.project,
      user: { id: params.user.id, role: params.user.role as Role },
      db_alias: params.db_alias,
      payload: {
        kind: 'approval_required',
        data: {
          request_id: params.request_id,
          sql: params.sql,
          sql_preview: params.sql_preview,
          intent: params.intent,
          db_alias: params.db_alias,
          expires_at: expiresAt,
        },
      },
    });

    if (this.auditSink) {
      this.auditSink.log({
        id: params.request_id,
        project: params.project,
        user_id: params.user.id,
        role: params.user.role as Role,
        action: 'manual_approval',
        decision: 'pending',
        outcome: 'n/a',
        permission_level: 'manual',
      });
    }

    return new Promise<ManualApprovalResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        const pendingApproval = this.pending.get(params.request_id);
        if (pendingApproval) {
          this.pending.delete(params.request_id);
          const result: ManualApprovalResult = { approved: false, reason: 'timeout' };
          resolve(result);
          this.onResolved?.(params.request_id, result);
          if (this.auditSink) {
            this.auditSink.log({
              id: params.request_id,
              project: params.project,
              user_id: params.user.id,
              role: params.user.role as Role,
              action: 'manual_approval',
              decision: 'expired',
              outcome: 'n/a',
              permission_level: 'manual',
            });
          }
        }
      }, this.timeoutMs);

      this.pending.set(params.request_id, {
        requestId: params.request_id,
        resolve,
        timer,
        expiresAt,
      });

      this.send(eventMsg)
        .then(() => {
          this.onPending?.(params.request_id, expiresAt);
        })
        .catch((err) => {
          const pendingApproval = this.pending.get(params.request_id);
          if (pendingApproval) {
            clearTimeout(pendingApproval.timer);
            this.pending.delete(params.request_id);
          }
          reject(err);
        });
    });
  }

  /**
   * Called when browser sends an approval_response event.
   * Resolves the corresponding pending approval.
   */
  handleResponse(event: ApprovalResponseEvent): boolean {
    const pendingApproval = this.pending.get(event.request_id);
    if (!pendingApproval) {
      return false;
    }

    clearTimeout(pendingApproval.timer);
    this.pending.delete(event.request_id);

    const result: ManualApprovalResult = {
      approved: event.approved,
      approved_by: event.approved_by,
      reason: event.approved ? undefined : 'denied',
    };

    pendingApproval.resolve(result);
    this.onResolved?.(event.request_id, result);
    return true;
  }

  /** Cancel all pending approvals (e.g. on shutdown). */
  cancelAll(reason: string = 'cancelled'): void {
    for (const [requestId, pendingApproval] of this.pending.entries()) {
      clearTimeout(pendingApproval.timer);
      const result: ManualApprovalResult = { approved: false, reason };
      pendingApproval.resolve(result);
      this.onResolved?.(requestId, result);
    }
    this.pending.clear();
  }

  /** Get count of pending approvals. */
  get pendingCount(): number {
    return this.pending.size;
  }
}
