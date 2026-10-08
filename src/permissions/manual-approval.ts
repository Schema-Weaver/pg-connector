import * as crypto from 'crypto';
import { AgentMessage, Role, createMessage } from '../protocol/envelope';
import { ApprovalRequiredEvent, ApprovalResponseEvent, EventPayload } from '../protocol/messages';
import { APPROVAL_TIMEOUT_ENV_VAR, DEFAULTS, LIMITS } from '../protocol/constants';
import { ManualApprovalResult } from './types';

import { AuditSink } from '../audit/sink';
import { previewStatement } from '../audit/redact';
import { hasCapability } from './role-policy';

/**
 * Resolve the manual-approval window: the single source of truth is
 * DEFAULTS.APPROVAL_TIMEOUT_MS, with an optional operator override read from
 * APPROVAL_TIMEOUT_ENV_VAR and clamped into
 * [LIMITS.APPROVAL_TIMEOUT_MIN_MS, LIMITS.APPROVAL_TIMEOUT_MAX_MS].
 *
 * Audit L-03. The window existed in three places with three different
 * fallbacks (the dead constant, a hardcoded 60_000 in the value advertised to the
 * browser, and `opts ?? env ?? 60_000` in this module), and an override set to
 * something absurd was honoured verbatim. Export this so every caller resolves
 * the same number instead of re-deriving it: `new ManualApprovalHandler({ … })`
 * with no `timeoutMs` already does, so passing `timeoutMs: DEFAULTS.…` at a call
 * site is unnecessary and would *bypass* the env override.
 */
export function resolveApprovalTimeoutMs(env: NodeJS.ProcessEnv = process.env): {
  timeoutMs: number;
  source: 'constant' | 'env' | 'clamped' | 'invalid';
} {
  const constant = DEFAULTS.APPROVAL_TIMEOUT_MS;
  const raw = env[APPROVAL_TIMEOUT_ENV_VAR];
  if (raw === undefined || raw.trim() === '') {
    return { timeoutMs: constant, source: 'constant' };
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed <= 0) {
    return { timeoutMs: constant, source: 'invalid' };
  }
  const clamped = Math.min(
    Math.max(parsed, LIMITS.APPROVAL_TIMEOUT_MIN_MS),
    LIMITS.APPROVAL_TIMEOUT_MAX_MS,
  );
  return { timeoutMs: clamped, source: clamped === parsed ? 'env' : 'clamped' };
}

export interface ManualApprovalOptions {
  /**
   * Approval window in ms. Omit to resolve from DEFAULTS.APPROVAL_TIMEOUT_MS with
   * a clamped env override (see {@link resolveApprovalTimeoutMs}); an explicit
   * value is still clamped so no caller can create an unbounded window.
   */
  timeoutMs?: number;
  /**
   * Extra slack before the independent reaper fires, in ms. Clamped to
   * [MIN_STRANDED_SLACK_MS, MAX_STRANDED_SLACK_MS]; the lower bound exists so the
   * reaper can never be turned into "the same instant as the approval timer",
   * which would report every ordinary expiry as a stranding. Tests use it to keep
   * the reaper observable without waiting out a real approval window.
   */
  strandedSlackMs?: number;
  /** Clock injection point so expiry is testable deterministically. */
  now?: () => number;
  /** Called to send a message to the browser. */
  send: (msg: AgentMessage) => Promise<void>;
  /** Called to register a pending approval (for tracking). */
  onPending?: (requestId: string, expiresAt: number) => void;
  /** Called when approval is resolved (for tracking). */
  onResolved?: (requestId: string, result: ManualApprovalResult) => void;
  /**
   * Called when the independent reaper has to force an approval closed.
   *
   * This is the hook that makes permit release independent of the approval
   * promise settling: the dispatcher releases its concurrency permit here
   * rather than relying on a promise an attacker-controlled `request_id` could
   * strand. It runs before the promise is settled, and it is not allowed to
   * throw into the timer.
   */
  onStranded?: (info: { request_id: string; project: string; user_id: string }) => void;
  /** Optional audit sink for logging decisions and outcomes. */
  auditSink?: AuditSink;
}

interface PendingApproval {
  /**
   * Server-minted key this entry is stored under. Length-prefixed with the
   * request id and the requester, so two distinct pairs cannot collide.
   */
  key: string;
  requestId: string;
  /** The user who requested the write. Only this user may approve it. */
  requesterId: string;
  requesterRole: Role;
  project: string;
  /** Unguessable value the approver must echo back. Prevents replay. */
  nonce: string;
  resolve: (result: ManualApprovalResult) => void;
  timer: NodeJS.Timeout;
  /**
   * Independent reaper, armed at `timeoutMs + slack`. It does not depend on the
   * approval timer having run, and it does not depend on anything having settled
   * the promise — that is the whole point.
   */
  reaper: NodeJS.Timeout;
  expiresAt: number;
}

/**
 * What {@link ManualApprovalHandler.requestApproval} hands back.
 *
 * Deliberately BOTH a promise and a discriminated result. The permission checker
 * (`src/permissions/checker.ts`) has always awaited this call and reads
 * `approval.approved`, so the promise must keep being the return value; a caller
 * that needs to know *why* nothing was approved reads `ok`/`code`. A duplicate
 * `request_id` is therefore a refusal with its own code, not an exception and not
 * an overwrite: the pending entry belongs to the first caller and its promise has
 * to stay reachable, or that request waits out its window and never returns
 *.
 */
export type ManualApprovalRequestResult =
  | (Promise<ManualApprovalResult> & {
      ok: true;
      promise: Promise<ManualApprovalResult>;
      approval_id: string;
    })
  | (Promise<ManualApprovalResult> & {
      ok: false;
      code: 'duplicate_request_id';
      reason: string;
      promise: null;
      approval_id: null;
    });

/**
 * Extra slack on top of the approval window before the independent reaper fires.
 *
 * The approval timer settles the promise; the reaper is what guarantees the
 * permit is released and the trail records that it had to be. It must be strictly
 * later than the approval timer so the ordinary expiry path never looks like a
 * stranding.
 */
export const APPROVAL_STRANDED_SLACK_MS = 5_000;

/** Bounds on the reaper slack, so it can be tuned for tests but not disabled. */
const MIN_STRANDED_SLACK_MS = 100;
const MAX_STRANDED_SLACK_MS = 60_000;

export class ManualApprovalHandler {
  /**
   * Pending approvals, keyed by a **server-minted** id.
   *
   * The key is `randomUUID()` — not the caller-supplied `request_id`.
   * The request id is still recorded on the entry and is still what the map is
   * *searched* by (`findByRequestId`), but it can no longer *address* an entry, so
   * a second frame reusing someone else's id cannot overwrite, expire or resolve
   * their approval. Two requests that both claim id `X` now occupy two distinct
   * keys and neither can reach the other.
   */
  private pending: Map<string, PendingApproval> = new Map();
  private readonly timeoutMs: number;
  private readonly send: (msg: AgentMessage) => Promise<void>;
  private readonly onPending?: (requestId: string, expiresAt: number) => void;
  private readonly onResolved?: (requestId: string, result: ManualApprovalResult) => void;
  private readonly onStranded?: (info: { request_id: string; project: string; user_id: string }) => void;
  private readonly auditSink?: AuditSink;
  private readonly now: () => number;
  private readonly strandedSlackMs: number;

  constructor(opts: ManualApprovalOptions) {
    const resolved = resolveApprovalTimeoutMs();
    const requested = opts.timeoutMs ?? resolved.timeoutMs;
    // Clamp unconditionally: an explicit caller-supplied value must not be able
    // to create an approval window that never expires.
    this.timeoutMs = Math.min(
      Math.max(Math.trunc(requested), LIMITS.APPROVAL_TIMEOUT_MIN_MS),
      LIMITS.APPROVAL_TIMEOUT_MAX_MS,
    );
    if (
      opts.timeoutMs !== undefined &&
      Number.isFinite(opts.timeoutMs) &&
      opts.timeoutMs !== this.timeoutMs
    ) {
      console.warn(
        `[approval] requested timeout ${opts.timeoutMs}ms clamped to ${this.timeoutMs}ms ` +
          `(allowed ${LIMITS.APPROVAL_TIMEOUT_MIN_MS}..${LIMITS.APPROVAL_TIMEOUT_MAX_MS}ms)`,
      );
    } else if (resolved.source !== 'constant') {
      console.warn(
        `[approval] ${APPROVAL_TIMEOUT_ENV_VAR}=${process.env[APPROVAL_TIMEOUT_ENV_VAR]} resolved to ` +
          `${this.timeoutMs}ms (${resolved.source}); the value advertised to the browser and the value ` +
          'enforced are the same number.',
      );
    }
    this.strandedSlackMs = Math.min(
      Math.max(
        Math.trunc(opts.strandedSlackMs ?? APPROVAL_STRANDED_SLACK_MS),
        MIN_STRANDED_SLACK_MS,
      ),
      MAX_STRANDED_SLACK_MS,
    );
    this.now = opts.now ?? Date.now;
    this.send = opts.send;
    this.onPending = opts.onPending;
    this.onResolved = opts.onResolved;
    this.onStranded = opts.onStranded;
    this.auditSink = opts.auditSink;
  }

  /** The window this handler enforces, in ms. */
  getTimeoutMs(): number {
    return this.timeoutMs;
  }

  /**
   * When the independent reaper for a request parked *now* would fire.
   *
   * The dispatcher arms its own watchdog at this deadline so it can release a
   * concurrency permit even if the approval promise never settles.
   */
  getStrandedReaperMs(): number {
    return this.timeoutMs + this.strandedSlackMs;
  }

  /**
   * Whether an approval is pending for exactly this `(request_id, requester)`
   * pair, addressed by SEARCH rather than by key.
   *
   * The dispatcher's watchdog uses this to tell a stranded approval from a
   * merely slow one: a request that is not parked is not waiting for a human.
   */
  isPending(requestId: string, requesterId: string): boolean {
    for (const entry of this.pending.values()) {
      if (entry.requestId === requestId && entry.requesterId === requesterId) return true;
    }
    return false;
  }

  /**
   * Request approval for a query.
   *
   * The pending approval is bound to a **server-minted** key and carries a
   * cryptographically random nonce that only this process knows. `handleResponse`
   * requires the nonce and the requesting user id to match; the key is not
   * derivable from anything the sender controls, so a duplicate `request_id`
   * cannot reach, overwrite or expire another approval.
   *
   * A second request that reuses an id that is already pending for the same
   * requester is REFUSED with `duplicate_request_id` — it does not overwrite the
   * first entry, and the first promise stays reachable. The caller is expected to
   * release the resources it acquired for the refused request.
   *
   * Only a redacted, length-capped preview of the statement is transmitted. The
   * full SQL can carry PII literals (`INSERT INTO users(email) VALUES
   * ('alice@corp.com')`) and this event crosses the cloud boundary.
   */
  requestApproval(params: {
    request_id: string;
    /** Full statement text. Used only to build the redacted preview. */
    sql?: string;
    sql_preview: string;
    intent: 'write' | 'ddl';
    db_alias: string;
    project: string;
    user: { id: string; role: Role };
  }): ManualApprovalRequestResult {
    // Refuse a duplicate BEFORE anything is minted or sent. Overwriting the
    // entry is what orphaned the first promise and leaked its permit; the
    // second caller must learn nothing about the pending approval beyond the
    // fact that its own id is taken.
    if (this.isPending(params.request_id, params.user.id)) {
      const reason = `An approval is already pending for request id '${params.request_id}'`;
      if (this.auditSink) {
        this.auditSink.log({
          id: params.request_id,
          project: params.project,
          user_id: params.user.id,
          role: params.user.role,
          action: 'manual_approval',
          decision: 'deny',
          outcome: 'n/a',
          permission_level: 'manual',
          denial_reason: 'duplicate_request_id',
        });
      }
      return refusedDuplicate(reason);
    }

    const nonce = crypto.randomBytes(32).toString('hex');
    // The deadline is computed ONCE, from the same clock, and both the advertised
    // `expires_at` and the enforcing timer derive from it. Previously the
    // advertised value and the timer were two independent `Date.now()` reads a
    // few microseconds apart, so a browser could be shown a window that had
    // already started closing — and a caller-supplied `expires_at` would have
    // been able to claim more time than was enforced.
    const expiresAt = this.now() + this.timeoutMs;
    const requesterRole = params.user.role;
    const preview = approvalPreview(params.sql, params.sql_preview);
    // Server-minted, so the caller cannot address another principal's approval.
    const approvalId = crypto.randomUUID();

    // `ApprovalRequiredEvent` still declares the full `sql` field for wire
    // compatibility with older browsers. It is deliberately NOT populated: the
    // statement text is not required for a human to approve a statement, and
    // transmitting it is the leak this replaces.
    const eventData = {
      request_id: params.request_id,
      sql_preview: preview,
      intent: params.intent,
      db_alias: params.db_alias,
      approval_nonce: nonce,
      expires_at: expiresAt,
    } as unknown as ApprovalRequiredEvent;

    const eventMsg = createMessage<EventPayload>('event', {
      project: params.project,
      user: { id: params.user.id, role: requesterRole },
      db_alias: params.db_alias,
      payload: {
        kind: 'approval_required',
        data: eventData,
      },
    });

    if (this.auditSink) {
      this.auditSink.log({
        id: params.request_id,
        project: params.project,
        user_id: params.user.id,
        role: requesterRole,
        action: 'manual_approval',
        decision: 'pending',
        outcome: 'n/a',
        permission_level: 'manual',
      });
    }

    const promise = new Promise<ManualApprovalResult>((resolve, reject) => {
      let settled = false;
      const settle = (result: ManualApprovalResult): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };

      const timer = setTimeout(() => {
        const entry = this.pending.get(approvalId);
        if (!entry) return;
        this.pending.delete(approvalId);
        const result: ManualApprovalResult = { approved: false, reason: 'timeout' };
        settle(result);
        this.onResolved?.(params.request_id, result);
        if (this.auditSink) {
          this.auditSink.log({
            id: params.request_id,
            project: params.project,
            user_id: params.user.id,
            role: requesterRole,
            action: 'manual_approval',
            decision: 'expired',
            outcome: 'n/a',
            permission_level: 'manual',
          });
        }
      }, this.timeoutMs);

      // The independent reaper. It does not consult the approval timer
      // and does not wait for anybody to settle the promise: whatever has
      // happened by `timeoutMs + slack`, this entry is closed, the stranding is
      // recorded, the release hook runs, and the promise settles so the caller's
      // `finally` — and with it the concurrency permit — completes.
      const reaper = setTimeout(() => {
        const entry = this.pending.get(approvalId);
        // Already resolved, expired or cancelled: nothing is stranded.
        if (!entry || settled) return;
        this.pending.delete(approvalId);
        if (this.auditSink) {
          this.auditSink.log({
            id: params.request_id,
            project: params.project,
            user_id: params.user.id,
            role: requesterRole,
            action: 'manual_approval',
            decision: 'deny',
            outcome: 'n/a',
            permission_level: 'manual',
            denial_reason: 'approval_promise_stranded',
          });
        }
        // Release the caller's permit first, so the resource is back even if the
        // settlement below is delayed.
        try {
          this.onStranded?.({
            request_id: params.request_id,
            project: params.project,
            user_id: params.user.id,
          });
        } catch (err: unknown) {
          console.error('[approval] stranded-release hook failed:', err);
        }
        const result: ManualApprovalResult = { approved: false, reason: 'timeout' };
        settle(result);
        this.onResolved?.(params.request_id, result);
      }, this.getStrandedReaperMs());

      this.pending.set(approvalId, {
        key: approvalId,
        requestId: params.request_id,
        requesterId: params.user.id,
        requesterRole,
        project: params.project,
        nonce,
        resolve: settle,
        timer,
        reaper,
        expiresAt,
      });

      this.send(eventMsg)
        .then(() => {
          this.onPending?.(params.request_id, expiresAt);
        })
        .catch((err) => {
          const entry = this.pending.get(approvalId);
          if (entry) {
            clearTimeout(entry.timer);
            clearTimeout(entry.reaper);
            this.pending.delete(approvalId);
          }
          reject(err);
        });
    });

    return granted(promise, approvalId);
  }

  /**
   * Resolve a pending approval from a browser response.
   *
   * All of the following must hold, or the pending approval is left untouched:
   *   - a pending approval exists for `(request_id, requesting_user_id)`
   *   - `actorId` (falling back to `user_id`) equals the requesting user
   *   - the actor's role holds the `approve_ddl` capability, so a `viewer` can
   *     never approve a pending write/DDL
   *   - `approval_nonce` matches the value this process minted
   *
   * A nonce is consumed exactly once: the entry is removed as it resolves, so a
   * replayed frame finds nothing.
   *
   * `params` carries the *envelope* identity, which is the only identity the
   * dispatcher has verified. The payload's own `approved_by` string is treated
   * as untrusted display data and is deliberately ignored — the audit record
   * takes the approver from `params`.
   */
  handleResponse(
    event: ApprovalResponseEvent,
    params: { actorId: string; actorRole: Role; now?: number },
  ): { handled: boolean; reason?: string } {
    // Addressed by SEARCH, never by a caller-derived key: two pending approvals
    // may share a `request_id`, and the responder must reach exactly the one
    // that belongs to them. `findByRequestId` prefers the requesting user's own
    // entry so a legitimate approver resolves theirs.
    const pendingApproval = this.findPending(event.request_id, params.actorId);

    if (!pendingApproval) {
      // Do not tell a different principal that an approval is pending for
      // someone else, but do distinguish the two failures for the audit trail.
      const belongsToAnotherUser = this.findByRequestId(event.request_id) !== undefined;
      return {
        handled: false,
        reason: belongsToAnotherUser
          ? 'approver is not the requesting user'
          : 'no pending approval for this request_id',
      };
    }

    // Expiry is checked against the handler's ACTUAL deadline, which is the same
    // value advertised in `expires_at` — including when the caller supplies no
    // `now`, in which case the handler's own clock is used rather than skipping
    // the check entirely.
    const evaluatedAt = params.now ?? this.now();
    if (evaluatedAt > pendingApproval.expiresAt) {
      this.forget(pendingApproval);
      const result: ManualApprovalResult = { approved: false, reason: 'timeout' };
      pendingApproval.resolve(result);
      this.onResolved?.(event.request_id, result);
      if (this.auditSink) {
        this.auditSink.log({
          id: event.request_id,
          project: pendingApproval.project,
          user_id: params.actorId,
          role: params.actorRole,
          action: 'manual_approval',
          decision: 'expired',
          outcome: 'n/a',
          permission_level: 'manual',
        });
      }
      return { handled: false, reason: 'approval window expired' };
    }

    if (params.actorId !== pendingApproval.requesterId) {
      return { handled: false, reason: 'approver is not the requesting user' };
    }

    if (!hasCapability(params.actorRole, 'approve_ddl')) {
      return {
        handled: false,
        reason: `role '${params.actorRole}' may not approve a pending write (requires 'approve_ddl')`,
      };
    }

    if (
      typeof event.approval_nonce !== 'string' ||
      event.approval_nonce.length !== pendingApproval.nonce.length ||
      !timingSafeEqualStrings(event.approval_nonce, pendingApproval.nonce)
    ) {
      return { handled: false, reason: 'approval nonce mismatch' };
    }

    this.forget(pendingApproval);

    const result: ManualApprovalResult = {
      approved: event.approved,
      approved_by: params.actorId,
      reason: event.approved ? undefined : 'denied',
    };

    pendingApproval.resolve(result);
    this.onResolved?.(event.request_id, result);

    if (this.auditSink) {
      this.auditSink.log({
        id: event.request_id,
        project: pendingApproval.project,
        user_id: params.actorId,
        role: params.actorRole,
        action: 'manual_approval',
        decision: event.approved ? 'approved' : 'rejected',
        outcome: 'n/a',
        permission_level: 'manual',
      });
    }

    return { handled: true };
  }

  /** Cancel all pending approvals (e.g. on shutdown). */
  cancelAll(reason: string = 'cancelled'): void {
    for (const [, pendingApproval] of this.pending.entries()) {
      this.forget(pendingApproval);
      const result: ManualApprovalResult = { approved: false, reason };
      pendingApproval.resolve(result);
      this.onResolved?.(pendingApproval.requestId, result);
    }
    this.pending.clear();
  }

  /** Get count of pending approvals. */
  get pendingCount(): number {
    return this.pending.size;
  }

  /**
   * Drop an entry and disarm both of its timers.
   *
   * Both timers, always: leaving the reaper armed after a legitimate resolution
   * would have it fire against a settled promise and record a stranding that
   * never happened.
   */
  private forget(pendingApproval: PendingApproval): void {
    clearTimeout(pendingApproval.timer);
    clearTimeout(pendingApproval.reaper);
    this.pending.delete(pendingApproval.key);
  }

  /**
   * The pending approval `(requestId, requesterId)` may address.
   *
   * The requester's own entry wins, so a duplicate id cannot make one of two
   * requests unreachable to its own requester; the other entry is only reachable
   * by its own requester too.
   */
  private findPending(requestId: string, requesterId: string): PendingApproval | undefined {
    let foreignMatch: PendingApproval | undefined;
    for (const pendingApproval of this.pending.values()) {
      if (pendingApproval.requestId !== requestId) continue;
      if (pendingApproval.requesterId === requesterId) return pendingApproval;
      foreignMatch ??= pendingApproval;
    }
    return foreignMatch;
  }

  /** Pending approvals are few; a scan keeps the failure messages precise. */
  private findByRequestId(requestId: string): PendingApproval | undefined {
    for (const pendingApproval of this.pending.values()) {
      if (pendingApproval.requestId === requestId) return pendingApproval;
    }
    return undefined;
  }
}

/**
 * The preview transmitted on the `approval_required` event.
 *
 * Both inputs are redacted here rather than trusted: the full statement when
 * the caller supplies it, and otherwise the caller's own preview, which has not
 * been through the redactor from this module's point of view. `previewStatement`
 * is idempotent over already-redacted text, so redacting a preview that was
 * produced by the same function costs nothing and removes the case where a
 * caller passes raw SQL in `sql_preview`.
 */
function approvalPreview(sql: string | undefined, suppliedPreview: string): string {
  return previewStatement(typeof sql === 'string' ? sql : suppliedPreview);
}

/** Constant-time string comparison that does not leak length via early exit. */
function timingSafeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    // Still perform a comparison so the timing does not depend on the branch.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * An accepted approval: the promise, plus the codes a caller can branch on.
 *
 * The extra members hang off the promise object rather than replacing it, so
 * `await requestApproval(...)` yields `ManualApprovalResult` exactly as before.
 */
function granted(
  promise: Promise<ManualApprovalResult>,
  approvalId: string,
): ManualApprovalRequestResult {
  return Object.assign(promise, {
    ok: true,
    promise,
    approval_id: approvalId,
  }) as ManualApprovalRequestResult;
}

/**
 * A refused request. The promise resolves to a non-approval carrying the reason,
 * so a caller that only awaits it (the permission checker) denies the request and
 * releases its resources on the normal path, and a caller that inspects `ok` sees
 * the distinct `duplicate_request_id` code.
 */
function refusedDuplicate(reason: string): ManualApprovalRequestResult {
  const promise = Promise.resolve<ManualApprovalResult>({
    approved: false,
    reason: 'duplicate_request_id',
  });
  return Object.assign(promise, {
    ok: false,
    code: 'duplicate_request_id',
    reason,
    promise: null,
    approval_id: null,
  }) as ManualApprovalRequestResult;
}
