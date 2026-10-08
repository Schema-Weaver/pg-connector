/* eslint-disable @typescript-eslint/no-explicit-any */
import * as crypto from 'crypto';
import { WakeChannel, WakeChannelOptions } from './wake-channel';
import { DataChannel } from './data-channel';
import {
  AgentMessage,
  ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT,
  ROLES,
  Role,
  deriveSessionMacKey,
  isRole,
} from '../protocol/envelope';
import { InboundEnvelopeGuard } from '../protocol/validate';
import { ProtocolError } from '../protocol/serialize';
import { DEFAULTS, ENVELOPE_MAC_REQUIRED_DEFAULT } from '../protocol/constants';
import type { AuditSink } from '../audit/sink';
import {
  AgentSessionState,
  DataChannelCloseReason,
  EnvelopeAuthPolicy,
  MessageHandler,
  WakeEvent,
  StateChangeHandler,
} from './types';
import { MachineConfig } from '../config/machine-config';

export interface AgentSessionOptions {
  /** Machine config (loaded by caller). */
  machineConfig: MachineConfig;
  /** Optional: returns configured database list from databases.config.json. */
  getDatabases?: () => Array<{ db_alias: string; database: string }>;
  /** Message handler. Called for every incoming message on the data channel. */
  onMessage: MessageHandler;
  /** State change handler. Called whenever AgentSessionState changes. */
  onStateChange?: StateChangeHandler;
  /** Optional: custom wake channel options (for tests). */
  wakeChannelOverrides?: Partial<WakeChannelOptions>;
  /** Optional: abort signal. */
  abortSignal?: AbortSignal;
  /**
   * Per-session envelope authentication policy. Omit to take every default from
   * src/protocol/constants.ts (a MAC is required; the relay may negotiate up to
   * `admin`).
   */
  envelopeAuth?: EnvelopeAuthPolicy;
  /** Audit sink for session lifecycle events. */
  auditSink?: AuditSink;
  /**
   * Explicit authorisation to tear down a HEALTHY data channel because a wake
   * event named a different `browser_session_id` (audit M-15).
   *
   * Omit it and the session is never replaced while healthy. When present, the
   * caller decides — that is the point: session replacement must be a
   * deliberate, policy-bearing decision, not an accident of message ordering. It
   * must itself verify that the incoming session is authorised (for example by
   * checking a token the cloud scoped to the new session); the agent cannot
   * establish that on its own.
   */
  authoriseSessionReplacement?: (event: WakeEvent, current: WakeEvent | undefined) => boolean;
  /**
   * Called when requests are being failed because the channel is being torn
   * down, so the execution layer can cancel the backends. Receive the request
   * ids and the close reason.
   */
  onInFlightDrained?: (
    requestIds: string[],
    reason: DataChannelCloseReason,
  ) => void | Promise<void>;
  /** Clock injection point for the churn budget. Defaults to `Date.now`. */
  now?: () => number;
  /** Session churn budget override. Every field defaults to DEFAULTS. */
  sessionChangeBudget?: {
    /** Minimum spacing between admitted replacements. */
    cooldownMs?: number;
    /** Window the count applies over. */
    windowMs?: number;
    /** Max admitted replacements per window. */
    maxPerWindow?: number;
  };
}

/** What a wake event was permitted to do to the active data channel. */
export type SessionAdmission =
  | { action: 'adopt'; reason: string; churn?: never }
  | { action: 'noop'; reason: string; churn?: never }
  | { action: 'replace'; reason: string; churn: ChurnVerdict }
  | { action: 'reject'; reason: string; churn: ChurnVerdict };

export interface ChurnVerdict {
  allowed: boolean;
  reason: string;
  replacements: number;
}

/**
 * Subset of `MachineConfig` this session reads for envelope authentication.
 * Group 6 owns the config schema; reading it structurally keeps this file
 * compiling against the current `MachineConfig` while still honouring the key
 * the moment it exists.
 */
interface MachineConfigSecurity {
  envelope_mac_required?: boolean;
  max_negotiable_role?: Role;
}

export class AgentSession {
  private wakeChannel?: WakeChannel;
  private dataChannel?: DataChannel;
  private state: AgentSessionState;
  private readonly opts: AgentSessionOptions;
  private inFlightRequests: Map<string, AgentMessage> = new Map();
  private currentWakeEvent?: WakeEvent;
  private inboundGuard?: InboundEnvelopeGuard;

  private activeMessageHandler: MessageHandler;
  private activeStateChangeHandler?: StateChangeHandler;

  /** Explicit authoriser for tearing down a healthy session. Absent = deny. */
  private readonly authoriseReplacement?: AgentSessionOptions['authoriseSessionReplacement'];
  private readonly now: () => number;
  private readonly sessionPolicy: {
    cooldownMs: number;
    windowMs: number;
    maxPerWindow: number;
  };
  /**
   * Timestamps of session-change attempts inside the current window, oldest
   * first. Bounded: entries are trimmed by age and the array is hard-capped at
   * `maxPerWindow * 4`, so a churn flood cannot grow it without limit.
   */
  private readonly sessionChanges: Array<{ at: number; admitted: boolean }> = [];

  constructor(opts: AgentSessionOptions) {
    this.opts = opts;
    this.activeMessageHandler = opts.onMessage;
    this.activeStateChangeHandler = opts.onStateChange;
    this.authoriseReplacement = opts.authoriseSessionReplacement;
    this.now = opts.now ?? Date.now;
    this.sessionPolicy = {
      cooldownMs: opts.sessionChangeBudget?.cooldownMs ?? DEFAULTS.SESSION_CHANGE_COOLDOWN_MS,
      windowMs: opts.sessionChangeBudget?.windowMs ?? DEFAULTS.SESSION_CHANGE_WINDOW_MS,
      maxPerWindow:
        opts.sessionChangeBudget?.maxPerWindow ?? DEFAULTS.SESSION_CHANGE_MAX_PER_WINDOW,
    };

    this.state = {
      wake: 'disconnected',
      data: 'closed',
      has_in_flight: false,
      reconnect_attempts: 0,
      negotiated_roles: [],
      envelope_mac_active: false,
      envelope_authn_failures: 0,
      session_replacements: 0,
      session_replacement_rejections: 0,
    };

    if (this.opts.abortSignal) {
      if (this.opts.abortSignal.aborted) {
        this.stop().catch(() => {});
      } else {
        this.opts.abortSignal.addEventListener('abort', () => {
          this.stop().catch((err) => {
            console.error('Error stopping AgentSession via abortSignal:', err);
          });
        });
      }
    }
  }

  /** Start the agent. Boots wake channel. Returns when fully started. */
  async start(): Promise<void> {
    this.updateState({
      wake: 'connecting',
    });

    this.wakeChannel = new WakeChannel({
      cloudUrl: this.opts.machineConfig.cloud_url,
      token: this.opts.machineConfig.agent_token,
      agentId: this.opts.machineConfig.agent_id,
      getDatabases: this.opts.getDatabases,
      onWake: (event) => this.handleWakeEvent(event),
      onStateChange: (wakeState, error) => {
        this.updateState({
          wake: wakeState,
          last_error: error || this.state.last_error,
          reconnect_attempts: this.wakeChannel ? this.wakeChannel.getReconnectAttempts() : 0,
          wake_connected_at: wakeState === 'connected' ? Date.now() : this.state.wake_connected_at,
        });
      },
      abortSignal: this.opts.abortSignal,
      ...this.opts.wakeChannelOverrides,
    });

    await this.wakeChannel.start();
  }

  /** Graceful shutdown. Closes data channel, then wake channel. */
  async stop(): Promise<void> {
    if (this.dataChannel) {
      await this.dataChannel.close('shutdown');
      this.dataChannel = undefined;
    }
    this.clearInboundGuard();
    if (this.wakeChannel) {
      await this.wakeChannel.stop();
      this.wakeChannel = undefined;
    }
  }

  /**
   * Send a message out via the data channel.
   * If data channel is closed, opens it first (using current wake event's token).
   * Throws if no wake event has been received yet (i.e., no token to open data channel).
   */
  async send(msg: AgentMessage): Promise<void> {
    if (this.state.data !== 'open' || !this.dataChannel) {
      throw new ProtocolError('channel_closed', 'Data channel not open');
    }

    await this.dataChannel.send(msg);

    // Track requests (not responses/events/chunks/ends/errors)
    if (
      msg.type !== 'response' &&
      msg.type !== 'error' &&
      msg.type !== 'stream_chunk' &&
      msg.type !== 'stream_end' &&
      msg.type !== 'event'
    ) {
      this.trackInFlight(msg.id, msg);
    }
  }

  /** Register a message handler (overrides the one from opts). */
  setMessageHandler(handler: MessageHandler): void {
    this.activeMessageHandler = handler;
  }

  /**
   * Resolve once this session's data channel has caught up: the send buffer is at
   * or below its high-water mark and nothing earlier is still in flight.
   *
   * This is the transport signal a cursor fetch loop waits on (audit H-10), so
   * the producer stops asking PostgreSQL for rows while the relay is behind.
   * Hand it to the dispatcher as its `waitForDrain` option.
   *
   * Resolves immediately when there is no data channel — before the first wake
   * event, or after the channel was torn down. A socket that will never drain
   * again must not strand a producer, and the caller still observes the missing
   * channel on its next {@link send}.
   */
  waitForDrain(): Promise<void> {
    return this.dataChannel ? this.dataChannel.waitForDrain() : Promise.resolve();
  }

  /** Register a state change handler (overrides the one from opts). */
  onStateChange(handler: StateChangeHandler): void {
    this.activeStateChangeHandler = handler;
  }

  /** Current state. */
  getState(): AgentSessionState {
    return this.state;
  }

  /**
   * The envelope authenticator for the open data channel, or undefined before
   * the first wake event. Exposed so diagnostics and tests can inspect the
   * negotiated role set and replay-cache occupancy.
   */
  getInboundGuard(): InboundEnvelopeGuard | undefined {
    return this.inboundGuard;
  }

  /**
   * Roles permitted for the current session. Empty until a wake event arrives,
   * and empty — meaning nothing is permitted — if the relay negotiated none.
   */
  getNegotiatedRoles(): Role[] {
    return this.state.negotiated_roles;
  }

  /**
   * Build the per-session inbound authenticator: derive the MAC key from the
   * data-channel token, intersect the roles the relay asked for with the local
   * ceiling, and start with an empty replay cache.
   */
  private buildInboundGuard(event: WakeEvent): {
    guard: InboundEnvelopeGuard;
    requireMac: boolean;
  } {
    const security =
      (this.opts.machineConfig as unknown as { security?: MachineConfigSecurity }).security ?? {};
    const policy: EnvelopeAuthPolicy = {
      requireMac: this.opts.envelopeAuth?.requireMac ?? security.envelope_mac_required,
      maxNegotiableRole: this.opts.envelopeAuth?.maxNegotiableRole ?? security.max_negotiable_role,
    };
    const requireMac = policy.requireMac ?? ENVELOPE_MAC_REQUIRED_DEFAULT;
    const ceiling = policy.maxNegotiableRole ?? ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT;
    const browserSessionId = event.browser_session_id || 'unknown';
    const allowedRoles = intersectNegotiatedRoles(event.allowed_roles, ceiling);
    const macKey = deriveSessionMacKey({
      dataChannelToken: event.data_channel_token,
      agentId: this.opts.machineConfig.agent_id,
      browserSessionId,
    });

    if (allowedRoles.length === 0) {
      console.error(
        '[authn] Data channel negotiated no usable role; every inbound envelope will be rejected. ' +
          'The relay must send WakeEvent.allowed_roles for this session.',
      );
    }
    if (!requireMac) {
      console.error(
        '[authn] WARNING: per-session envelope MAC verification is DISABLED by configuration. ' +
          'Only the negotiated role set, freshness window and replay cache are enforced.',
      );
    }

    return {
      guard: new InboundEnvelopeGuard({
        macKey,
        allowedRoles,
        requireMac,
        // The ceiling is applied twice on purpose. `intersectNegotiatedRoles`
        // trims the set at session open; the guard re-checks every frame so a
        // bug in that intersection, a replacement session, or any other
        // construction path that hands the guard a wider set still cannot
        // assert a role above the operator's ceiling.
        maxNegotiableRole: ceiling,
      }),
      requireMac,
    };
  }

  /**
   * Authenticate one inbound envelope, then hand it on. A rejected envelope
   * never reaches `onMessage` — and therefore never reaches the dispatcher — and
   * the data channel is torn down rather than left open to a peer that is
   * forging authorization claims.
   */
  private handleInboundMessage(msg: AgentMessage): Promise<void> | void {
    const guard = this.inboundGuard;
    if (!guard) {
      const detail = 'No envelope authenticator is active for this data channel';
      console.error(`[authn] rejected inbound envelope ${msg?.id ?? 'unknown'}: ${detail}`);
      this.dataChannel?.forceClose('protocol_error', detail);
      return;
    }
    try {
      guard.verify(msg);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      console.error(`[authn] rejected inbound envelope ${msg?.id ?? 'unknown'}: ${detail}`);
      this.updateState({
        envelope_authn_failures: this.state.envelope_authn_failures + 1,
        last_envelope_authn_failure_at: Date.now(),
        last_error: detail,
      });
      this.dataChannel?.forceClose('protocol_error', detail);
      return;
    }
    return this.activeMessageHandler(msg);
  }

  /** Tear down the current authenticator so no envelope can be admitted. */
  private clearInboundGuard(): void {
    if (this.inboundGuard) {
      this.inboundGuard.reset();
      this.inboundGuard = undefined;
    }
    this.updateState({ negotiated_roles: [], envelope_mac_active: false });
  }

  /**
   * Track an in-flight request (for reconnect/resume).
   * Called by execution engine before sending a request.
   * Cleared when response is received.
   */
  trackInFlight(requestId: string, msg: AgentMessage): void {
    this.inFlightRequests.set(requestId, msg);
    this.updateState({ has_in_flight: this.inFlightRequests.size > 0 });
  }

  untrackInFlight(requestId: string): void {
    this.inFlightRequests.delete(requestId);
    this.updateState({ has_in_flight: this.inFlightRequests.size > 0 });
  }

  getInFlight(): Map<string, AgentMessage> {
    return this.inFlightRequests;
  }

  private handleWakeEvent(event: WakeEvent): void {
    this.processWakeEvent(event).catch((err) => {
      console.error('AgentSession: failed processing wake event:', err);
    });
  }

  /**
   * Decide what a wake event is allowed to do to the active data channel.
   *
   * Audit M-15. The previous implementation closed the live channel and opened a
   * new one for ANY wake event carrying a different `browser_session_id`, which
   * made session takeover and forced disconnection a single message, and
   * orphaned every in-flight query on the old channel. The policy is now:
   *
   *   1. Same session while healthy → no-op (a duplicate wake for work already
   *      being served).
   *   2. A different `browser_session_id` while the current channel is HEALTHY
   *      (open or connecting) → REPLACED only when the caller supplied an explicit
   *      authoriser, otherwise REJECTED. Deny by default.
   *   3. A different session while the current channel is DEAD (closed or error)
   *      → replaced, because there is nothing to take over and refusing would
   *      strand the agent.
   *   4. No channel at all (first wake) → adopted.
   *
   * Session churn is additionally rate limited, so the 3 case cannot be turned
   * into a cheaper denial of service than tearing the channel down once.
   */
  private evaluateWakeEvent(event: WakeEvent): SessionAdmission {
    const current = this.currentWakeEvent?.browser_session_id;
    const incoming = event.browser_session_id || 'unknown';
    const dataState = this.dataChannel ? this.dataChannel.getState() : this.state.data;
    const healthy = dataState === 'open' || dataState === 'connecting';

    if (!this.dataChannel) {
      return { action: 'adopt', reason: 'no active data channel' };
    }

    if (current === incoming) {
      // Re-delivery for the session already being served. Nothing to tear down.
      return { action: 'noop', reason: 'wake event for the active browser session' };
    }

    // An authoriser only speaks for a healthy channel: replacing a dead one is
    // recovery, not a security decision, and must not require a policy.
    //
    // Deny by default. The refusal must NOT be nested inside
    // `if (this.authoriseReplacement)`: an absent authoriser means nobody has
    // established that the party naming a new session is entitled to displace
    // the one already being served, and that is exactly the session-hijack
    // window. Gating the refusal on the authoriser existing inverted the
    // policy, so an unconfigured session silently tore down a healthy channel
    // for any wake event carrying a different `browser_session_id`.
    if (healthy) {
      let authorised = false;
      let authoriserConfigured = false;
      if (this.authoriseReplacement) {
        authoriserConfigured = true;
        try {
          authorised = this.authoriseReplacement(event, this.currentWakeEvent) === true;
        } catch (err) {
          authorised = false;
          console.error('AgentSession: session replacement authoriser threw; denying:', err);
        }
      }
      if (!authorised) {
        return {
          action: 'reject',
          reason:
            `refused session replacement while browser session '${current ?? 'unknown'}' is still ` +
            `healthy (data channel ${dataState}): ` +
            (authoriserConfigured
              ? 'the configured authoriser declined'
              : 'no session replacement authoriser is configured (deny by default)'),
          churn: {
            allowed: false,
            reason: authoriserConfigured ? 'not authorised' : 'no authoriser configured',
            replacements: this.sessionChanges.length,
          },
        };
      }
    }

    const churn = this.checkChurnBudget();
    if (!churn.allowed) {
      return { action: 'reject', reason: churn.reason, churn };
    }

    return {
      action: 'replace',
      reason: healthy
        ? `replacing browser session '${current ?? 'unknown'}' under explicit authorisation`
        : `replacing dead browser session '${current ?? 'unknown'}' (data channel ${dataState})`,
      churn,
    };
  }

  /**
   * Bounded session-churn budget (audit M-15): at most
   * DEFAULTS.SESSION_CHANGE_MAX_PER_WINDOW session changes inside any
   * DEFAULTS.SESSION_CHANGE_WINDOW_MS window, and never two closer together than
   * DEFAULTS.SESSION_CHANGE_COOLDOWN_MS. Deny by default when the budget is out.
   */
  private checkChurnBudget(): { allowed: boolean; reason: string; replacements: number } {
    const now = this.now();
    const window = this.sessionPolicy.windowMs;
    const thisChange = {
      at: now,
      admitted: false,
    };
    while (this.sessionChanges.length > 0 && now - this.sessionChanges[0].at > window) {
      this.sessionChanges.shift();
    }

    if (this.sessionChanges.length >= this.sessionPolicy.maxPerWindow) {
      thisChange.admitted = false;
      this.sessionChanges.push(thisChange);
      if (this.sessionChanges.length > this.sessionPolicy.maxPerWindow * 4) {
        this.sessionChanges.splice(0, this.sessionChanges.length - this.sessionPolicy.maxPerWindow);
      }
      return {
        allowed: false,
        reason:
          `session churn limit reached: ${this.sessionChanges.length} replacements within ${window}ms ` +
          `(max ${this.sessionPolicy.maxPerWindow})`,
        replacements: this.sessionChanges.length,
      };
    }

    const lastAdmitted = [...this.sessionChanges].reverse().find((entry) => entry.admitted);
    if (lastAdmitted && now - lastAdmitted.at < this.sessionPolicy.cooldownMs) {
      thisChange.admitted = false;
      this.sessionChanges.push(thisChange);
      return {
        allowed: false,
        reason:
          `session churn cooldown: the previous replacement was ${now - lastAdmitted.at}ms ago, ` +
          `minimum is ${this.sessionPolicy.cooldownMs}ms`,
        replacements: this.sessionChanges.length,
      };
    }

    thisChange.admitted = true;
    this.sessionChanges.push(thisChange);
    if (this.sessionChanges.length > this.sessionPolicy.maxPerWindow * 4) {
      this.sessionChanges.splice(0, this.sessionChanges.length - this.sessionPolicy.maxPerWindow);
    }
    return {
      allowed: true,
      reason: 'within churn budget',
      replacements: this.sessionChanges.length,
    };
  }

  /**
   * Every session replacement is a security event: the active channel is being
   * torn down by a party that merely asserted a different session id. Recorded
   * as a `system` actor (no principal is authenticated for this) through the
   * same sink the dispatcher uses.
   */
  private auditSessionAdmission(event: WakeEvent, admission: SessionAdmission): void {
    if (admission.action === 'adopt' || admission.action === 'noop') {
      return;
    }
    const replacing = this.currentWakeEvent?.browser_session_id ?? null;
    const denied = admission.action === 'reject';

    // Recorded as `cancel`/`cancelled` because `AuditAction` has no dedicated
    // member for a session takeover (audit/types.ts is owned elsewhere); the
    // reason strings below always name it as `session_replace` so the record is
    // never ambiguous once that member exists.
    this.opts.auditSink?.log({
      project: '',
      user_id: 'system',
      actor: 'system',
      role: 'system',
      action: 'cancel',
      decision: denied ? 'deny' : 'allow',
      outcome: denied ? 'n/a' : 'cancelled',
      permission_level: 'unknown',
      denial_reason: denied ? `session_replace: ${admission.reason}` : undefined,
      statement_preview:
        `session_replace: browser_session_id ${replacing ?? 'none'} -> ` +
        `${event.browser_session_id || 'unknown'}; wake_id ${event.wake_id}; ` +
        `reason ${admission.reason}`,
    });

    this.updateState(
      denied
        ? {
            session_replacement_rejections: this.state.session_replacement_rejections + 1,
            last_error: admission.reason,
          }
        : { session_replacements: this.state.session_replacements + 1 },
    );
  }

  /**
   * Fail in-flight work explicitly when the channel is being torn down.
   *
   * The old behaviour silently dropped the tracking map, so those queries ran to
   * completion against a channel that could no longer carry their responses. They
   * are now cancelled at the backend (best effort) and removed from tracking, and
   * `onInFlightDrained` lets the caller observe exactly what was lost.
   */
  private async drainInFlight(reason: DataChannelCloseReason): Promise<string[]> {
    const ids = [...this.inFlightRequests.keys()];
    for (const id of ids) {
      this.inFlightRequests.delete(id);
    }
    this.updateState({ has_in_flight: this.inFlightRequests.size > 0 });
    if (ids.length > 0) {
      try {
        await this.opts.onInFlightDrained?.(ids, reason);
      } catch (err) {
        console.error('AgentSession: in-flight drain handler failed:', err);
      }
    }
    return ids;
  }

  private async processWakeEvent(event: WakeEvent): Promise<void> {
    const admission = this.evaluateWakeEvent(event);

    if (admission.action === 'noop') {
      return;
    }

    if (admission.action === 'reject') {
      this.auditSessionAdmission(event, admission);
      console.warn(`AgentSession: ${admission.reason}`);
      return;
    }

    this.auditSessionAdmission(event, admission);

    if (this.dataChannel) {
      const drained = await this.drainInFlight('explicit_close');
      if (drained.length > 0) {
        console.warn(
          `AgentSession: ${admission.reason}; ${drained.length} in-flight request(s) were ` +
            `explicitly failed rather than orphaned: ${drained.join(', ')}`,
        );
      }
      await this.dataChannel.close('explicit_close').catch(() => {});
      this.dataChannel = undefined;
    }
    this.clearInboundGuard();

    this.currentWakeEvent = event;
    const { guard, requireMac } = this.buildInboundGuard(event);
    this.inboundGuard = guard;
    this.updateState({
      negotiated_roles: guard.getAllowedRoles(),
      envelope_mac_active: requireMac,
    });

    this.dataChannel = new DataChannel({
      cloudUrl: this.opts.machineConfig.cloud_url,
      dataChannelToken: event.data_channel_token,
      dataChannelTokenExpiresAt: event.data_channel_token_expires_at,
      agentId: this.opts.machineConfig.agent_id,
      browserSessionId: event.browser_session_id || 'unknown',
      onMessage: (msg) => this.handleInboundMessage(msg),
      onStateChange: (dataState, _reason, error) => {
        this.updateState({
          data: dataState,
          last_error: error || this.state.last_error,
          data_opened_at: dataState === 'open' ? Date.now() : this.state.data_opened_at,
        });
      },
      abortSignal: this.opts.abortSignal,
    });

    try {
      await this.dataChannel.connect();
    } catch (err: any) {
      console.error('AgentSession: failed to connect data channel:', err);
      return;
    }

    // Fast-track request if needed
    if (event.request_id) {
      const inFlightMsg = this.inFlightRequests.get(event.request_id);
      if (inFlightMsg) {
        const resumeEvent = {
          v: 1,
          id: crypto.randomUUID(),
          type: 'event' as const,
          project: inFlightMsg.project,
          user: inFlightMsg.user,
          db_alias: inFlightMsg.db_alias,
          ts: Date.now(),
          payload: {
            kind: 'resume_request' as const,
            data: {
              request_id: event.request_id,
            },
          },
        };
        this.send(resumeEvent as AgentMessage).catch((sendErr) => {
          console.error('Failed to send resume_request event:', sendErr);
        });
      }
    }
  }

  private updateState(diff: Partial<AgentSessionState>) {
    this.state = { ...this.state, ...diff };
    if (this.activeStateChangeHandler) {
      this.activeStateChangeHandler(this.state);
    }
  }
}

/**
 * Roles the connector will accept for this session: the roles the relay
 * negotiated, minus anything above the local ceiling, minus anything that is not
 * a legal role. Returned in the canonical `ROLES` order.
 *
 * An absent, empty, or wholly invalid `allowed_roles` yields an empty set, which
 * the guard treats as "no role is permitted" — there is no fallback to "all
 * roles", because that fallback is the C-04 vulnerability.
 */
export function intersectNegotiatedRoles(
  negotiated: readonly unknown[] | undefined,
  ceiling: Role = ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT,
): Role[] {
  if (!Array.isArray(negotiated)) {
    return [];
  }
  const permitted = new Set(negotiated.filter(isRole));
  const ceilingRole = isRole(ceiling) ? ceiling : ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT;
  // ROLES is ordered most- to least-privileged, so a role is within the ceiling
  // when it sits at or below the ceiling's rank.
  const ceilingRank = ROLES.indexOf(ceilingRole);
  return ROLES.filter((role) => permitted.has(role) && ROLES.indexOf(role) >= ceilingRank);
}
