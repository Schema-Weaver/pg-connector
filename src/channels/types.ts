import { AgentMessage, Role } from '../protocol/envelope';

/**
 * State of the wake channel (SSE).
 * - disconnected: not connected, possibly mid-backoff
 * - connecting: HTTPS request in flight, awaiting response
 * - connected: SSE stream open, receiving events
 * - error: connection failed, will retry
 */
export type WakeChannelState = 'disconnected' | 'connecting' | 'connected' | 'error';

/**
 * Per-session envelope authentication policy.
 *
 * Supplied by the daemon from machine config; every field is optional and every
 * default lives in `src/protocol/constants.ts` so the policy has exactly one
 * definition. Nothing here can turn the negotiated-role check or the replay
 * check off.
 */
export interface EnvelopeAuthPolicy {
  /**
   * Reject inbound envelopes that carry no per-session MAC. Defaults to
   * ENVELOPE_MAC_REQUIRED_DEFAULT (true).
   */
  requireMac?: boolean;
  /**
   * Local ceiling: the highest role the relay may negotiate for this session,
   * regardless of what it asks for. Defaults to
   * ENVELOPE_MAX_NEGOTIABLE_ROLE_DEFAULT.
   */
  maxNegotiableRole?: Role;
}

/**
 * State of the data channel (WSS).
 * - closed: not open (either never opened, or closed after idle/disconnect)
 * - connecting: WSS handshake in flight
 * - open: ready to send/receive messages
 * - closing: close handshake in flight
 * - error: connection failed
 */
export type DataChannelState = 'closed' | 'connecting' | 'open' | 'closing' | 'error';

/**
 * Reason the data channel closed. Used for reconnect decisions and audit.
 */
export type DataChannelCloseReason =
  | 'idle_timeout'           // 60s no activity
  | 'explicit_close'         // we called close()
  | 'remote_close'           // cloud/relay closed
  | 'protocol_error'         // invalid frame received
  | 'network_error'          // underlying socket died
  | 'auth_failed'            // token rejected
  | 'fatal_error'            // something unrecoverable
  | 'shutdown';              // agent is shutting down

/**
 * Wake event pushed by cloud via SSE.
 * Tells the agent: "open the data channel, browser has work for you."
 */
export interface WakeEvent {
  /** Unique ID for this wake (for dedup if SSE redelivers). */
  wake_id: string;
  /** Why cloud is waking the agent. */
  reason: 'browser_request' | 'ping' | 'migration_queued' | 'config_sync';
  /** Browser session ID that wants to talk (for routing). */
  browser_session_id?: string;
  /** Optional request_id that triggered the wake (for fast-track). */
  request_id?: string;
  /** When cloud queued this wake (epoch ms). */
  queued_at: number;
  /** Short-lived token to use when opening the data channel. */
  data_channel_token: string;
  /** When data_channel_token expires (epoch ms). */
  data_channel_token_expires_at: number;
  /**
   * Roles the cloud agreed this session may act as. The connector intersects
   * this with its own local ceiling and rejects every inbound envelope whose
   * `user.role` is not in the result, so the relay cannot mint a role after the
   * fact.
   *
   * Omitting this field is not a way to get "any role": an absent or empty list
   * yields an empty permitted set and every envelope is rejected.
   */
  allowed_roles?: Role[];
}

/**
 * Callback signature for incoming messages on the data channel.
 * Part 5 will register a handler that dispatches to execution engine.
 */
export type MessageHandler = (msg: AgentMessage) => Promise<void> | void;

/**
 * Callback for state changes (used by agent-session to update browser UI).
 */
export type StateChangeHandler = (state: AgentSessionState) => void;

export interface AgentSessionState {
  wake: WakeChannelState;
  data: DataChannelState;
  /** True if at least one message is in-flight (waiting for response). */
  has_in_flight: boolean;
  /** Number of reconnect attempts since last successful connect. */
  reconnect_attempts: number;
  /** Last error message (if any). */
  last_error?: string;
  /** Epoch ms of last successful wake channel connect. */
  wake_connected_at?: number;
  /** Epoch ms of last successful data channel open. */
  data_opened_at?: number;
  /** Roles negotiated for the current data-channel session. Empty = none permitted. */
  negotiated_roles: Role[];
  /** True once a per-session envelope MAC key has been derived for the open channel. */
  envelope_mac_active: boolean;
  /** Inbound envelopes dropped by envelope authentication since start. */
  envelope_authn_failures: number;
  /** Epoch ms of the last inbound envelope dropped by envelope authentication. */
  last_envelope_authn_failure_at?: number;
  /**
   * Wake events that were permitted to take over the data channel (audit M-15).
   * Every increment is also written to the audit sink as a security event.
   */
  session_replacements: number;
  /** Wake events refused because they named a different browser session. */
  session_replacement_rejections: number;
}
