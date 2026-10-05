import { AgentMessage } from '../protocol/envelope';

/**
 * State of the wake channel (SSE).
 * - disconnected: not connected, possibly mid-backoff
 * - connecting: HTTPS request in flight, awaiting response
 * - connected: SSE stream open, receiving events
 * - error: connection failed, will retry
 */
export type WakeChannelState = 'disconnected' | 'connecting' | 'connected' | 'error';

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
}
