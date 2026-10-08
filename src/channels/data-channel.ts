/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import WebSocket from 'ws';
import { URL } from 'url';
import * as crypto from 'crypto';
import { AgentMessage } from '../protocol/envelope';
import {
  deserialize,
  serializeToBytes,
  deserializeFromBytes,
  ProtocolError,
} from '../protocol/serialize';
import { validateMessage } from '../protocol/validate';
import { DataChannelState, DataChannelCloseReason, MessageHandler } from './types';
import { DEFAULTS, LIMITS } from '../protocol/constants';
import { formatTokenExpiredMessage, toWebSocketUrl } from './reconnect';

/**
 * Inbound frame ceiling enforced by the transport, in bytes.
 *
 * `ws` checks this against the *decompressed* message length as well as the
 * frame length, so a compressed payload cannot inflate past it.
 */
export const MAX_INBOUND_FRAME_BYTES = LIMITS.MAX_PAYLOAD_BYTES;

/** RFC 6455 close code for a message that exceeded the negotiated limit. */
export const CLOSE_MESSAGE_TOO_BIG = 1009;

/**
 * Safety margin applied to `data_channel_token_expires_at` before connecting.
 *
 * The token is spent on a TLS handshake plus a round trip; refusing slightly
 * early is cheaper than a data channel that 401s mid-session.
 */
export const TOKEN_EXPIRY_SAFETY_MARGIN_MS = 5_000;

/**
 * Watermark above which the socket is considered back-pressured, in bytes.
 *
 * At or below this the relay is keeping up and the producer may keep sending.
 * Above it the producer waits instead of pushing more bytes into a buffer that
 * is already draining slower than it is fed.
 */
export const SEND_BUFFER_HIGH_WATER_MARK_BYTES = 1024 * 1024;

/**
 * Hard ceiling on unsent bytes, in bytes.
 *
 * Above the watermark a send is deferred, never rejected — but a producer that
 * never gets a drain signal (a relay that has stopped reading) must not be able
 * to grow the daemon's heap without limit. Past this the send fails closed with
 * a `payload_invalid` ProtocolError, which the caller's error path reports
 * terminally instead of silently truncating a stream.
 */
export const SEND_BUFFER_HARD_CAP_BYTES = LIMITS.MAX_PAYLOAD_BYTES;

/** How often {@link DataChannel.waitForDrain} re-checks the socket while waiting. */
const DRAIN_POLL_INTERVAL_MS = 5;

/** Current send-buffer occupancy. Diagnostics only. */
export interface DataChannelSendStats {
  /** Bytes the socket has accepted but not yet written. */
  buffered: number;
  /** Bytes handed to `ws.send` whose callback has not fired yet. */
  pending: number;
  /** Watermark at or below which the producer is unblocked. */
  high_water_mark: number;
  /** Ceiling past which a send is refused. */
  hard_cap: number;
}

export interface DataChannelOptions {
  /** Cloud URL, e.g. "wss://api.schemaweaver.dev". Plaintext schemes are refused. */
  cloudUrl: string;
  /** Short-lived data channel token from wake event. */
  dataChannelToken: string;
  /**
   * Epoch ms at which `dataChannelToken` expires (from the wake event).
   *
   * Required: the client is the only party that can check it before the
   * handshake, so an absent value is treated as a malformed credential.
   */
  dataChannelTokenExpiresAt: number;
  /** Agent ID for routing. */
  agentId: string;
  /** Browser session ID this channel serves. */
  browserSessionId: string;
  /** Incoming message handler. */
  onMessage: MessageHandler;
  /** Called when channel state changes. */
  onStateChange?: (
    state: DataChannelState,
    reason?: DataChannelCloseReason,
    error?: string,
  ) => void;
  /** Idle timeout in ms. Default 60_000. Set to 0 to disable. */
  idleTimeoutMs?: number;
  /** Optional: abort signal. */
  abortSignal?: AbortSignal;
  /**
   * Allow a cleartext `ws:`/`http:` target. Only wire this to an explicit,
   * non-persisted operator flag (`--insecure-transport`).
   */
  allowInsecureTransport?: boolean;
}

export class DataChannel {
  private state: DataChannelState = 'closed';
  private ws?: WebSocket;
  private idleTimer?: NodeJS.Timeout;
  private closeReason?: DataChannelCloseReason;
  private transportError?: string;
  private readonly opts: DataChannelOptions;

  /** Bytes handed to `ws.send` whose completion callback has not fired yet. */
  private pendingSendBytes = 0;
  /** Producers blocked in {@link DataChannel.waitForDrain}. */
  private readonly drainWaiters = new Set<() => void>();
  private drainPollTimer?: NodeJS.Timeout;
  /**
   * Safety net for a close that the peer never answers. Held so it can be
   * cancelled the moment the close settles: a timer left armed here outlives
   * the close it belongs to and would tear down the *next* connection opened on
   * this instance (token rotation reconnects on the same object), and it also
   * holds the process open for its whole backoff window.
   */
  private closeSafetyTimer?: NodeJS.Timeout;

  constructor(opts: DataChannelOptions) {
    this.opts = opts;

    if (this.opts.abortSignal) {
      if (this.opts.abortSignal.aborted) {
        this.forceClose('shutdown');
      } else {
        this.opts.abortSignal.addEventListener('abort', () => {
          this.forceClose('shutdown');
        });
      }
    }
  }

  /** Open the WSS connection. Resolves when handshake completes. */
  async connect(): Promise<void> {
    if (this.state !== 'closed' && this.state !== 'error') {
      return;
    }

    this.closeReason = undefined;
    this.transportError = undefined;

    // Fail closed before anything is sent: an expired or unusable short-lived
    // token must never reach the wire.
    this.assertTokenUsable();

    this.setState('connecting');

    // Audit H-03: the configured scheme is validated here, once, before the
    // Authorization header exists. `https:` → `wss:` is the only mapping
    // performed; `http:`/`ws:` are refused rather than downgraded.
    let url: URL;
    try {
      url = toWebSocketUrl(this.opts.cloudUrl, {
        allowInsecure: this.opts.allowInsecureTransport === true,
        context: 'data channel',
      });
    } catch (err) {
      // Terminal: a cleartext target is a configuration fault, not a transient
      // network condition. Report it and leave the channel closed.
      const message = err instanceof Error ? err.message : String(err);
      console.error(`DataChannel: ${message}`);
      this.setState('error', 'fatal_error', message);
      throw err;
    }
    url.pathname = `${url.pathname.replace(/\/+$/, '')}/api/agent/data`;

    // Token is sent exclusively via the Authorization header (not in query
    // params) to avoid leaking short-lived tokens in proxy/CDN access logs.
    url.searchParams.set('agent_id', this.opts.agentId);
    url.searchParams.set('session', this.opts.browserSessionId);

    return new Promise<void>((resolve, reject) => {
      let resolved = false;

      const onOpen = () => {
        if (!resolved) {
          resolved = true;
          this.setState('open');
          this.pingActivity();
          resolve();
        }
      };

      const onError = (err: Error) => {
        if (!resolved) {
          resolved = true;
          this.setState('error', 'network_error', err.message);
          reject(err);
        }
      };

      try {
        this.ws = new WebSocket(url.toString(), {
          headers: {
            Authorization: `Bearer ${this.opts.dataChannelToken}`,
            'X-Agent-Id': this.opts.agentId,
          },
          handshakeTimeout: 10_000,
          // Audit H-08: the transport, not the application, owns the inbound
          // size bound. `ws` rejects as soon as the declared frame length
          // passes maxPayload and closes with 1009, so an oversized frame never
          // reaches deserialize().
          maxPayload: MAX_INBOUND_FRAME_BYTES,
          // Audit H-08: compression is not enabled. The agent's payload mix is
          // small JSON envelopes (a stream chunk is a handful of rows), so deflate
          // buys little bandwidth for real CPU on every frame, and declining the
          // extension removes RSV1 parsing and inflate from the trusted path
          // entirely. Were it ever re-enabled, note that `maxPayload` is also
          // applied to the *decompressed* length, so the bound would still hold.
          perMessageDeflate: false,
        });

        this.ws.on('open', onOpen);

        this.ws.on('error', (err) => {
          if (!resolved) {
            onError(err);
            return;
          }
          // Post-handshake transport failure: record the cause so the close
          // handler can report something actionable.
          const described = describeTransportError(err);
          this.closeReason = described.reason;
          this.transportError = described.message;
        });

        this.ws.on('message', (data, isBinary) => {
          this.pingActivity();
          try {
            let msg: AgentMessage;
            if (isBinary) {
              let uint8: Uint8Array;
              if (Buffer.isBuffer(data)) {
                uint8 = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
              } else if (data instanceof ArrayBuffer) {
                uint8 = new Uint8Array(data);
              } else if (Array.isArray(data)) {
                const concatenated = Buffer.concat(data);
                uint8 = new Uint8Array(
                  concatenated.buffer,
                  concatenated.byteOffset,
                  concatenated.byteLength,
                );
              } else {
                throw new Error('Unsupported binary data type');
              }
              msg = deserializeFromBytes(uint8);
            } else {
              msg = deserialize(data.toString());
            }

            try {
              validateMessage(msg);
            } catch (validationError: any) {
              const errResponse = {
                v: 1,
                id: msg?.id || crypto.randomUUID(),
                type: 'error',
                project: msg?.project || 'unknown',
                user: msg?.user || { id: 'unknown', role: 'viewer' as const },
                db_alias: msg?.db_alias || 'unknown',
                ts: Date.now(),
                payload: {
                  request_id: msg?.id || 'unknown',
                  code: 'invalid_message' as const,
                  message: validationError.message || 'Validation failed',
                  retryable: false,
                  fatal: true,
                },
              };
              this.send(errResponse as AgentMessage).catch(() => {});
              this.forceClose('protocol_error', validationError.message);
              return;
            }

            if (this.opts.onMessage) {
              const p = this.opts.onMessage(msg);
              if (p instanceof Promise) {
                p.catch((err) => {
                  console.error('DataChannel MessageHandler failed:', err);
                });
              }
            }
          } catch (err: any) {
            this.forceClose('protocol_error', err.message);
          }
        });

        this.ws.on('close', (code, reason) => {
          if (this.idleTimer) {
            clearTimeout(this.idleTimer);
            this.idleTimer = undefined;
          }

          if (this.state === 'error') {
            return;
          }

          let closeReason: DataChannelCloseReason = 'remote_close';
          if (this.closeReason) {
            closeReason = this.closeReason;
          } else if (code === 1000 || code === 1001) {
            closeReason = 'remote_close';
          } else if (code === 1006) {
            closeReason = 'network_error';
          } else if (code === 1008) {
            closeReason = 'auth_failed';
          } else if (code === 1009) {
            closeReason = 'protocol_error';
          } else if (code === 1011) {
            closeReason = 'fatal_error';
          }

          const errorMsg =
            this.transportError || (reason && reason.length > 0 ? reason.toString() : undefined);
          this.transportError = undefined;
          this.setState('closed', closeReason, errorMsg);
        });
      } catch (err: any) {
        onError(err);
      }
    });
  }

  /**
   * Refuse to authenticate with an unusable data channel token (audit H-12).
   *
   * Runs before the handshake so an expired token is never presented, and
   * reports through onStateChange so the operator sees why the channel refused.
   */
  private assertTokenUsable(): void {
    const expiresAt = this.opts.dataChannelTokenExpiresAt;
    const reason: DataChannelCloseReason = 'auth_failed';

    if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= 0) {
      const message =
        'Data channel refused to connect: data_channel_token_expires_at is missing or not a ' +
        'timestamp. The cloud wake event is malformed.';
      this.setState('error', reason, message);
      throw new ProtocolError('invalid_message', message);
    }

    if (expiresAt - TOKEN_EXPIRY_SAFETY_MARGIN_MS <= Date.now()) {
      const message = formatTokenExpiredMessage(
        expiresAt,
        TOKEN_EXPIRY_SAFETY_MARGIN_MS,
        'Data channel',
      );
      this.setState('error', reason, message);
      throw new ProtocolError('token_expired', message);
    }
  }

  /**
   * Send a message, applying backpressure instead of rejecting a busy socket.
   *
   * Above {@link SEND_BUFFER_HIGH_WATER_MARK_BYTES} the send waits for the
   * socket to drain. It used to throw `payload_invalid` here, which aborted the
   * producer mid-stream and left the browser waiting for a `stream_end` that
   * never came (audit H-10). A slow relay is a condition to wait out, not an
   * error. Past {@link SEND_BUFFER_HARD_CAP_BYTES} the wait has demonstrably not
   * been satisfied and the send fails closed so unbounded growth stays impossible.
   *
   * Concurrent callers are serialised through the gate: the drain condition is
   * re-tested after every wait, and the check and the hand-off to `ws.send` sit
   * in one synchronous step. Without that, N producers resuming from the same
   * microtask batch would all observe an empty buffer and push N messages into
   * the socket anyway — the gate would throttle nothing.
   *
   * Throws `channel_closed` if the channel is not open, or if it closes while
   * this call is waiting to drain.
   */
  async send(msg: AgentMessage): Promise<void> {
    if (this.state !== 'open' || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new ProtocolError('channel_closed', 'Data channel not open');
    }

    const bytes = serializeToBytes(msg);

    for (;;) {
      if (this.sendBufferExceeded(bytes.byteLength)) {
        throw new ProtocolError(
          'payload_invalid',
          `Send buffer exceeded its ${SEND_BUFFER_HARD_CAP_BYTES} byte cap without draining; ` +
            `refusing to queue more. The relay is not reading.`,
        );
      }
      if (!this.drainPending()) {
        break;
      }
      await this.waitForDrain();
      if (this.state !== 'open' || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
        throw new ProtocolError('channel_closed', 'Data channel closed while waiting to drain');
      }
    }

    this.pingActivity();

    this.pendingSendBytes += bytes.byteLength;
    try {
      await new Promise<void>((resolve, reject) => {
        this.ws?.send(bytes, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });
    } finally {
      this.pendingSendBytes -= bytes.byteLength;
      this.notifyDrainWaiters();
    }
  }

  /**
   * Resolve once the socket has caught up: `bufferedAmount` is at or below
   * {@link SEND_BUFFER_HIGH_WATER_MARK_BYTES} and no earlier send is still in
   * flight. Returns immediately when that is already true, and also when the
   * channel is not open — a socket that will never drain again must not strand a
   * producer, and the caller still observes the closed channel on its next send.
   *
   * This is the hook to hand to a cursor fetch loop so the producer stops asking
   * PostgreSQL for more rows while the relay is behind:
   *
   * ```ts
   * await queryRunner.runStreaming(payload, { waitForDrain: () => channel.waitForDrain(), ... });
   * ```
   *
   * Every waiter is released when the channel leaves `open`, so a stalled relay
   * is bounded by the idle timeout rather than by this promise.
   */
  waitForDrain(): Promise<void> {
    if (!this.drainPending()) {
      return Promise.resolve();
    }

    return new Promise<void>((resolve) => {
      this.drainWaiters.add(resolve);
      this.startDrainPoll();
    });
  }

  /** Current send-buffer occupancy against the watermark and hard cap. */
  getSendBufferStats(): DataChannelSendStats {
    return {
      buffered: this.bufferedBytes(),
      pending: this.pendingSendBytes,
      high_water_mark: SEND_BUFFER_HIGH_WATER_MARK_BYTES,
      hard_cap: SEND_BUFFER_HARD_CAP_BYTES,
    };
  }

  private bufferedBytes(): number {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return 0;
    }
    return ws.bufferedAmount;
  }

  /**
   * True while the socket is behind. `pendingSendBytes` is included because a
   * `ws.send` callback has not yet fired for it, so the bytes are still in
   * flight and the producer should not run ahead of them.
   */
  private drainPending(): boolean {
    if (this.state !== 'open') {
      return false;
    }
    return this.pendingSendBytes > 0 || this.bufferedBytes() > SEND_BUFFER_HIGH_WATER_MARK_BYTES;
  }

  /** True when queueing `incomingBytes` more would reach the cap `send` refuses at. */
  private sendBufferExceeded(incomingBytes: number): boolean {
    return (
      this.pendingSendBytes + this.bufferedBytes() + incomingBytes >= SEND_BUFFER_HARD_CAP_BYTES
    );
  }

  /**
   * Release every blocked producer, then stop polling. A single shared interval
   * serves all waiters so N blocked producers cost one timer, not N.
   */
  private notifyDrainWaiters(): void {
    if (this.drainWaiters.size === 0) {
      return;
    }
    if (this.drainPending()) {
      return;
    }
    const waiters = [...this.drainWaiters];
    this.drainWaiters.clear();
    this.stopDrainPoll();
    for (const resolve of waiters) {
      resolve();
    }
  }

  private startDrainPoll(): void {
    if (this.drainPollTimer || this.drainWaiters.size === 0) {
      return;
    }
    this.drainPollTimer = setInterval(() => {
      this.notifyDrainWaiters();
      if (this.drainWaiters.size === 0) {
        this.stopDrainPoll();
      }
    }, DRAIN_POLL_INTERVAL_MS);
    // Never hold the process open for a blocked producer.
    this.drainPollTimer.unref?.();
  }

  private stopDrainPoll(): void {
    if (!this.drainPollTimer) {
      return;
    }
    clearInterval(this.drainPollTimer);
    this.drainPollTimer = undefined;
  }

  /**
   * Release every blocked producer unconditionally: the channel is leaving
   * `open`, so no amount of draining can satisfy them.
   */
  private releaseDrainWaiters(): void {
    this.stopDrainPoll();
    if (this.drainWaiters.size === 0) {
      return;
    }
    const waiters = [...this.drainWaiters];
    this.drainWaiters.clear();
    for (const resolve of waiters) {
      resolve();
    }
  }

  /** Graceful close. */
  async close(reason: DataChannelCloseReason = 'explicit_close'): Promise<void> {
    if (this.state === 'closed' || this.state === 'closing') {
      return;
    }
    this.setState('closing');
    this.closeReason = reason;

    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return new Promise<void>((resolve) => {
        this.ws?.close(1000, reason);

        let settled = false;
        const settle = () => {
          if (settled) {
            return;
          }
          settled = true;
          clearInterval(checkClosed);
          this.cancelCloseSafety();
          resolve();
        };

        const checkClosed = setInterval(() => {
          if (this.state === 'closed') {
            settle();
          }
        }, 10);

        // Safety timeout. Bound to this close: it is cancelled by `settle()` so
        // it can never fire against a connection opened after this one closed.
        this.closeSafetyTimer = setTimeout(() => {
          this.closeSafetyTimer = undefined;
          if (this.state !== 'closed') {
            this.forceClose(reason);
          }
          settle();
        }, 1000);
        this.closeSafetyTimer.unref?.();
      });
    } else {
      this.setState('closed', reason);
    }
  }

  /** Cancel the pending close safety net, if any. */
  private cancelCloseSafety(): void {
    if (this.closeSafetyTimer) {
      clearTimeout(this.closeSafetyTimer);
      this.closeSafetyTimer = undefined;
    }
  }

  /** Force close (e.g. on fatal error). */
  forceClose(reason: DataChannelCloseReason, error?: string): void {
    this.cancelCloseSafety();
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    this.closeReason = reason;
    if (this.ws) {
      try {
        this.ws.terminate();
      } catch (err) {
        // ignore
      }
    }
    this.setState('closed', reason, error);
  }

  /** Current state. */
  getState(): DataChannelState {
    return this.state;
  }

  /** Reset idle timer (called when activity occurs). */
  private pingActivity(): void {
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    const timeout = this.opts.idleTimeoutMs ?? DEFAULTS.IDLE_WSS_TIMEOUT_MS;
    if (timeout > 0) {
      this.idleTimer = setTimeout(() => {
        this.close('idle_timeout').catch((err) => {
          console.error('Error during idle timeout close:', err);
        });
      }, timeout);
    }
  }

  private setState(state: DataChannelState, reason?: DataChannelCloseReason, error?: string) {
    if (this.state !== state) {
      const wasOpen = this.state === 'open';
      this.state = state;
      if (wasOpen && state !== 'open') {
        // A socket that is closing will never drain, so every producer parked
        // in waitForDrain() is released and sees the closed channel on its own
        // next send.
        this.releaseDrainWaiters();
      }
      if (this.opts.onStateChange) {
        this.opts.onStateChange(state, reason, error);
      }
    }
  }
}

/**
 * Map a `ws` transport error onto a close reason plus an operator-facing
 * message. `ws` reports an oversized frame as
 * `WS_ERR_UNSUPPORTED_MESSAGE_LENGTH` and closes with 1009.
 */
function describeTransportError(err: unknown): {
  reason: DataChannelCloseReason;
  message: string;
} {
  const code = (err as { code?: string } | undefined)?.code;
  const detail = err instanceof Error ? err.message : String(err);

  if (code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH') {
    return {
      reason: 'protocol_error',
      message:
        `Inbound frame exceeded the ${MAX_INBOUND_FRAME_BYTES} byte limit and was rejected by ` +
        `the transport (close ${CLOSE_MESSAGE_TOO_BIG}); it was never parsed. ${detail}`,
    };
  }

  return { reason: 'network_error', message: detail };
}
