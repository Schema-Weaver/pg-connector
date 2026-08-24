/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import WebSocket from 'ws';
import { URL } from 'url';
import * as crypto from 'crypto';
import { AgentMessage } from '../protocol/envelope';
import { deserialize, serializeToBytes, deserializeFromBytes, ProtocolError } from '../protocol/serialize';
import { validateMessage } from '../protocol/validate';
import { DataChannelState, DataChannelCloseReason, MessageHandler } from './types';
import { DEFAULTS } from '../protocol/constants';

export interface DataChannelOptions {
  /** Cloud URL, e.g. "wss://agent.schema-weaver.dev". */
  cloudUrl: string;
  /** Short-lived data channel token from wake event. */
  dataChannelToken: string;
  /** Agent ID for routing. */
  agentId: string;
  /** Browser session ID this channel serves. */
  browserSessionId: string;
  /** Incoming message handler. */
  onMessage: MessageHandler;
  /** Called when channel state changes. */
  onStateChange?: (state: DataChannelState, reason?: DataChannelCloseReason, error?: string) => void;
  /** Idle timeout in ms. Default 60_000. Set to 0 to disable. */
  idleTimeoutMs?: number;
  /** Optional: abort signal. */
  abortSignal?: AbortSignal;
}

export class DataChannel {
  private state: DataChannelState = 'closed';
  private ws?: WebSocket;
  private idleTimer?: NodeJS.Timeout;
  private closeReason?: DataChannelCloseReason;
  private readonly opts: DataChannelOptions;

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
    this.setState('connecting');

    const urlStr = this.opts.cloudUrl;
    let targetUrl = urlStr;
    if (targetUrl.startsWith('https://')) {
      targetUrl = 'wss://' + targetUrl.substring(8);
    } else if (targetUrl.startsWith('http://')) {
      targetUrl = 'ws://' + targetUrl.substring(7);
    }
    targetUrl = targetUrl.replace(/\/+$/, '') + '/api/agent/data';

    const url = new URL(targetUrl);
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
            'Authorization': `Bearer ${this.opts.dataChannelToken}`,
            'X-Agent-Id': this.opts.agentId,
          },
          handshakeTimeout: 10_000,
          perMessageDeflate: true,
        });

        this.ws.on('open', onOpen);
        
        this.ws.on('error', (err) => {
          onError(err);
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
                uint8 = new Uint8Array(concatenated.buffer, concatenated.byteOffset, concatenated.byteLength);
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
                }
              };
              this.send(errResponse as AgentMessage).catch(() => {});
              this.forceClose('protocol_error', validationError.message);
              return;
            }

            if (this.opts.onMessage) {
              const p = this.opts.onMessage(msg);
              if (p instanceof Promise) {
                p.catch(err => {
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
          } else if (code === 1011) {
            closeReason = 'fatal_error';
          }

          const errorMsg = reason ? reason.toString() : undefined;
          this.setState('closed', closeReason, errorMsg);
        });

      } catch (err: any) {
        onError(err);
      }
    });
  }

  /** Send a message. Throws if state != 'open'. */
  async send(msg: AgentMessage): Promise<void> {
    if (this.state !== 'open' || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new ProtocolError('channel_closed', 'Data channel not open');
    }

    // Backpressure check: throw if bufferedAmount > 1MB
    if (this.ws.bufferedAmount > 1024 * 1024) {
      throw new ProtocolError('payload_invalid', 'Send buffer full');
    }

    this.pingActivity();

    const bytes = serializeToBytes(msg);
    return new Promise<void>((resolve, reject) => {
      this.ws?.send(bytes, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
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
        
        const checkClosed = setInterval(() => {
          if (this.state === 'closed') {
            clearInterval(checkClosed);
            resolve();
          }
        }, 10);

        // Safety timeout
        setTimeout(() => {
          clearInterval(checkClosed);
          if (this.state !== 'closed') {
            this.forceClose(reason);
          }
          resolve();
        }, 1000);
      });
    } else {
      this.setState('closed', reason);
    }
  }

  /** Force close (e.g. on fatal error). */
  forceClose(reason: DataChannelCloseReason, error?: string): void {
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
        this.close('idle_timeout').catch(err => {
          console.error('Error during idle timeout close:', err);
        });
      }, timeout);
    }
  }

  private setState(state: DataChannelState, reason?: DataChannelCloseReason, error?: string) {
    if (this.state !== state) {
      this.state = state;
      if (this.opts.onStateChange) {
        this.opts.onStateChange(state, reason, error);
      }
    }
  }
}
