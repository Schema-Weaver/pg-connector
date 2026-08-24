/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, prefer-const */
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { WakeChannelState, WakeEvent } from './types';
import { Backoff } from './reconnect';
import { DEFAULTS } from '../protocol/constants';

export interface WakeChannelOptions {
  /** Cloud URL, e.g. "wss://agent.schema-weaver.dev" — note: WSS prefix converted to HTTPS for SSE. */
  cloudUrl: string;
  /** Agent token (sent as Bearer header). */
  token: string;
  /** Agent ID (sent as X-Agent-Id header for routing). */
  agentId: string;
  /** Optional: returns configured database list from databases.config.json. */
  getDatabases?: () => Array<{ db_alias: string; database: string }>;
  /** Called when a wake event arrives. */
  onWake: (event: WakeEvent) => void;
  /** Called when channel state changes. */
  onStateChange?: (state: WakeChannelState, error?: string) => void;
  /** Optional: custom backoff schedule (for tests). */
  backoffSchedule?: readonly number[];
  /** Optional: disable keepalive (for tests). Default true. */
  enableKeepalive?: boolean;
  /** Optional: abort signal for clean shutdown. */
  abortSignal?: AbortSignal;
}

export class WakeChannel {
  private state: WakeChannelState = 'disconnected';
  private backoff: Backoff;
  private currentReq?: http.ClientRequest;
  private shutdownRequested = false;
  private readonly opts: WakeChannelOptions;
  private keepaliveTimer?: NodeJS.Timeout;
  private lastEventTime = 0;
  
  private sleepTimer?: NodeJS.Timeout;
  private sleepReject?: () => void;
  private loopPromise?: Promise<void>;
  private firstAttemptResolver?: () => void;
  private currentReject?: (err: any) => void;

  constructor(opts: WakeChannelOptions) {
    this.opts = opts;
    this.backoff = new Backoff(opts.backoffSchedule);
    
    if (this.opts.abortSignal) {
      if (this.opts.abortSignal.aborted) {
        this.stop();
      } else {
        this.opts.abortSignal.addEventListener('abort', () => {
          this.stop().catch(err => {
            console.error('Error stopping WakeChannel via abortSignal:', err);
          });
        });
      }
    }
  }

  /** Start the wake channel. Returns immediately; runs in background. */
  async start(): Promise<void> {
    this.shutdownRequested = false;
    this.backoff.reset();
    
    const firstAttemptPromise = new Promise<void>(resolve => {
      this.firstAttemptResolver = resolve;
    });

    // Start background loop
    this.loopPromise = this.runLoop().catch(err => {
      console.error('WakeChannel: unhandled loop error', err);
    });

    // Start keepalive checker if enabled
    if (this.opts.enableKeepalive !== false) {
      if (this.keepaliveTimer) {
        clearInterval(this.keepaliveTimer);
      }
      this.keepaliveTimer = setInterval(() => {
        if (this.state === 'connected' && Date.now() - this.lastEventTime > DEFAULTS.WAKE_KEEPALIVE_MS) {
          console.warn('WakeChannel: keepalive timeout, no events in last 5 minutes. Reconnecting...');
          this.abortCurrentRequest();
        }
      }, 30000); // check every 30s
    }

    return firstAttemptPromise;
  }

  /** Graceful shutdown. Waits for current request to abort. */
  async stop(): Promise<void> {
    this.shutdownRequested = true;
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = undefined;
    }
    
    if (this.sleepReject) {
      this.sleepReject();
      this.sleepReject = undefined;
    }
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = undefined;
    }

    this.abortCurrentRequest();
    this.setState('disconnected');

    if (this.loopPromise) {
      await this.loopPromise;
    }
  }

  /** Current state. */
  getState(): WakeChannelState {
    return this.state;
  }

  /** Get current backoff reconnect attempts. */
  getReconnectAttempts(): number {
    return this.backoff.attempts;
  }

  /** Force a reconnect (e.g. after token rotation). */
  async reconnect(): Promise<void> {
    this.backoff.reset();
    if (this.sleepReject) {
      this.sleepReject();
      this.sleepReject = undefined;
    }
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = undefined;
    }
    this.abortCurrentRequest();
  }

  private abortCurrentRequest() {
    if (this.currentReject) {
      try {
        this.currentReject(new Error('Request aborted'));
      } catch {
        // ignore
      }
      this.currentReject = undefined;
    }
    if (this.currentReq) {
      try {
        this.currentReq.destroy();
      } catch (err) {
        // ignore
      }
      this.currentReq = undefined;
    }
  }

  private setState(state: WakeChannelState, error?: string) {
    if (this.state !== state) {
      this.state = state;
      if (this.opts.onStateChange) {
        this.opts.onStateChange(state, error);
      }
      
      if (state === 'connected' || state === 'error') {
        if (this.firstAttemptResolver) {
          this.firstAttemptResolver();
          this.firstAttemptResolver = undefined;
        }
      }
    }
  }

  private async sleepNextJittered(delay: number): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sleepReject = reject;
      this.sleepTimer = setTimeout(() => {
        this.sleepReject = undefined;
        this.sleepTimer = undefined;
        resolve();
      }, delay);
    });
  }

  private async runLoop() {
    while (!this.shutdownRequested) {
      try {
        await this.connectOnce();
      } catch (err: any) {
        if (this.shutdownRequested) {
          break;
        }

        const isAuthError = err.status === 401 || err.status === 403;
        if (isAuthError) {
          this.setState('error', err.message || 'auth_failed: token rejected by cloud');
          break; // Fatal error, do not retry
        }

        this.setState('error', err.message || 'connection failed');
        
        let delay = this.backoff.next();
        if (err.status === 429 && err.retryAfterMs && err.retryAfterMs > 0) {
          delay = err.retryAfterMs;
        }

        try {
          await this.sleepNextJittered(delay);
        } catch (e) {
          // Sleep interrupted by reconnect/stop
        }
      }
    }
  }

  private connectOnce(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.shutdownRequested) {
        return resolve();
      }

      this.setState('connecting');

      const urlStr = this.opts.cloudUrl;
      let targetUrl = urlStr;
      if (targetUrl.startsWith('wss://')) {
        targetUrl = 'https://' + targetUrl.substring(6);
      } else if (targetUrl.startsWith('ws://')) {
        targetUrl = 'http://' + targetUrl.substring(5);
      }
      targetUrl = targetUrl.replace(/\/+$/, '') + '/api/agent/wake';

      let url: URL;
      try {
        url = new URL(targetUrl);
      } catch (err) {
        reject(new Error(`Invalid URL: ${targetUrl}`));
        return;
      }

      const isHttps = url.protocol === 'https:';
      const requestLib = isHttps ? https : http;

      const headers: Record<string, string> = {
        'Authorization': `Bearer ${this.opts.token}`,
        'X-Agent-Id': this.opts.agentId,
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      };

      if (this.opts.getDatabases) {
        try {
          const dbs = this.opts.getDatabases();
          if (Array.isArray(dbs) && dbs.length > 0) {
            headers['X-Agent-Databases'] = JSON.stringify(dbs);
          }
        } catch (_) {}
      }

      const reqOpts: http.RequestOptions = {
        method: 'GET',
        headers,
      };

      let aborted = false;
      let req: http.ClientRequest;

      try {
        req = requestLib.request(targetUrl, reqOpts, (res) => {
          const status = res.statusCode || 0;
          if (status === 401 || status === 403) {
            reject({ status, message: 'auth_failed: token rejected by cloud' });
            return;
          }
          if (status === 429) {
            const retryAfter = res.headers['retry-after'];
            const delaySec = retryAfter ? parseInt(retryAfter, 10) : 0;
            reject({ status, message: 'rate_limited', retryAfterMs: delaySec * 1000 });
            return;
          }
          if (status < 200 || status >= 300) {
            reject({ status, message: `server_error: HTTP status ${status}` });
            return;
          }

          // Successfully connected to SSE!
          this.setState('connected');
          this.backoff.reset();
          this.lastEventTime = Date.now();

          res.setEncoding('utf8');
          let buffer = '';

          res.on('data', (chunk: string) => {
            this.lastEventTime = Date.now();
            buffer += chunk;
            const parts = buffer.split(/\r?\n\r?\n/);
            buffer = parts.pop() || '';
            for (const block of parts) {
              this.parseEventBlock(block);
            }
          });

          res.on('end', () => {
            if (!aborted) {
              resolve();
            }
          });

          res.on('error', (err) => {
            if (!aborted) {
              reject(err);
            }
          });
        });
      } catch (err) {
        reject(err);
        return;
      }

      req.on('error', (err: any) => {
        if (!aborted) {
          reject(err);
        }
      });

      this.currentReq = req;
      this.currentReject = reject;
      req.end();

      const origResolve = resolve;
      const origReject = reject;
      
      resolve = () => {
        this.currentReject = undefined;
        if (this.currentReq === req) {
          this.currentReq = undefined;
        }
        origResolve();
      };
      
      reject = (err: any) => {
        this.currentReject = undefined;
        if (this.currentReq === req) {
          this.currentReq = undefined;
        }
        origReject(err);
      };
    });
  }

  private parseEventBlock(block: string) {
    const lines = block.split(/\r?\n/);
    let dataContent = '';
    for (const line of lines) {
      if (line.startsWith('data:')) {
        dataContent += line.slice(5).trim();
      }
    }
    if (!dataContent) return;
    try {
      const parsed = JSON.parse(dataContent);
      this.validateAndTriggerWake(parsed);
    } catch (err) {
      console.warn('Failed to parse SSE wake event JSON:', err, 'content:', dataContent);
    }
  }

  private validateAndTriggerWake(parsed: any) {
    if (typeof parsed !== 'object' || parsed === null) return;
    if (typeof parsed.wake_id !== 'string') return;
    const validReasons = ['browser_request', 'ping', 'migration_queued', 'config_sync'];
    if (!validReasons.includes(parsed.reason)) return;
    if (typeof parsed.queued_at !== 'number') return;
    if (typeof parsed.data_channel_token !== 'string') return;
    if (typeof parsed.data_channel_token_expires_at !== 'number') return;

    this.opts.onWake(parsed as WakeEvent);
  }
}
