/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, prefer-const */
import * as https from 'https';
import * as http from 'http';
import { WakeChannelState, WakeEvent } from './types';
import {
  AUTH_FAILURE_BACKOFF_MS,
  Backoff,
  MAX_AUTH_FAILURE_ATTEMPTS,
  TransportSecurityError,
  formatTokenRejectedMessage,
  toHttpUrl,
  withJitter,
} from './reconnect';
import { DEFAULTS, LIMITS } from '../protocol/constants';
import { deriveRelayCredential } from '../config/token';

/**
 * Hard ceiling on the incremental SSE parser buffer, in characters.
 *
 * A stream that never emits a blank line would otherwise grow this buffer
 * monotonically for the lifetime of the daemon. JavaScript string length counts
 * UTF-16 code units, which never exceeds the UTF-8 byte length of the same
 * text, so a character cap is strictly tighter than a byte cap on
 * LIMITS.MAX_PAYLOAD_BYTES.
 */
export const SSE_BUFFER_MAX_CHARS = LIMITS.MAX_PAYLOAD_BYTES;

/** Maximum characters of `data:` payload parsed out of one SSE event. */
export const SSE_EVENT_DATA_MAX_CHARS = LIMITS.MAX_PAYLOAD_BYTES;

/** Maximum events queued from a single TCP chunk before the stream is failed. */
export const SSE_MAX_QUEUED_EVENTS = 4_096;

/** Maximum events processed per event-loop turn before yielding. */
export const SSE_MAX_EVENTS_PER_TICK = 64;

type SseBlockOutcome = 'keepalive' | 'event' | 'ignored' | 'protocol_error';

export interface WakeChannelOptions {
  /** Cloud URL, e.g. "wss://api.schemaweaver.dev" — wss/https are the only accepted schemes. */
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
  /** Optional: custom backoff schedule for consecutive 401/403 responses. */
  authBackoffSchedule?: readonly number[];
  /** Optional: consecutive auth failures tolerated before stopping. Default 5. */
  maxAuthFailures?: number;
  /**
   * Allow a cleartext `http:`/`ws:` target. Only wire this to an explicit,
   * non-persisted operator flag (`--insecure-transport`).
   */
  allowInsecureTransport?: boolean;
  /** Clock injection point for replay/freshness checks. Defaults to `Date.now`. */
  now?: () => number;
  /**
   * Age of an acceptable wake event, from `queued_at`. Defaults to
   * DEFAULTS.WAKE_MAX_EVENT_AGE_MS.
   */
  maxEventAgeMs?: number;
  /**
   * Clock skew tolerated on the cloud-stamped `queued_at` and
   * `data_channel_token_expires_at`. Defaults to DEFAULTS.WAKE_CLOCK_SKEW_MS.
   */
  clockSkewMs?: number;
  /**
   * Capacity of the `wake_id` replay cache. Defaults to
   * LIMITS.WAKE_REPLAY_CACHE_MAX_ENTRIES. The cache is hard-bounded: an
   * unbounded set of cloud-supplied ids is itself a memory-exhaustion vector.
   */
  replayCacheEntries?: number;
  /** Called when a wake event is refused, for operator-visible reporting. */
  onWakeRejected?: (reason: WakeRejectionReason, detail: string, event: unknown) => void;
}

/** Why a wake event was refused without being dispatched. */
export type WakeRejectionReason =
  | 'malformed'
  | 'expired_token'
  | 'stale'
  | 'future_dated'
  | 'replayed'
  | 'cache_full';

/** Counters for the wake-event admission checks. Diagnostics only. */
export interface WakeAdmissionStats {
  /** Wake ids currently held in the replay cache. Never exceeds the bound. */
  cached: number;
  /** Events refused as replays of a cached `wake_id`. */
  duplicates: number;
  /** Events refused because the cache was already at its bound. */
  denied_cache_full: number;
  /** Events refused for any other reason (malformed, stale, expired token). */
  refused: number;
  accepted: number;
}

export interface SseBufferStats {
  /** Current parser buffer size in characters. */
  current: number;
  /** High-water mark of the parser buffer since process start. */
  peak: number;
  /** Events waiting to be dispatched. */
  queued: number;
}

export class WakeChannel {
  private state: WakeChannelState = 'disconnected';
  private backoff: Backoff;
  private authBackoff: Backoff;
  private currentReq?: http.ClientRequest;
  private shutdownRequested = false;
  private readonly opts: WakeChannelOptions;
  private keepaliveTimer?: NodeJS.Timeout;
  private lastEventTime = 0;

  private sleepTimer?: NodeJS.Timeout;
  private sleepReject?: () => void;
  private loopPromise?: Promise<void>;
  private loopRunning = false;
  private firstAttemptResolver?: () => void;
  private currentReject?: (err: any) => void;
  private authFailures = 0;

  private sseBuffer = '';
  private sseQueue: string[] = [];
  private sseDrainScheduled = false;
  private ssePeakChars = 0;
  private sseFailure?: string;

  /**
   * Admission limits for wake events (audit M-14). Frozen at construction so a
   * later mutation of `opts` cannot widen them mid-stream.
   */
  private readonly wakeLimits: {
    now: () => number;
    maxEventAgeMs: number;
    clockSkewMs: number;
    replayCacheEntries: number;
  };

  /**
   * `wake_id` -> first-seen timestamp, insertion-ordered so the oldest entry is
   * the eviction candidate. Hard-bounded by `wakeLimits.replayCacheEntries`:
   * when the bound is reached a new id is refused rather than evicting, so a
   * flood of ids cannot shrink the defence applied to ids already seen.
   */
  private readonly seenWakeIds = new Map<string, number>();
  private wakeDuplicates = 0;
  private wakeCacheFullDenials = 0;
  private wakeRefusals = 0;
  private wakeAccepted = 0;

  constructor(opts: WakeChannelOptions) {
    this.opts = opts;
    this.backoff = new Backoff(opts.backoffSchedule);
    this.authBackoff = new Backoff(
      opts.authBackoffSchedule ?? AUTH_FAILURE_BACKOFF_MS,
      opts.authBackoffSchedule
        ? opts.authBackoffSchedule[opts.authBackoffSchedule.length - 1]
        : undefined,
    );
    this.wakeLimits = {
      now: opts.now ?? Date.now,
      maxEventAgeMs: opts.maxEventAgeMs ?? DEFAULTS.WAKE_MAX_EVENT_AGE_MS,
      clockSkewMs: opts.clockSkewMs ?? DEFAULTS.WAKE_CLOCK_SKEW_MS,
      replayCacheEntries: opts.replayCacheEntries ?? LIMITS.WAKE_REPLAY_CACHE_MAX_ENTRIES,
    };
    if (
      !Number.isFinite(this.wakeLimits.replayCacheEntries) ||
      this.wakeLimits.replayCacheEntries < 1
    ) {
      this.wakeLimits.replayCacheEntries = LIMITS.WAKE_REPLAY_CACHE_MAX_ENTRIES;
    }

    if (this.opts.abortSignal) {
      if (this.opts.abortSignal.aborted) {
        this.stop();
      } else {
        this.opts.abortSignal.addEventListener('abort', () => {
          this.stop().catch((err) => {
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
    this.authBackoff.reset();
    this.authFailures = 0;

    const firstAttemptPromise = new Promise<void>((resolve) => {
      this.firstAttemptResolver = resolve;
    });

    this.ensureLoop();

    return firstAttemptPromise;
  }

  /** Graceful shutdown. Waits for current request to abort. */
  async stop(): Promise<void> {
    this.shutdownRequested = true;
    this.stopKeepalive();

    if (this.sleepReject) {
      this.sleepReject();
      this.sleepReject = undefined;
    }
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = undefined;
    }

    this.resetStreamState();
    this.abortCurrentRequest('WakeChannel: stopping');
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

  /** Consecutive auth failures observed since the last successful connect. */
  getAuthFailures(): number {
    return this.authFailures;
  }

  /** Diagnostics: current/peak SSE parser buffer size and pending events. */
  getSseBufferStats(): SseBufferStats {
    return {
      current: this.sseBuffer.length,
      peak: this.ssePeakChars,
      queued: this.sseQueue.length,
    };
  }

  /** Last SSE stream failure reason, if any. Diagnostics only. */
  getSseFailureReason(): string | undefined {
    return this.sseFailure;
  }

  /**
   * Wake-event admission counters. `cached` is the current occupancy of the
   * bounded replay cache and never exceeds the configured bound.
   */
  getWakeAdmissionStats(): WakeAdmissionStats {
    return {
      cached: this.seenWakeIds.size,
      duplicates: this.wakeDuplicates,
      denied_cache_full: this.wakeCacheFullDenials,
      refused: this.wakeRefusals,
      accepted: this.wakeAccepted,
    };
  }

  /** Forget every cached `wake_id`. Used when the stream is re-established. */
  private resetWakeReplayCache(): void {
    this.seenWakeIds.clear();
  }

  /** Force a reconnect (e.g. after token rotation). Restarts a stopped loop. */
  async reconnect(): Promise<void> {
    this.backoff.reset();
    this.authBackoff.reset();
    this.authFailures = 0;
    if (this.sleepReject) {
      this.sleepReject();
      this.sleepReject = undefined;
    }
    if (this.sleepTimer) {
      clearTimeout(this.sleepTimer);
      this.sleepTimer = undefined;
    }
    this.resetStreamState();
    this.abortCurrentRequest('WakeChannel: reconnect requested');
    if (!this.loopRunning) {
      this.shutdownRequested = false;
      this.ensureLoop();
    }
  }

  private ensureLoop(): void {
    if (this.loopRunning) {
      return;
    }
    this.loopRunning = true;
    // Armed with the loop, not with start(): a terminal exit (audit H-03
    // refusal, exhausted auth retries) stops the loop, and reconnect() has to
    // bring liveness checking back with it.
    this.startKeepalive();
    this.loopPromise = this.runLoop()
      .catch((err) => {
        console.error('WakeChannel: unhandled loop error', err);
      })
      .finally(() => {
        this.loopRunning = false;
        // A loop that has ended will never fire the liveness check again, so
        // the interval is released instead of outliving it and holding the
        // process open until stop() happens to be called.
        this.stopKeepalive();
      });
  }

  /**
   * Start the liveness checker that tears down a stream the cloud stopped
   * feeding. Opaque unless the operator disabled it.
   */
  private startKeepalive(): void {
    if (this.opts.enableKeepalive === false) {
      return;
    }
    this.stopKeepalive();
    this.keepaliveTimer = setInterval(() => {
      if (this.state === 'connected' && Date.now() - this.lastEventTime > DEFAULTS.WAKE_KEEPALIVE_MS) {
        // Liveness is refreshed only by well-formed stream activity, so an
        // unparseable flood cannot hold a dead connection open.
        console.warn(
          `WakeChannel: keepalive timeout, no well-formed events in the last ` +
            `${DEFAULTS.WAKE_KEEPALIVE_MS}ms. Reconnecting...`,
        );
        this.failSseStream(
          'keepalive_timeout',
          `no well-formed events received in ${DEFAULTS.WAKE_KEEPALIVE_MS}ms`,
        );
      }
    }, 30000); // check every 30s
    // Never hold the process open for the liveness checker alone.
    this.keepaliveTimer.unref?.();
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = undefined;
    }
  }

  private abortCurrentRequest(reason = 'Request aborted') {
    if (this.currentReject) {
      try {
        this.currentReject(new Error(reason));
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

  /**
   * Report an error even when the state is already `error`, so an escalating
   * failure (repeated auth rejections, repeated stream violations) stays
   * visible to the operator instead of going silent on the first message.
   */
  private reportError(message: string): void {
    if (this.state === 'error') {
      if (this.opts.onStateChange) {
        this.opts.onStateChange('error', message);
      }
      return;
    }
    this.setState('error', message);
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
        this.authFailures = 0;
        this.authBackoff.reset();
      } catch (err: any) {
        if (this.shutdownRequested) {
          break;
        }

        if (err instanceof TransportSecurityError) {
          // Audit H-03: a cleartext or unparseable target is a configuration
          // fault. Retrying cannot fix it, so stop and leave the operator with
          // the reason rather than a silent 60s retry loop.
          console.error(`WakeChannel: ${err.message}`);
          this.reportError(err.message);
          break;
        }

        const isAuthError = err.status === 401 || err.status === 403;
        if (isAuthError) {
          // Audit H-12: a rejected credential used to break the loop, which
          // bricked the agent until a manual re-init. Retry a bounded number of
          // times with jittered backoff (covering clock skew and a not-yet
          // replicated rotation), then stop and say what to do about it.
          this.authFailures++;
          const maxFailures = this.opts.maxAuthFailures ?? MAX_AUTH_FAILURE_ATTEMPTS;
          const message = formatTokenRejectedMessage(err.status, this.authFailures, maxFailures);
          this.reportError(message);

          if (this.authFailures >= maxFailures) {
            console.error(
              `WakeChannel: giving up after ${this.authFailures} consecutive authentication ` +
                `failures. ${message}`,
            );
            break;
          }

          try {
            await this.sleepNextJittered(withJitter(this.authBackoff.next()));
          } catch (e) {
            // Sleep interrupted by reconnect/stop
          }
          continue;
        }

        this.reportError(err.message || 'connection failed');

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

      // Audit H-03: validate the configured scheme once, here, before the
      // Authorization header is built. `wss:` → `https:` is the only mapping
      // performed; `ws:`/`http:` are refused rather than downgraded.
      let url: URL;
      try {
        url = toHttpUrl(this.opts.cloudUrl, {
          allowInsecure: this.opts.allowInsecureTransport === true,
          context: 'wake channel',
        });
      } catch (err) {
        this.setState('error', err instanceof Error ? err.message : String(err));
        reject(err);
        return;
      }
      url.pathname = `${url.pathname.replace(/\/+$/, '')}/api/agent/wake`;
      const targetUrl = url.toString();

      // toHttpUrl() refuses every non-TLS scheme unless the caller explicitly
      // opted in, so the plain-http branch is reachable only via
      // --insecure-transport.
      const requestLib = url.protocol === 'https:' ? https : http;

      const headers: Record<string, string> = {
        // Derived, never the raw agent token.
        Authorization: `Bearer ${deriveRelayCredential(this.opts.token)}`,
        'X-Agent-Id': this.opts.agentId,
        Accept: 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
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

      this.resetStreamState();

      try {
        req = requestLib.request(targetUrl, reqOpts, (res) => {
          const status = res.statusCode || 0;
          if (status === 401 || status === 403) {
            res.resume();
            reject({ status, message: 'auth_failed: token rejected by cloud' });
            return;
          }
          if (status === 429) {
            const retryAfter = res.headers['retry-after'];
            const delaySec = retryAfter ? parseInt(retryAfter, 10) : 0;
            res.resume();
            reject({ status, message: 'rate_limited', retryAfterMs: delaySec * 1000 });
            return;
          }
          if (status < 200 || status >= 300) {
            res.resume();
            reject({ status, message: `server_error: HTTP status ${status}` });
            return;
          }

          // Successfully connected to SSE!
          this.setState('connected');
          this.backoff.reset();
          this.lastEventTime = Date.now();

          res.setEncoding('utf8');

          res.on('data', (chunk: string) => {
            this.ingestSseChunk(chunk);
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

  /**
   * Drop all untrusted partial state. The buffer is never carried into the
   * next connection: it is entirely cloud-controlled bytes.
   */
  private resetSseState(): void {
    this.sseBuffer = '';
    this.sseQueue = [];
    this.sseDrainScheduled = false;
    this.sseFailure = undefined;
  }

  /**
   * Drop every untrusted partial state on reconnect, INCLUDING the replay cache.
   *
   * The cloud is the only producer of a legitimate `wake_id`, so a reconnect can
   * re-deliver ids the previous connection already consumed (at-least-once SSE);
   * keeping the cache across reconnects turns that into a denial of service. The
   * cloud's own expiry on `data_channel_token_expires_at` remains the durable
   * backstop: a token that was valid before the reconnect has not become valid
   * again.
   */
  private resetStreamState(): void {
    this.resetSseState();
    this.resetWakeReplayCache();
  }

  /**
   * Feed one decoded chunk into the incremental SSE parser (audit H-09).
   *
   * Bounded on every axis: the carry-over buffer, the number of events a
   * single chunk may enqueue, and (in {@link drainSseQueue}) how many events
   * run per event-loop turn.
   */
  private ingestSseChunk(chunk: string): void {
    if (this.sseFailure) {
      return;
    }

    if (this.sseBuffer.length + chunk.length > SSE_BUFFER_MAX_CHARS) {
      this.failSseStream(
        'sse_buffer_overflow',
        `stream produced more than ${SSE_BUFFER_MAX_CHARS} characters without a blank-line ` +
          `event terminator`,
      );
      return;
    }

    this.sseBuffer += chunk;
    if (this.sseBuffer.length > this.ssePeakChars) {
      this.ssePeakChars = this.sseBuffer.length;
    }

    const parts = this.sseBuffer.split(/\r?\n\r?\n/);
    this.sseBuffer = parts.pop() || '';

    for (const part of parts) {
      if (part.trim().length === 0) {
        continue;
      }
      if (this.sseQueue.length >= SSE_MAX_QUEUED_EVENTS) {
        this.failSseStream(
          'sse_event_flood',
          `single chunk contained more than ${SSE_MAX_QUEUED_EVENTS} SSE events`,
        );
        return;
      }
      this.sseQueue.push(part);
    }

    if (this.sseQueue.length > 0) {
      this.scheduleSseDrain();
    }
  }

  /** Queue a drain on the next event-loop turn (never inline in `data`). */
  private scheduleSseDrain(): void {
    if (this.sseDrainScheduled || this.shutdownRequested) {
      return;
    }
    this.sseDrainScheduled = true;
    setImmediate(() => {
      this.sseDrainScheduled = false;
      void this.drainSseQueue();
    });
  }

  /**
   * Dispatch queued events, capped per turn and yielding in between so a burst
   * cannot starve the event loop the rest of the daemon runs on.
   */
  private async drainSseQueue(): Promise<void> {
    try {
      while (this.sseQueue.length > 0 && !this.shutdownRequested && !this.sseFailure) {
        const batch = this.sseQueue.splice(0, SSE_MAX_EVENTS_PER_TICK);
        for (const block of batch) {
          if (this.shutdownRequested || this.sseFailure) {
            break;
          }
          this.dispatchSseBlock(block);
        }
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
    } catch (err) {
      this.failSseStream('sse_handler_error', err instanceof Error ? err.message : String(err));
    }
  }

  /**
   * Handle one event block. Only a well-formed frame counts as liveness, so a
   * flood of unparseable bytes cannot keep a dead stream looking healthy.
   */
  private dispatchSseBlock(block: string): void {
    const outcome = this.parseEventBlock(block);

    if (outcome === 'keepalive' || outcome === 'event') {
      this.lastEventTime = Date.now();
    }

    if (outcome === 'protocol_error') {
      this.failSseStream('sse_malformed_event', 'event block was unparseable or over the size cap');
    }
  }

  /**
   * Fail the current stream: discard untrusted state, report, and force a
   * reconnect through the normal (backed-off) retry path.
   */
  private failSseStream(reason: string, detail: string): void {
    if (this.sseFailure) {
      return;
    }
    this.sseFailure = reason;
    this.sseBuffer = '';
    this.sseQueue = [];
    const message = `WakeChannel SSE stream failed (${reason}): ${detail}`;
    console.warn(message);
    this.reportError(message);
    this.abortCurrentRequest(message);
  }

  /**
   * Parse one SSE event block per the SSE grammar. Returns what the block was:
   * a keepalive comment, a dispatched wake event, a well-formed event that is
   * not a wake, or a protocol error.
   */
  private parseEventBlock(block: string): SseBlockOutcome {
    let sawDataField = false;
    let sawComment = false;
    let dataLength = 0;
    const dataParts: string[] = [];

    for (const line of block.split(/\r?\n/)) {
      if (line.length === 0 || line.startsWith(':')) {
        if (line.startsWith(':')) {
          sawComment = true;
        }
        continue;
      }

      const colon = line.indexOf(':');
      const field = colon === -1 ? line : line.slice(0, colon);
      let value = colon === -1 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) {
        value = value.slice(1);
      }
      if (field !== 'data') {
        continue;
      }

      sawDataField = true;
      dataLength += value.length;
      if (dataLength > SSE_EVENT_DATA_MAX_CHARS) {
        return 'protocol_error';
      }
      dataParts.push(value);
    }

    if (!sawDataField) {
      return sawComment ? 'keepalive' : 'ignored';
    }

    const dataContent = dataParts.join('\n');
    if (dataContent.trim().length === 0) {
      return sawComment ? 'keepalive' : 'ignored';
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(dataContent);
    } catch {
      return 'protocol_error';
    }

    return this.validateAndTriggerWake(parsed) ? 'event' : 'ignored';
  }

  /**
   * Shape plus freshness plus replay. Returns true only when the event was
   * dispatched to `onWake`.
   *
   * Audit M-14. `data_channel_token_expires_at` used to be type-checked and then
   * ignored, so a captured SSE event could be replayed indefinitely to re-open a
   * data channel with a token the relay had already expired. Every check here
   * denies by default: an event that fails any of them is never dispatched, and
   * no path re-checks or relaxes them downstream.
   */
  private validateAndTriggerWake(parsed: any): boolean {
    if (typeof parsed !== 'object' || parsed === null)
      return this.reject('malformed', 'not a JSON object', parsed);
    if (typeof parsed.wake_id !== 'string' || parsed.wake_id.length === 0) {
      return this.reject('malformed', 'missing or empty wake_id', parsed);
    }
    const validReasons = ['browser_request', 'ping', 'migration_queued', 'config_sync'];
    if (typeof parsed.reason !== 'string' || !validReasons.includes(parsed.reason)) {
      return this.reject('malformed', `unknown wake reason ${String(parsed.reason)}`, parsed);
    }
    if (typeof parsed.queued_at !== 'number' || !Number.isFinite(parsed.queued_at)) {
      return this.reject('malformed', 'queued_at is not a finite timestamp', parsed);
    }
    if (typeof parsed.data_channel_token !== 'string' || parsed.data_channel_token.length === 0) {
      return this.reject('malformed', 'missing data_channel_token', parsed);
    }
    if (
      typeof parsed.data_channel_token_expires_at !== 'number' ||
      !Number.isFinite(parsed.data_channel_token_expires_at)
    ) {
      return this.reject(
        'malformed',
        'data_channel_token_expires_at is not a finite timestamp',
        parsed,
      );
    }
    if (parsed.browser_session_id !== undefined && typeof parsed.browser_session_id !== 'string') {
      return this.reject('malformed', 'browser_session_id is not a string', parsed);
    }

    const now = this.wakeLimits.now();
    const skew = this.wakeLimits.clockSkewMs;

    // The token must still be usable, allowing for skew and for the safety
    // margin DataChannel applies before it dials. This is the check that makes a
    // captured event useless: the relay stops honouring the token regardless of
    // what the agent believes.
    if (parsed.data_channel_token_expires_at - skew - DEFAULTS.WAKE_MIN_TOKEN_LIFE_MS <= now) {
      return this.reject(
        'expired_token',
        `data_channel_token expired at ${parsed.data_channel_token_expires_at} (now ${now})`,
        parsed,
      );
    }

    const age = now - parsed.queued_at;
    if (age > this.wakeLimits.maxEventAgeMs + skew) {
      return this.reject(
        'stale',
        `wake event is ${age}ms old, limit is ${this.wakeLimits.maxEventAgeMs + skew}ms`,
        parsed,
      );
    }
    if (age < -skew) {
      return this.reject('future_dated', `queued_at is ${-age}ms in the future`, parsed);
    }

    // Replay: bounded, and never at the cost of the entries already protected.
    // Evicting here would let a flood of ids reset the defence for ids an
    // attacker has already captured, so a full cache refuses instead.
    if (this.seenWakeIds.has(parsed.wake_id)) {
      this.wakeDuplicates++;
      return this.reject('replayed', `wake_id ${parsed.wake_id} was already processed`, parsed);
    }
    if (this.seenWakeIds.size >= this.wakeLimits.replayCacheEntries) {
      this.wakeCacheFullDenials++;
      return this.reject(
        'cache_full',
        `wake replay cache is full (${this.wakeLimits.replayCacheEntries} entries)`,
        parsed,
      );
    }
    this.seenWakeIds.set(parsed.wake_id, now);

    this.wakeAccepted++;
    this.opts.onWake(parsed as WakeEvent);
    return true;
  }

  /** Record and report a refusal. Always returns false so callers can `return`. */
  private reject(reason: WakeRejectionReason, detail: string, event: unknown): false {
    if (reason !== 'replayed' && reason !== 'cache_full') {
      this.wakeRefusals++;
    }
    const message = `WakeChannel refused a wake event (${reason}): ${detail}`;
    console.warn(message);
    try {
      this.opts.onWakeRejected?.(reason, detail, event);
    } catch {
      /* reporting must never break the stream */
    }
    return false;
  }
}
