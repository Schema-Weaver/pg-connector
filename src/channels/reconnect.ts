import { DEFAULTS } from '../protocol/constants';

/**
 * Exponential backoff calculator.
 * Sequence: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s, 60s, ...
 */
export class Backoff {
  private attempt = 0;
  private readonly max: number;

  constructor(
    /** Custom backoff schedule (defaults to DEFAULTS.RECONNECT_BACKOFF_MS). */
    private readonly schedule: readonly number[] = DEFAULTS.RECONNECT_BACKOFF_MS,
    /** Maximum delay cap (defaults to last value in schedule). */
    maxMs?: number,
  ) {
    this.max = maxMs ?? schedule[schedule.length - 1];
  }

  /** Returns the next delay in ms (does NOT sleep). */
  next(): number {
    const idx = Math.min(this.attempt, this.schedule.length - 1);
    const delay = this.schedule[idx];
    this.attempt++;
    return Math.min(delay, this.max);
  }

  /** Current attempt number (0 before first next() call). */
  get attempts(): number {
    return this.attempt;
  }

  /** Reset to attempt 0 (call after successful connect). */
  reset(): void {
    this.attempt = 0;
  }

  /** Sleep for the next backoff delay. Returns the ms slept. */
  async sleepNext(): Promise<number> {
    const delay = this.next();
    await sleep(delay);
    return delay;
  }
}

/** Promise-based sleep. */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Compute jittered backoff (±20% of base delay) to prevent thundering herd.
 * Optional — use only if you want to add jitter on top of Backoff.
 */
export function withJitter(delayMs: number, jitterPct: number = 0.2): number {
  const jitter = delayMs * jitterPct;
  return Math.round(delayMs - jitter + Math.random() * 2 * jitter);
}

/* -------------------------------------------------------------------------- */
/* Transport security guard (audit H-03)                                       */
/* -------------------------------------------------------------------------- */

/** URL schemes that mean "TLS-protected". Nothing else may carry the token. */
export const SECURE_TRANSPORT_SCHEMES: readonly string[] = Object.freeze(['wss:', 'https:']);

/**
 * Operator-facing remediation for a rejected or expired agent token.
 *
 * Wording is kept in step with `sw-agent agent rotate-token`: a running agent
 * keeps the credential it was started with, so the restart is part of the fix,
 * not an optional extra.
 */
export const TOKEN_ROTATION_HINT =
  'Run `sw-agent agent rotate-token` to mint a new agent token, then `sw-agent agent restart` so ' +
  'the running agent picks it up.';

/**
 * Remediation for a cleartext transport target.
 *
 * Names the sanctioned lab escape hatch (`--insecure-transport`, audit H-03) with
 * its costs attached. The config validators reject plaintext URLs outright, so
 * the flag is the only route to a cleartext socket — withholding it would leave
 * the operator with a refusal they cannot act on and a plaintext mode they cannot
 * discover. The secure remedy still comes first and the flag is stated as a last
 * resort that keeps the token in cleartext for the whole session.
 */
export const INSECURE_TRANSPORT_HINT =
  'Set `cloud_url` (and `cloud_telemetry.ingest_url`, if set) to a wss:// or https:// URL: plaintext ' +
  'targets are refused because the agent token would be readable in transit. For local lab use, put ' +
  'a TLS terminator in front of the relay; if that is genuinely impossible, start the agent with ' +
  '--insecure-transport, which is never written to config, logs a loud warning on every start, and ' +
  'leaves the agent token in cleartext for the lifetime of the session.';

/** Marker so operators can grep logs for this condition. */
export const INSECURE_TRANSPORT_MARKER = '[INSECURE TRANSPORT]';

export type TransportSecurityErrorCode = 'insecure_transport' | 'invalid_url';

/**
 * Thrown when an outbound target is not a TLS-protected `wss:`/`https:` URL.
 *
 * Every outbound connection path throws this instead of downgrading the
 * protocol, so the agent token can never be written to a cleartext socket.
 */
export class TransportSecurityError extends Error {
  constructor(
    public code: TransportSecurityErrorCode,
    message: string,
    /** The offending target, as supplied by config. */
    public url: string,
    /** The offending scheme, or '' when the URL could not be parsed. */
    public scheme: string,
    /** Short description of the connection attempt, e.g. "wake channel". */
    public context: string = 'outbound connection',
  ) {
    super(message);
    this.name = 'TransportSecurityError';
  }
}

export interface TransportGuardOptions {
  /**
   * Opt-in plaintext allowance, for an explicit operator decision only. The CLI
   * rejects plaintext URLs outright, so nothing in the shipped product sets
   * this; it exists so a downstream embedder that has made its own decision
   * cannot do so silently. When set, a loud warning is logged on every call.
   */
  allowInsecure?: boolean;
  /** Short description of the connection attempt, used in error messages. */
  context?: string;
}

function describeContext(context?: string): string {
  return context && context.length > 0 ? context : 'outbound connection';
}

/** Parse a target URL, throwing TransportSecurityError('invalid_url') on failure. */
function parseTarget(url: string | URL, context: string): URL {
  try {
    return url instanceof URL ? new URL(url.toString()) : new URL(url);
  } catch {
    throw new TransportSecurityError(
      'invalid_url',
      `Invalid URL for ${context}: ${String(url).slice(0, 200)}`,
      String(url).slice(0, 200),
      '',
      context,
    );
  }
}

/**
 * True when the target is a TLS-protected `wss:`/`https:` URL. Unparseable
 * input returns false — callers must fail closed.
 */
export function isSecureTransportUrl(url: string | URL): boolean {
  let parsed: URL;
  try {
    parsed = url instanceof URL ? url : new URL(url);
  } catch {
    return false;
  }
  return SECURE_TRANSPORT_SCHEMES.includes(parsed.protocol);
}

/**
 * Assert that `url` is a `wss:`/`https:` target and return it parsed.
 *
 * This is the single enforcement point for audit H-03: every outbound
 * connection path calls it (directly or via {@link toWebSocketUrl} /
 * {@link toHttpUrl}) before an `Authorization: Bearer <agent token>` header is
 * attached. Non-TLS schemes throw instead of being downgraded. Only an
 * explicit, non-persisted `allowInsecure` opt-in permits plaintext, and it
 * warns loudly on every call.
 */
export function assertSecureTransport(url: string | URL, opts: TransportGuardOptions = {}): URL {
  const context = describeContext(opts.context);
  const parsed = parseTarget(url, context);

  if (SECURE_TRANSPORT_SCHEMES.includes(parsed.protocol)) {
    return parsed;
  }

  if (opts.allowInsecure === true) {
    console.warn(
      `${INSECURE_TRANSPORT_MARKER} ${context} is using ${parsed.protocol}// — the agent token ` +
        `is being sent in cleartext to ${parsed.host}. ${INSECURE_TRANSPORT_HINT}`,
    );
    return parsed;
  }

  throw insecureTransportError(parsed, context);
}

function insecureTransportError(parsed: URL, context: string): TransportSecurityError {
  return new TransportSecurityError(
    'insecure_transport',
    `Refusing to open ${context} to ${parsed.protocol}//${parsed.host}: the agent token is a ` +
      `bearer credential and is only ever sent over TLS. ${INSECURE_TRANSPORT_HINT}`,
    `${parsed.protocol}//${parsed.host}`,
    parsed.protocol,
    context,
  );
}

/**
 * Build a `wss:` target from a configured cloud URL.
 *
 * `https:` maps to `wss:` (same TLS transport, different protocol) and `wss:`
 * is used as-is. `ws:`/`http:` throw unless the caller passed `allowInsecure`.
 */
export function toWebSocketUrl(base: string | URL, opts: TransportGuardOptions = {}): URL {
  const context = describeContext(opts.context);
  const parsed = assertSecureTransport(base, { ...opts, context });

  if (parsed.protocol === 'https:') {
    parsed.protocol = 'wss:';
  }
  return parsed;
}

/**
 * Build an `https:` target from a configured cloud URL.
 *
 * `wss:` maps to `https:` (same TLS transport, SSE/plain HTTP) and `https:` is
 * used as-is. `ws:`/`http:` throw unless the caller passed `allowInsecure`.
 */
export function toHttpUrl(base: string | URL, opts: TransportGuardOptions = {}): URL {
  const context = describeContext(opts.context);
  const parsed = assertSecureTransport(base, { ...opts, context });

  if (parsed.protocol === 'wss:') {
    parsed.protocol = 'https:';
  } else if (opts.allowInsecure === true && parsed.protocol === 'ws:') {
    parsed.protocol = 'http:';
  }
  return parsed;
}

/* -------------------------------------------------------------------------- */
/* Token lifecycle helpers (audit H-12)                                        */
/* -------------------------------------------------------------------------- */

/**
 * Backoff schedule for consecutive authentication failures. Kept separate from
 * DEFAULTS.RECONNECT_BACKOFF_MS because a rejected credential is a different
 * class of failure: it is slow to start and slow to give up on.
 */
export const AUTH_FAILURE_BACKOFF_MS: readonly number[] = Object.freeze([
  5_000, 15_000, 60_000, 300_000, 900_000,
]);

/**
 * Consecutive 401/403 responses tolerated before the wake loop stops retrying.
 *
 * Policy: a credential the server evaluated and rejected cannot become valid by
 * retrying, so retries are bounded rather than infinite. The bound exists only
 * to absorb the two realistic transient cases — clock skew and a token the
 * cloud rotated but has not yet replicated — after which the loop stops instead
 * of hammering the auth endpoint from every connected agent.
 */
export const MAX_AUTH_FAILURE_ATTEMPTS = 5;

/**
 * Operator-facing message for a credential the cloud rejected.
 */
export function formatTokenRejectedMessage(
  status?: number,
  attempts?: number,
  maxAttempts?: number,
): string {
  const statusText = status ? `HTTP ${status}` : 'auth failure';
  const attemptText =
    typeof attempts === 'number' && typeof maxAttempts === 'number'
      ? ` (attempt ${attempts} of ${maxAttempts})`
      : '';
  return (
    `auth_failed: agent token rejected by cloud (${statusText})${attemptText}. ` +
    `The agent_token in sw-agent.config.json is invalid, revoked, or belongs to a different ` +
    `agent_id. ${TOKEN_ROTATION_HINT}`
  );
}

/**
 * Operator-facing message for a credential the client itself found expired.
 */
export function formatTokenExpiredMessage(
  expiresAt: number,
  marginMs: number,
  context: string,
): string {
  const at = Number.isFinite(expiresAt) ? new Date(expiresAt).toISOString() : 'an unknown time';
  return (
    `${context} refused to use an expired token: it expires at ${at}, which is inside the ` +
    `${marginMs}ms safety margin. ${TOKEN_ROTATION_HINT}`
  );
}
