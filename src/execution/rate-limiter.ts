import { LIMITS } from '../protocol/constants';

/**
 * Operations that consume budget. Every inbound message type maps onto exactly
 * one of these; `other` is the fail-safe bucket for a type this module does
 * not recognise, so a new message type is rate limited by default rather than
 * exempt by omission.
 */
export type RateLimitedAction =
  | 'ping'
  | 'introspect'
  | 'query'
  | 'stream_query'
  | 'migration_run'
  | 'cancel'
  | 'event'
  | 'other';

/** Token-bucket shape: a burst allowance plus a sustained refill rate. */
export interface RateLimitPolicy {
  /** Bucket capacity. One request per token. */
  burst: number;
  /** Tokens added per second while the bucket is below capacity. */
  per_second: number;
}

/** Who is spending budget. All three components are attacker-controlled. */
export interface RateLimitIdentity {
  agent_id: string;
  user_id: string;
  db_alias: string;
}

/** Which limit refused the request. */
export type RateLimitScope =
  | 'global'
  | 'identity'
  | 'concurrency_global'
  | 'concurrency_db';

/** Result of an admission check. */
export interface RateLimitVerdict {
  allowed: boolean;
  scope?: RateLimitScope;
  /** Curated, data-free text safe to forward to the browser. */
  reason?: string;
  retry_after_ms: number;
}

/** An admitted request. `release` must be called exactly once when it finishes. */
export interface RateLimitPermit extends RateLimitVerdict {
  release: () => void;
}

/**
 * Absolute ceilings. A limit is configurable but never unbounded: a
 * misconfigured or hostile environment variable is clamped into this range
 * rather than allowed to remove the control.
 */
const MAX_BURST = 10_000;
const MAX_RATE_PER_SECOND = 5_000;
const MAX_INFLIGHT = 4_096;
const MAX_INFLIGHT_PER_DB = 1_024;
const MAX_TRACKED_KEYS = 200_000;
const MIN_TRACKED_KEYS = 64;
const MAX_IDLE_TTL_MS = 3_600_000;
const MIN_IDLE_TTL_MS = 1_000;
const MAX_INTROSPECT_BYTES = 268_435_456;

/**
 * Default budget per action.
 *
 * `introspect` is deliberately the tightest: one call runs eleven catalogue
 * queries and returns the entire schema, so it is the cheapest request to make
 * and the most valuable one to an attacker exfiltrating a schema.
 */
export const DEFAULT_RATE_LIMIT_POLICIES: Record<RateLimitedAction, RateLimitPolicy> = {
  ping: { burst: 240, per_second: 60 },
  query: { burst: 300, per_second: 100 },
  stream_query: { burst: 60, per_second: 20 },
  migration_run: { burst: 20, per_second: 1 },
  cancel: { burst: 60, per_second: 20 },
  introspect: { burst: 30, per_second: 5 },
  event: { burst: 120, per_second: 30 },
  other: { burst: 120, per_second: 30 },
};

/** Ceiling for everything the connector does, whatever the caller's identity. */
export const DEFAULT_GLOBAL_POLICY: RateLimitPolicy = { burst: 1000, per_second: 200 };

export const DEFAULT_MAX_INFLIGHT = 128;
export const DEFAULT_MAX_INFLIGHT_PER_DB = 64;

/**
 * `cancel` is exempt from the concurrency cap and `ping` from both counters.
 *
 * A concurrency cap that could refuse a cancel would turn load into an
 * un-cancellable workload, which is the opposite of what the control is for.
 * Both actions still spend tokens, and `ping` still costs nothing but a frame.
 */
const CONCURRENCY_EXEMPT: ReadonlySet<RateLimitedAction> = new Set<RateLimitedAction>([
  'cancel',
  'ping',
]);

/** Reported when a bucket has a zero refill rate and will never recover. */
const NO_RETRY_MS = 60_000;

/** Reported when a request is refused a concurrency slot. */
const CONCURRENCY_RETRY_MS = 1_000;

interface Bucket {
  tokens: number;
  updated_at: number;
  last_seen: number;
}

export interface RateLimiterOptions {
  /** Per-action budget overrides, merged over {@link DEFAULT_RATE_LIMIT_POLICIES}. */
  policies?: Partial<Record<RateLimitedAction, RateLimitPolicy>>;
  /** Global budget override. */
  global?: Partial<RateLimitPolicy>;
  /** Concurrent admitted requests across every identity. */
  max_inflight?: number;
  /** Concurrent admitted requests for a single `db_alias`. */
  max_inflight_per_db?: number;
  /** Hard cap on tracked buckets, so the key space cannot grow without bound. */
  max_tracked_keys?: number;
  /** A bucket untouched for this long is evicted. */
  idle_ttl_ms?: number;
  /** Serialized introspection snapshot ceiling, in bytes. */
  max_introspect_bytes?: number;
  /** Clock injection point; tests supply a deterministic clock. */
  now?: () => number;
}

const NOOP = (): void => {};

function clampInt(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(Math.max(Math.floor(value), min), max);
}

function clampPolicy(policy: RateLimitPolicy): RateLimitPolicy {
  return {
    burst: clampInt(policy.burst, 1, MAX_BURST),
    per_second: Math.min(
      Math.max(Number.isFinite(policy.per_second) ? policy.per_second : 0, 0),
      MAX_RATE_PER_SECOND,
    ),
  };
}

function envInt(name: string): number | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return undefined;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * Identity components are truncated before they are used as a key so that a
 * caller cannot inflate the map with megabyte-long `db_alias` values.
 */
function keyPart(value: string | undefined): string {
  return (value ?? '').slice(0, LIMITS.ID_MAX_LENGTH);
}

export class RateLimiter {
  private readonly policies: Record<RateLimitedAction, RateLimitPolicy>;
  private readonly globalPolicy: RateLimitPolicy;
  private readonly maxInflight: number;
  private readonly maxInflightPerDb: number;
  private readonly maxTrackedKeys: number;
  private readonly idleTtlMs: number;
  private readonly sweepIntervalMs: number;
  private readonly maxIntrospectBytes: number;
  private readonly now: () => number;

  /**
   * Buckets keyed by `identity\u0000action`, plus the global bucket. Insertion
   * order is maintained on touch, which makes the oldest entry the least
   * recently used one and the entry evicted when the cap is reached.
   */
  private readonly buckets = new Map<string, Bucket>();
  private readonly globalBucket: Bucket;
  private readonly inflightByDb = new Map<string, number>();
  private inflight = 0;
  private lastSweepAt = 0;

  constructor(opts: RateLimiterOptions = {}) {
    const base: Record<RateLimitedAction, RateLimitPolicy> = {
      ...DEFAULT_RATE_LIMIT_POLICIES,
    };
    for (const action of Object.keys(base) as RateLimitedAction[]) {
      const override = opts.policies?.[action];
      if (override) base[action] = clampPolicy({ ...base[action], ...override });
    }
    this.policies = base;

    this.globalPolicy = clampPolicy({
      burst: opts.global?.burst ?? envInt('SW_RATE_LIMIT_GLOBAL_BURST') ?? DEFAULT_GLOBAL_POLICY.burst,
      per_second:
        opts.global?.per_second ??
        envInt('SW_RATE_LIMIT_GLOBAL_RPS') ??
        DEFAULT_GLOBAL_POLICY.per_second,
    });

    this.maxInflight = clampInt(
      opts.max_inflight ?? envInt('SW_RATE_LIMIT_MAX_INFLIGHT') ?? DEFAULT_MAX_INFLIGHT,
      1,
      MAX_INFLIGHT,
    );
    this.maxInflightPerDb = Math.min(
      clampInt(
        opts.max_inflight_per_db ??
          envInt('SW_RATE_LIMIT_MAX_INFLIGHT_PER_DB') ??
          DEFAULT_MAX_INFLIGHT_PER_DB,
        1,
        MAX_INFLIGHT_PER_DB,
      ),
      this.maxInflight,
    );
    this.maxTrackedKeys = clampInt(
      opts.max_tracked_keys ?? envInt('SW_RATE_LIMIT_MAX_KEYS') ?? 10_000,
      MIN_TRACKED_KEYS,
      MAX_TRACKED_KEYS,
    );
    this.idleTtlMs = clampInt(opts.idle_ttl_ms ?? 300_000, MIN_IDLE_TTL_MS, MAX_IDLE_TTL_MS);
    this.sweepIntervalMs = Math.max(MIN_IDLE_TTL_MS, Math.min(30_000, Math.floor(this.idleTtlMs / 10)));
    this.maxIntrospectBytes = clampInt(
      opts.max_introspect_bytes ?? envInt('SW_RATE_LIMIT_MAX_INTROSPECT_BYTES') ?? 32_777_216,
      1_024,
      MAX_INTROSPECT_BYTES,
    );
    this.now = opts.now ?? (() => Date.now());

    const now = this.now();
    this.globalBucket = { tokens: this.globalPolicy.burst, updated_at: now, last_seen: now };
  }

  /** Number of tracked buckets. Exposed so boundedness is assertable. */
  trackedKeys(): number {
    return this.buckets.size;
  }

  /** Requests admitted and not yet released. */
  inflightCount(): number {
    return this.inflight;
  }

  limits(): {
    global: RateLimitPolicy;
    max_inflight: number;
    max_inflight_per_db: number;
    max_tracked_keys: number;
  } {
    return {
      global: this.globalPolicy,
      max_inflight: this.maxInflight,
      max_inflight_per_db: this.maxInflightPerDb,
      max_tracked_keys: this.maxTrackedKeys,
    };
  }

  /**
   * Admit one request, spending budget from the global bucket, the caller's
   * per-identity bucket and the concurrency counters.
   *
   * The returned permit must be released exactly when the request finishes,
   * including on every error path: an unreleased permit permanently consumes
   * concurrency capacity.
   */
  tryAcquire(action: RateLimitedAction, identity: RateLimitIdentity): RateLimitPermit {
    const now = this.now();
    this.sweep(now);

    const dbAlias = keyPart(identity.db_alias);
    const exempt = CONCURRENCY_EXEMPT.has(action);
    const dbInflight = this.inflightByDb.get(dbAlias) ?? 0;

    if (!exempt) {
      if (this.inflight >= this.maxInflight) {
        return this.deny('concurrency_global', 'too_many_concurrent_requests', CONCURRENCY_RETRY_MS);
      }
      if (dbInflight >= this.maxInflightPerDb) {
        return this.deny('concurrency_db', 'too_many_concurrent_requests_for_database', CONCURRENCY_RETRY_MS);
      }
    }

    const globalSpend = this.spend(this.globalBucket, this.globalPolicy, now);
    if (!globalSpend.ok) return this.deny('global', 'rate_limit_exceeded', globalSpend.retry_after_ms);

    const key = `${keyPart(identity.agent_id)}\u0000${keyPart(identity.user_id)}\u0000${dbAlias}\u0000${action}`;
    const policy = this.policies[action] ?? this.policies.other;
    const identitySpend = this.spend(this.bucketFor(key, policy, now), policy, now);
    if (!identitySpend.ok) return this.deny('identity', 'rate_limit_exceeded', identitySpend.retry_after_ms);

    if (!exempt) {
      this.inflight++;
      this.inflightByDb.set(dbAlias, dbInflight + 1);
    }

    let released = false;
    return {
      allowed: true,
      retry_after_ms: 0,
      release: () => {
        if (released || exempt) return;
        released = true;
        this.releaseSlot(dbAlias);
      },
    };
  }

  /**
   * Size budget for one introspection response. A snapshot above the ceiling
   * still cost eleven catalogue queries on the server, but it is not shipped,
   * which is what bounds schema exfiltration.
   */
  checkIntrospectSize(bytes: number): RateLimitVerdict {
    if (Number.isFinite(bytes) && bytes >= 0 && bytes <= this.maxIntrospectBytes) {
      return { allowed: true, retry_after_ms: 0 };
    }
    return {
      allowed: false,
      reason: 'introspection_snapshot_exceeds_budget',
      retry_after_ms: 0,
    };
  }

  private deny(scope: RateLimitScope, reason: string, retry_after_ms: number): RateLimitPermit {
    return {
      allowed: false,
      scope,
      reason,
      retry_after_ms,
      release: NOOP,
    };
  }

  /** Take one token, refilling for elapsed time first. */
  private spend(
    bucket: Bucket,
    policy: RateLimitPolicy,
    now: number,
  ): { ok: boolean; retry_after_ms: number } {
    const elapsed = Math.max(0, now - bucket.updated_at);
    bucket.tokens = Math.min(policy.burst, bucket.tokens + (elapsed / 1_000) * policy.per_second);
    bucket.updated_at = now;
    bucket.last_seen = now;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { ok: true, retry_after_ms: 0 };
    }
    const deficit = 1 - bucket.tokens;
    return {
      ok: false,
      retry_after_ms:
        policy.per_second > 0 ? Math.max(1, Math.ceil((deficit / policy.per_second) * 1_000)) : NO_RETRY_MS,
    };
  }

  private bucketFor(key: string, policy: RateLimitPolicy, now: number): Bucket {
    const existing = this.buckets.get(key);
    if (existing) {
      // Re-insert so the map iterates least-recently-used first.
      this.buckets.delete(key);
      this.buckets.set(key, existing);
      return existing;
    }
    if (this.buckets.size >= this.maxTrackedKeys) this.evictOne();
    const bucket: Bucket = { tokens: policy.burst, updated_at: now, last_seen: now };
    this.buckets.set(key, bucket);
    return bucket;
  }

  private releaseSlot(dbAlias: string): void {
    if (this.inflight > 0) this.inflight--;
    const next = (this.inflightByDb.get(dbAlias) ?? 1) - 1;
    if (next <= 0) this.inflightByDb.delete(dbAlias);
    else this.inflightByDb.set(dbAlias, next);
  }

  /** Drop buckets that have been idle past the TTL, then enforce the cap. */
  private sweep(now: number): void {
    if (now - this.lastSweepAt < this.sweepIntervalMs) return;
    this.lastSweepAt = now;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.last_seen > this.idleTtlMs) this.buckets.delete(key);
    }
    while (this.buckets.size > this.maxTrackedKeys) this.evictOne();
  }

  private evictOne(): void {
    const oldest = this.buckets.keys().next();
    if (!oldest.done) this.buckets.delete(oldest.value);
  }
}
