export const PROTOCOL_VERSION = 1 as const;

export const DEFAULTS = {
  QUERY_TIMEOUT_MS: 30_000,           // 30s default for one-shot queries
  MIGRATION_TIMEOUT_MS: 1_800_000,    // 30 min default for migrations
  STREAM_CHUNK_ROWS: 100,             // chunk if 100 rows collected
  STREAM_CHUNK_BYTES: 65_536,         // chunk if 64KB collected
  STREAM_CHUNK_MS: 100,               // chunk if 100ms elapsed
  MAX_QUERY_ROWS: 10_000,             // hard cap for non-streaming query
  MAX_STREAM_ROWS: 1_000_000,         // hard cap for streaming query
  MAX_CELL_BYTES: 1_048_576,          // 1MB per cell (larger = truncated)
  // SINGLE SOURCE OF TRUTH for the manual-approval window. The value enforced by
  // `ManualApprovalHandler` and the `expires_at` it advertises to the browser are
  // both derived from this (see `resolveApprovalTimeoutMs` in
  // permissions/manual-approval.ts); an operator override is clamped into
  // [LIMITS.APPROVAL_TIMEOUT_MIN_MS, LIMITS.APPROVAL_TIMEOUT_MAX_MS].
  APPROVAL_TIMEOUT_MS: 60_000,        // manual approval: 60s timeout
  IDLE_WSS_TIMEOUT_MS: 60_000,        // close WSS after 60s idle
  WAKE_KEEPALIVE_MS: 300_000,         // SSE keepalive every 5 min
  RECONNECT_BACKOFF_MS: [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000],
  ORPHAN_REQUEST_TIMEOUT_MS: 300_000, // 5 min: kill query if no reconnect
  // Absolute clock skew tolerated on an inbound envelope's `ts`. Wide enough to
  // absorb relay latency and browser clock drift, narrow enough that a captured
  // frame is useless minutes later.
  ENVELOPE_MAX_CLOCK_SKEW_MS: 120_000, // 2 min
  // Age of an SSE wake event, measured from `queued_at`. A captured event replayed
  // after this window is rejected regardless of what token it carries.
  WAKE_MAX_EVENT_AGE_MS: 120_000,     // 2 min
  // Clock skew tolerated on a wake event's `queued_at` and
  // `data_channel_token_expires_at`, both of which are stamped by the cloud.
  WAKE_CLOCK_SKEW_MS: 5_000,          // 5s
  // Minimum remaining life a data-channel token must have for the wake event to
  // be accepted at all; the data channel applies its own margin before dialling.
  WAKE_MIN_TOKEN_LIFE_MS: 5_000,      // 5s
  // Session churn (audit M-15): a wake event that replaces the active browser
  // session is refused while the current one is healthy, and any session change
  // closer together than this is refused outright.
  SESSION_CHANGE_COOLDOWN_MS: 30_000, // 30s
  // …and at most this many session changes inside any one window.
  SESSION_CHANGE_WINDOW_MS: 300_000,  // 5 min
  SESSION_CHANGE_MAX_PER_WINDOW: 3,
} as const;

export const LIMITS = {
  MAX_STATEMENT_COUNT_PER_MIGRATION: 500,
  // Protocol-level invariant for a single `query`/`stream_query` payload.
  // PostgreSQL's simple query protocol executes every semicolon-separated
  // statement in one round trip, so anything above 1 is a parser differential.
  MAX_STATEMENT_COUNT_PER_QUERY: 1,
  MAX_STATEMENT_LENGTH: 1_048_576,    // 1MB per SQL statement
  MAX_PAYLOAD_BYTES: 16_777_216,      // 16MB per message (envelope + payload)
  ID_MAX_LENGTH: 64,
  PROJECT_MAX_LENGTH: 64,
  ALIAS_MAX_LENGTH: 64,
  ENVELOPE_NONCE_MIN_LENGTH: 16,
  ENVELOPE_NONCE_MAX_LENGTH: 64,
  // 32 bytes of HMAC-SHA256, hex encoded.
  ENVELOPE_MAC_HEX_LENGTH: 64,
  // Bounded replay cache. Oldest nonce is evicted first once the cache is full,
  // so a flood cannot grow memory without bound (eviction can only re-admit an
  // evicted nonce, and the freshness window bounds the value of doing so).
  REPLAY_CACHE_MAX_ENTRIES: 8_192,
  // Bounded wake_id replay cache (audit M-14). Oldest id is evicted first. This is
  // a DoS control in its own right: an unbounded Set of cloud-supplied ids would
  // be an unbounded memory sink on a stream the agent cannot authenticate the
  // producer of. Eviction can only re-admit an id whose token has already
  // expired, so the token check is the backstop, not this cache.
  WAKE_REPLAY_CACHE_MAX_ENTRIES: 1_024,
  // Bounds on the clamped manual-approval timeout override.
  APPROVAL_TIMEOUT_MIN_MS: 5_000,     // 5s
  APPROVAL_TIMEOUT_MAX_MS: 900_000,   // 15 min
  // crypto.randomBytes(32).toString('hex')
  APPROVAL_NONCE_HEX_LENGTH: 64,
} as const;

/**
 * The only environment variable that may change the manual-approval window.
 *
 * Declared here so the daemon's env allow-list (src/cli/daemon/state.ts) and the
 * resolver that enforces it cannot drift; the resolver clamps whatever it reads
 * into LIMITS.APPROVAL_TIMEOUT_MIN_MS..LIMITS.APPROVAL_TIMEOUT_MAX_MS.
 */
export const APPROVAL_TIMEOUT_ENV_VAR = 'SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS';

/**
 * Whether a per-session MAC is mandatory on inbound envelopes.
 *
 * Fail closed: an envelope with no MAC is rejected. A relay that has not yet
 * implemented envelope signing therefore cannot drive the agent at all, which
 * is the intended behaviour — the alternative (defaulting to "accept unsigned")
 * preserves the C-04 vulnerability for every existing deployment.
 */
export const ENVELOPE_MAC_REQUIRED_DEFAULT = true;

/** HKDF suite used to turn a data-channel token into an envelope MAC key. */
export const ENVELOPE_MAC_KDF = {
  digest: 'sha256',
  saltLabel: 'sw-agent/v1/envelope-mac/salt',
  infoLabel: 'sw-agent/v1/envelope-mac/info',
  keyBytes: 32,
} as const;

/**
 * Anti-replay nonces are opaque to the connector; it only requires them to be
 * unique per session and unguessable enough not to collide across sessions.
 */
export const ENVELOPE_NONCE_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;

/** Approval nonces are 32 random bytes, lowercase hex. */
export const APPROVAL_NONCE_PATTERN = /^[0-9a-f]{64}$/;
