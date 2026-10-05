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
  APPROVAL_TIMEOUT_MS: 60_000,        // manual approval: 60s timeout
  IDLE_WSS_TIMEOUT_MS: 60_000,        // close WSS after 60s idle
  WAKE_KEEPALIVE_MS: 300_000,         // SSE keepalive every 5 min
  RECONNECT_BACKOFF_MS: [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000],
  ORPHAN_REQUEST_TIMEOUT_MS: 300_000, // 5 min: kill query if no reconnect
} as const;

export const LIMITS = {
  MAX_STATEMENT_COUNT_PER_MIGRATION: 500,
  MAX_STATEMENT_LENGTH: 1_048_576,    // 1MB per SQL statement
  MAX_PAYLOAD_BYTES: 16_777_216,      // 16MB per message (envelope + payload)
  ID_MAX_LENGTH: 64,
  PROJECT_MAX_LENGTH: 64,
  ALIAS_MAX_LENGTH: 64,
} as const;
