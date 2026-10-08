import { Role } from '../protocol/envelope';
import { PermissionLevel } from '../permissions/types';

export type AuditAction =
  | 'query'
  | 'stream_query'
  | 'migration_run'
  | 'cancel'
  | 'introspect'
  | 'plan_register'
  | 'manual_approval'
  | 'audit_overflow';

export type AuditDecision = 'allow' | 'deny' | 'pending' | 'approved' | 'rejected' | 'expired';

export type AuditOutcome = 'success' | 'error' | 'cancelled' | 'n/a';

/**
 * Who caused a record to exist.
 *
 * `user` — a principal asserted by the cloud, with `role` and
 * `permission_level` as asserted values.
 * `system` — the agent itself (buffer pressure, lifecycle, internal
 * conditions). System records MUST NOT carry a principal role.
 * `local` — initiated by the operator on this host, from `sw-agent db query`
 * or `sw-agent db test`. A `local` record carries NO cloud-asserted identity:
 * the `role` field is the agent's own choice of authority for a local shell,
 * not a role the cloud ever asserted or verified. Without this member such a
 * record defaulted to `user` and was written as though a cloud principal
 * holding `role: 'admin'` had performed the action — the false-attestation
 * pattern audit finding C-03 is about, reintroduced on the local surface.
 */
export type AuditActor = 'user' | 'system' | 'local';

/**
 * A record's `role` field: a cloud-asserted principal role, or the literal
 * `system` for agent-generated records. Audit records never invent a
 * privileged role for the agent itself (audit finding L-06).
 */
export type AuditRole = Role | 'system';

/**
 * A record's `permission_level`: the effective, locally-resolved level for a
 * principal, or the literal `unknown` for agent-generated records. There is no
 * agent-generated permission level, so none is asserted.
 */
export type AuditPermissionLevel = PermissionLevel | 'unknown';

export interface AuditEvent {
  id: string;
  ts: string;
  agent_id: string;
  /**
   * The project the FRAME named. This is a caller-asserted string and it is
   * retained for continuity with the existing record shape — it is NOT evidence
   * of which database was touched. `resolved_db_alias` is that evidence.
   */
  project: string;
  /**
   * The `db_alias` the frame carried, exactly as sent.
   *
   * Recorded so a record that contradicts itself is legible: an asserted alias
   * that differs from `resolved_db_alias` is precisely the  condition, and
   * a verifier needs both halves to see it. Empty when the frame carried none.
   */
  db_alias_asserted?: string;
  /**
   * `db_alias` of the entry the request actually resolved to, as recorded by the
   * audit sink from the per-request resolved context (see
   * `withResolvedDatabase` in `src/audit/context.ts`), never from the frame.
   *
   * the trail used to carry `project` only, so a cross-database frame
   * executing under a false label left no field that could name the database it
   * really touched. `'unresolved'` is the fail-closed value and is what a
   * refusal — where nothing was resolved — carries.
   *
   * Optional in the type because hand-built fixtures and records written by a
   * build that predates the field still type-check; every record this build
   * writes has it, and it is inside the MAC either way
   * (`canonicalStringify` covers the whole record).
   */
  resolved_db_alias?: string;
  /**
   * Database **name** of the resolved entry, from the same context as
   * `resolved_db_alias`. `'unresolved'` when nothing was resolved.
   */
  resolved_database?: string;
  user_id: string;
  /** `user` for cloud-asserted principals, `local` for a host-local operator, `system` for agent-generated records. */
  actor: AuditActor;
  role: AuditRole;
  action: AuditAction;
  decision: AuditDecision;
  outcome: AuditOutcome;
  statement_fingerprint?: string;
  statement_preview?: string;
  permission_level: AuditPermissionLevel;
  denial_reason?: string;
  error_code?: string;
  duration_ms?: number;
  rows_affected?: number;
  rows_returned?: number;
  migration_plan_id?: string;
  /**
   * The principal whose in-flight request a `cancel` frame named.
   *
   * `user_id` on a cancel record is the CANCELLER, who is frequently not the
   * owner of the work being interrupted. Without this field the trail attributes
   * a cross-tenant cancellation to the attacker and says nothing about whose
   * request it was. Empty when the target carried no envelope.
   */
  cancel_target_user_id?: string;
  /** The TARGET's project, from the target's own frame. */
  cancel_target_project?: string;
  /** The TARGET's asserted `db_alias`, from the target's own frame. */
  cancel_target_db_alias?: string;
  /**
   * Monotonic position in the log. Starts at 1 and increments by exactly 1 per
   * record, across daemon restarts and file rotations. Gaps, regressions and
   * duplicates are tampering signals.
   */
  seq: number;
  /** Identity of the key that signed this chain. See `AUDIT_KEY_FILENAME`. */
  chain_id: string;
  prev_hash: string;
  /**
   * `HMAC-SHA256(key, canonical(event without mac/hash) || prev_hash)`, hex.
   * This is the tamper-evidence control: recomputing the chain requires the
   * installation key.
   */
  mac: string;
  /**
   * Legacy alias of {@link AuditEvent.mac}. Kept so existing readers (log
   * viewer, cloud ingest payload shape) keep working. Always equal to `mac`;
   * verification fails if the two disagree.
   */
  hash: string;
}

/**
 * The anchored head of the audit chain, persisted separately from the log in
 * `head.json` inside the audit directory.
 *
 * Without an expected head there is nothing outside the log to compare against,
 * so truncation, deletion and rollback are invisible. Verification MUST take the
 * head from `head.json` (or a copy an operator cannot reach).
 */
export interface AuditHead {
  /** Schema version of the head record. */
  v: 1;
  chain_id: string;
  /** Sequence number of the newest record. 0 means "nothing has been written". */
  seq: number;
  /** `mac` of the record at `seq`. Genesis hash when `seq` is 0. */
  last_hash: string;
  written_at: string;
  /**
   * Oldest sequence number still on disk, i.e. the first record the log can be
   * verified from. 1 unless rotation has evicted archives.
   *
   * The log is retained in a bounded number of files, so eventually the oldest
   * records are dropped on purpose. Verification must therefore start at this
   * sequence number, not at the genesis hash: a log that begins *later* than
   * this is truncated or rolled back, a log that begins at it is complete as
   * far as the retained window goes.
   */
  retained_from_seq?: number;
}

export interface AuditFilter {
  project?: string;
  user_id?: string;
  action?: AuditAction;
  decision?: AuditDecision;
  outcome?: AuditOutcome;
  since?: string;
  until?: string;
  limit?: number;
}

export interface AuditQueryResult {
  events: AuditEvent[];
  total: number;
  chain_intact: boolean;
  broken_at?: number;
  /** Machine-readable verification failure reason, when `chain_intact` is false. */
  chain_reason?: string;
  /** Human-readable detail for `chain_reason`. */
  chain_detail?: string;
  /** Records examined while verifying the chain. */
  chain_records?: number;
}

/** Observability surface for the local audit writer (audit finding C-06). */
export interface AuditWriterHealth {
  dir: string;
  active_path: string;
  /** True once the directory and file exist and the handle is open. */
  ready: boolean;
  /** False if the last append failed. Audit loss must never be silent. */
  writable: boolean;
  dir_mode: number | null;
  file_mode: number | null;
  /**
   * Oldest sequence number still on disk, or null when no record is retained.
   * Advances when rotation evicts the oldest archive.
   */
  retained_from_seq: number | null;
  last_write_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  error_count: number;
  events_written: number;
  events_failed: number;
  bytes_written: number;
  rotations: number;
}

/** Observability surface for the audit sink (audit findings C-05, C-06, M-04). */
export interface AuditSinkHealth extends AuditWriterHealth {
  chain_id: string | null;
  /** Sequence number of the newest record this process has written. */
  seq: number;
  chain_error: string | null;
  /**
   * Records waiting in the sink's bounded queue.
   *
   * Hard-capped at `AuditSinkOptions.maxQueueItems`: past it the oldest are
   * dropped. Records that take the write lane directly (`logSync()`, and any
   * `allow`/`deny`) are held by their caller and are never counted here — that is
   * what makes the cap a real bound on the sink's own memory.
   */
  queue_depth: number;
  /** Records admitted above the queue high-water mark (`bufferSize`). */
  overflow_admitted: number;
  /**
   * Records actually lost, because the bounded queue overflowed.
   *
   * A non-zero value is audit loss and is never silent: the same count is
   * persisted as an `audit_overflow` record and handed to `onDrop`. It stays 0
   * for `allow`/`deny` records and for `logSync()` — those are never queued, so no
   * queue policy can drop them.
   */
  dropped: number;
}
