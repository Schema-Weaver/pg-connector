import * as crypto from 'crypto';
import {
  AUDIT_FLOOR_SUFFIX,
  computeMac,
  decodeKeyMaterial,
  deriveChainId,
  GENESIS_HASH,
  loadAuditKey,
  makeHead,
  readHead,
  readHeadFloor,
  resolveAnchor,
  writeHead,
  writeHeadFloor,
  macInputOf,
  AuditKeyError,
  ChainVerifier,
  type AuditKey,
} from './chain';
import { LocalAuditWriter } from './local-writer';
import { CloudAuditWriter } from './cloud-writer';
import {
  AuditActor,
  AuditDecision,
  AuditEvent,
  AuditFilter,
  AuditHead,
  AuditQueryResult,
  AuditSinkHealth,
} from './types';
import { currentResolvedDbIdentity, withResolvedDatabase, type ResolvedDbIdentity } from './context';

/**
 * Fields the sink fills in itself; a caller supplies only the facts it knows.
 *
 * `resolved_db_alias`/`resolved_database` are deliberately NOT part of what a
 * caller may supply: they are stamped by the sink from the per-request resolved
 * context (`withResolvedDatabase`), so a call site cannot record the frame's
 * claimed database and call it resolved.
 */
export type PendingEvent = Omit<
  AuditEvent,
  | 'id'
  | 'ts'
  | 'agent_id'
  | 'seq'
  | 'chain_id'
  | 'prev_hash'
  | 'mac'
  | 'hash'
  | 'actor'
  | 'resolved_db_alias'
  | 'resolved_database'
> & {
  id?: string;
  /**
   * `user` (default) for cloud-asserted principals, `local` for a host-local
   * operator, `system` for agent records. An absent value stays `user`, so
   * every pre-existing call site keeps its meaning.
   */
  actor?: AuditActor;
};

export interface AuditSinkOptions {
  agentId: string;
  localWriter: LocalAuditWriter;
  cloudWriter: CloudAuditWriter;
  bufferSize?: number;
  /**
   * Hard cap on **queued** records. Past it the **oldest** are dropped, because
   * an unbounded queue under sustained write pressure is unbounded memory in the
   * daemon — the same defect class `CloudClient.maxQueueItems` closes (finding
   * M-07). Default 4096.
   *
   * Only records that carry no authorization decision are ever queued (see
   * {@link AuditSink}), so this bounds the sink's own memory no matter how much
   * decision traffic arrives. It is clamped to at least `bufferSize`.
   */
  maxQueueItems?: number;
  /**
   * Called whenever queued records are dropped instead of written. Mirrors
   * `CloudClient.onDrop`: the counter in {@link AuditSink.getHealth} is the
   * marker, and an owner with a durable log elsewhere can record the loss.
   * Never allowed to throw into the write path.
   */
  onDrop?: (drop: AuditDrop) => void;
  /** Directory holding `audit.key`. Defaults to the agent home. */
  keyDir?: string;
  /** Explicit HMAC key (32-byte Buffer, or 64 hex chars). Overrides `keyDir`. */
  key?: Buffer | string;
  /** Upper bound on records scanned by `query()`. Default 200000. */
  maxScanRecords?: number;
}

/** Why a queued record was dropped instead of written. */
export type AuditDropReason = 'queue_overflow';

export interface AuditDrop {
  /** How many records were dropped in this event. */
  count: number;
  reason: AuditDropReason;
  /** Queue depth after the drop. */
  queueDepth: number;
  /** The hard cap that was hit. */
  maxQueueItems: number;
}

interface QueueEntry {
  work: () => Promise<void>;
  resolve: () => void;
  reject: (err: unknown) => void;
}

const DEFAULT_BUFFER_SIZE = 1024;
const DEFAULT_MAX_SCAN_RECORDS = 200_000;
/** Hard cap on queued records. See {@link AuditSinkOptions.maxQueueItems}. */
const DEFAULT_MAX_QUEUE_ITEMS = 4_096;
/** Report the queue high-water mark after this many overflow admissions. */
const OVERFLOW_REPORT_THRESHOLD = 64;
/** Re-announce a growing drop total at these multiples. */
const DROP_REPORT_INTERVAL = 64;

/**
 * The audit sink: builds keyed, sequenced records, appends them locally and
 * mirrors them to the cloud.
 *
 * Chain integrity rules:
 *   - every record is MAC'd with the installation key and stamped with a
 *     monotonically increasing `seq`
 *   - `{seq, last_hash}` is anchored in `head.json` at every durable commit
 *   - the head is recovered on first append (from `head.json` plus the tail of
 *     the newest log file), so a restart continues the chain instead of
 *     restarting it (finding H-13)
 *   - a tail that does not verify is a loud, exposed failure — never a silent
 *     new chain in the same file
 *
 * Buffer pressure (findings M-04, M-07): every write is serialised through one
 * FIFO write lane, which is what keeps `seq`/`prev_hash` coherent. Records split
 * by how they reach that lane:
 *   - **never queued** — `logSync()` (an awaited record) and any record carrying
 *     an authorization decision (`allow`/`deny`). They take the write lane
 *     directly, so no amount of pressure can drop one, reject one, or make its
 *     caller wait for queue space. This is the guaranteed path.
 *   - **queued** — fire-and-forget `log()` records with no authorization
 *     decision (manual-approval lifecycle telemetry). The queue is hard-capped
 *     at `maxQueueItems`; past it the **oldest** are dropped and counted, so
 *     sustained pressure cannot grow the heap without bound.
 *
 * A full queue is therefore not an error and never rejects a caller; the loss is
 * counted (`getHealth().dropped`), logged, persisted as an `audit_overflow`
 * record and handed to `onDrop`.
 *
 * Every record also carries the **resolved** database identity
 * (`resolved_db_alias`, `resolved_database`), taken from the per-request context
 * established by `withResolvedDatabase` and never from the caller. With
 * no context established the value is the fail-closed `'unresolved'`.
 */
export class AuditSink {
  private readonly opts: Required<Omit<AuditSinkOptions, 'key' | 'onDrop'>> & {
    key?: Buffer | string;
    onDrop?: (drop: AuditDrop) => void;
  };
  private queue: QueueEntry[] = [];
  private draining = false;
  private pendingFlush: (() => void) | null = null;

  /**
   * FIFO serialisation for every record write. Admission order is chain order;
   * a lane slot is held only for the duration of one append.
   */
  private writeLane: Promise<unknown> = Promise.resolve();
  /** Records admitted but not yet written, queued or straight through. */
  private pending = 0;

  private overflowPending = 0;
  private overflowTotal = 0;
  /** Drops since the last `audit_overflow` record was written. */
  private overflowDropped = 0;
  private dropped = 0;

  private chainInit: Promise<void> | null = null;
  private auditKey: AuditKey | null = null;
  private seq = 0;
  private lastHash = GENESIS_HASH;
  private head: AuditHead | null = null;
  /**
   * Oldest sequence number still on disk. Rotation evicts the oldest archives,
   * so verification starts here instead of at the genesis hash. Monotonic: it is
   * a promise about what the log retains.
   */
  private retainedFromSeq: number | null = null;
  /** Highest sequence number already anchored in the floor file. */
  private floorSeq = 0;
  private floorErrorReported: string | null = null;
  private chainError: string | null = null;
  private chainErrorReported: string | null = null;

  private eventsWritten = 0;
  private eventsFailed = 0;
  private writeErrorReported: string | null = null;

  constructor(opts: AuditSinkOptions) {
    const envBuffer = process.env.SW_AGENT_AUDIT_BUFFER;
    const parsedBuffer = envBuffer ? parseInt(envBuffer, 10) : Number.NaN;
    const bufferSize =
      opts.bufferSize ?? (Number.isFinite(parsedBuffer) ? parsedBuffer : DEFAULT_BUFFER_SIZE);
    const requestedMax = opts.maxQueueItems ?? DEFAULT_MAX_QUEUE_ITEMS;
    this.opts = {
      agentId: opts.agentId,
      localWriter: opts.localWriter,
      cloudWriter: opts.cloudWriter,
      bufferSize,
      // The queue cap is never allowed below the high-water mark it reports, and
      // never zero: a cap below `bufferSize` would drop a record that had not
      // even reached the mark that says pressure started.
      maxQueueItems: Math.max(
        1,
        bufferSize,
        Number.isFinite(requestedMax) && requestedMax > 0
          ? Math.floor(requestedMax)
          : DEFAULT_MAX_QUEUE_ITEMS,
      ),
      onDrop: opts.onDrop,
      keyDir: opts.keyDir ?? '',
      key: opts.key,
      maxScanRecords: opts.maxScanRecords ?? DEFAULT_MAX_SCAN_RECORDS,
    };

    // Anchor the chain head at every durable commit. The hook receives the
    // newest record that actually reached the disk, so the head can never be
    // written ahead of the data it describes.
    this.opts.localWriter.setCommitListener((last, retainedFromSeq) =>
      this.onDurableCommit(last, retainedFromSeq),
    );
  }

  /** Chain identity, once established. */
  get chainId(): string | null {
    return this.auditKey?.chain_id ?? null;
  }

  /**
   * Attribute every audit record written inside `fn` to a resolved database.
   *
   * A thin delegate to the module-level context store, exposed here because the
   * sink is where the contract lives: `log()`/`logSync()` read the identity from
   * that store, so this method is the only supported way to supply one. It does
   * not depend on sink instance state, which is what lets a caller that holds a
   * hand-rolled sink in a test still get the same record shape.
   */
  withResolvedDatabase<T>(identity: ResolvedDbIdentity, fn: () => T): T {
    return withResolvedDatabase(identity, fn);
  }

  /** Sequence number of the newest record this instance has written. */
  get currentSeq(): number {
    return this.seq;
  }

  /* ---------------------------------------------------------------- */
  /* Public API                                                        */
  /* ---------------------------------------------------------------- */

  /**
   * Fire-and-forget append. The record is written and committed by the next
   * group commit; it is not guaranteed durable when this returns.
   *
   * A record that carries an authorization decision (`allow`/`deny`) bypasses
   * the bounded queue and takes the write lane directly: a decision is never
   * droppable and never waits for queue space. Everything else is queued and is
   * subject to the `maxQueueItems` drop-oldest policy.
   */
  log(partial: PendingEvent): void {
    if (isAuthorizationDecision(partial.decision)) {
      void this.writeThrough(partial, false).catch(() => undefined);
      return;
    }
    // drain() counts and reports the failure; the catch only keeps the rejection
    // from becoming an unhandled rejection — including the rejection a dropped
    // entry produces, which `reportDrop` has already counted and surfaced.
    void this.enqueueQueued(() => this.record(partial, false)).catch(() => undefined);
  }

  /**
   * Awaited append. Resolves only once the record (and the chain head that
   * anchors it) is fsync'd. A write failure rejects — audit loss is never
   * swallowed on this path.
   *
   * Never queued: buffer pressure can neither reject this call nor drop the
   * record (finding M-04). The caller waits for its own append, never for queue
   * room, so the wait is bounded by one write rather than by the backlog.
   */
  async logSync(partial: PendingEvent): Promise<void> {
    await this.writeThrough(partial, true);
  }

  async flush(): Promise<void> {
    if (this.queue.length > 0 || this.draining || this.pending > 0) {
      await new Promise<void>((resolve) => {
        this.pendingFlush = resolve;
        void this.drain();
      });
    }
    await this.opts.localWriter.flush();
  }

  /**
   * Filters the log and verifies the chain in the same streaming pass, so a full
   * history is never materialised (finding M-06).
   */
  async query(filter: AuditFilter): Promise<AuditQueryResult> {
    const limit = Math.min(filter.limit ?? 100, 1000);
    const sinceTs = filter.since ? new Date(filter.since).getTime() : null;
    const untilTs = filter.until ? new Date(filter.until).getTime() : null;

    const events: AuditEvent[] = [];
    let total = 0;
    let scanned = 0;

    const verifier = await this.buildVerifier();
    for await (const event of this.opts.localWriter.stream({
      maxRecords: this.opts.maxScanRecords,
    })) {
      scanned++;
      if (verifier && !verifier.failed) {
        verifier.push(event);
      }
      if (!matchesFilter(event, filter, sinceTs, untilTs)) continue;
      total++;
      if (events.length < limit) events.push(event);
    }

    if (!verifier) {
      return {
        events,
        total,
        chain_intact: false,
        chain_reason: this.chainError ? 'chain_broken' : 'key_unavailable',
        chain_detail: this.chainError ?? 'no audit key; the chain could not be verified',
        chain_records: scanned,
      };
    }

    const result = verifier.result(this.currentAnchor());
    return {
      events,
      total,
      chain_intact: result.intact,
      broken_at: result.brokenAt,
      chain_reason: result.reason,
      chain_detail: result.detail,
      chain_records: result.events,
    };
  }

  /**
   * The strongest claim about where the chain ends: this process's head plus the
   * monotonic floor, which a second process (or a restored backup) may have moved
   * further than the in-memory head.
   */
  private currentAnchor(): AuditHead | null {
    const dir = this.opts.localWriter.dir;
    const resolved = resolveAnchor([
      { head: this.head, source: 'head.json' },
      { head: readHeadFloor(dir), source: `head${AUDIT_FLOOR_SUFFIX}` },
    ]);
    if (resolved.conflict && this.chainError === null) {
      this.chainError = resolved.conflict;
      this.reportChainError(resolved.conflict);
    }
    return resolved.anchor;
  }

  getHealth(): AuditSinkHealth {
    return {
      ...this.opts.localWriter.getHealth(),
      chain_id: this.auditKey?.chain_id ?? null,
      seq: this.seq,
      retained_from_seq: this.retainedFromSeq,
      chain_error: this.chainError,
      // The bounded queue. This is the sink's own memory footprint, and it is
      // hard-capped at `maxQueueItems`; records that take the write lane directly
      // are held by their caller, not by the sink.
      queue_depth: this.queue.length,
      overflow_admitted: this.overflowTotal,
      dropped: this.dropped,
    };
  }

  /* ---------------------------------------------------------------- */
  /* Chain management                                                  */
  /* ---------------------------------------------------------------- */

  /**
   * Establishes the key and recovers the chain head. Idempotent; the promise is
   * memoised so concurrent appends share one recovery.
   */
  private ensureChain(): Promise<void> {
    if (this.chainError) {
      return Promise.reject(new Error(this.chainError));
    }
    if (!this.chainInit) {
      this.chainInit = this.initChain().catch((err) => {
        // A failed attempt is retried on the next append — an unwritable
        // directory is an environment problem, not a chain-integrity problem.
        // A key that cannot be established, however, will not fix itself and is
        // latched so every caller sees the same loud reason.
        this.chainInit = null;
        if (err instanceof AuditKeyError) {
          const message = `audit chain not established: ${err.message}`;
          this.chainError = message;
          this.reportChainError(message);
        }
        throw err;
      });
    }
    return this.chainInit;
  }

  private async initChain(): Promise<void> {
    const dir = this.opts.localWriter.dir;
    // Repair a directory left untraversable before anything touches it,
    // including the head file.
    await this.opts.localWriter.prepare();
    const head = readHead(dir);
    // The floor is a second, independent claim about the same chain. Either one
    // can be rolled back together with the log; together they cannot.
    const floor = readHeadFloor(dir);
    const anchor = resolveAnchor([
      { head, source: 'head.json' },
      { head: floor, source: `head${AUDIT_FLOOR_SUFFIX}` },
    ]).anchor;
    const key = this.establishKey(anchor);
    this.auditKey = key;
    this.floorSeq = floor && floor.chain_id === key.chain_id ? floor.seq : 0;

    // Recover from the log itself: head.json can be a commit behind after a
    // crash, and a rotated active file may be empty right after a rotation.
    const tail = await this.opts.localWriter.readTailEvent();

    // Reconcile the retention floor with what is actually on disk. `max()`
    // keeps it monotonic and self-heals a crash between the log write and the
    // head write, which legitimately leaves the head behind.
    const onDisk = this.opts.localWriter.getRetentionFloor();
    const anchored = anchor?.retained_from_seq ?? null;
    this.retainedFromSeq = Math.max(anchored ?? 0, onDisk ?? 0) || null;

    if (tail) {
      const problem = this.inspectTail(tail, key);
      if (problem) {
        this.failChain(problem);
        return;
      }
      this.seq = tail.seq;
      this.lastHash = tail.mac;
      if (anchor && anchor.chain_id !== key.chain_id) {
        this.failChain(
          `anchored head belongs to chain ${anchor.chain_id} but this installation signs with ${key.chain_id}`,
        );
        return;
      }
      if (anchor && anchor.seq > tail.seq) {
        this.failChain(
          `an anchor is at seq ${anchor.seq} but the log ends at seq ${tail.seq} — the log was truncated or rolled back`,
        );
        return;
      }
    } else if (anchor && anchor.seq > 0) {
      this.failChain(
        `an anchor claims seq ${anchor.seq} but no record is readable — the log was deleted`,
      );
      return;
    } else {
      this.seq = 0;
      this.lastHash = GENESIS_HASH;
    }

    // Repair/establish the anchors. Written after the durable data, so a crash
    // in between leaves the anchors behind — never ahead.
    this.persistHead(this.seq, this.lastHash, true);
  }

  private establishKey(head: AuditHead | null): AuditKey {
    const explicit = this.opts.key;
    if (explicit !== undefined && explicit !== null) {
      const bytes = Buffer.isBuffer(explicit) ? explicit : decodeKeyMaterial(explicit);
      return {
        key: bytes,
        chain_id: head?.chain_id ?? deriveChainId(bytes),
        source: 'env',
        origin: 'explicit',
      };
    }
    return loadAuditKey({
      dir: this.opts.keyDir || undefined,
      create: true,
      chainId: head?.chain_id ?? null,
    });
  }

  /**
   * Validates the tail record against the key. Returns a problem description,
   * or null when the tail is a legitimate continuation point.
   */
  private inspectTail(tail: AuditEvent, key: AuditKey): string | null {
    if (tail.chain_id !== key.chain_id) {
      return `log tail is chain ${tail.chain_id} but this installation signs with ${key.chain_id} — the key was replaced`;
    }
    if (typeof tail.seq !== 'number' || !Number.isInteger(tail.seq) || tail.seq < 1) {
      return 'log tail record has no usable sequence number';
    }
    if (typeof tail.mac !== 'string' || tail.hash !== tail.mac) {
      return 'log tail record is malformed (missing or inconsistent mac)';
    }
    let expected: string;
    try {
      expected = computeMac(macInputOf(tail), key.key);
    } catch (err: unknown) {
      return `log tail record could not be verified: ${err instanceof Error ? err.message : String(err)}`;
    }
    if (expected !== tail.mac) {
      return 'log tail record does not match its mac — the log has been modified';
    }
    return null;
  }

  /**
   * Refuses to continue on a chain that does not verify. Throwing here is the
   * point: the alternative — starting a fresh chain in the same file — would
   * silently erase the evidence of the damage.
   */
  private failChain(problem: string): never {
    this.chainError = problem;
    this.reportChainError(problem);
    throw new Error(problem);
  }

  private reportChainError(problem: string): void {
    if (this.chainErrorReported === problem) return;
    this.chainErrorReported = problem;
    console.error(
      `[audit] CHAIN BROKEN: ${problem}. Audit records are being REJECTED rather than written to a ` +
        'chain that no longer verifies. Inspect the audit directory and restore from a backup before resuming.',
    );
  }

  private onDurableCommit(last: AuditEvent | null, retainedFromSeq: number | null): void {
    if (!this.auditKey) return;
    if (typeof retainedFromSeq === 'number') {
      this.retainedFromSeq =
        this.retainedFromSeq === null
          ? retainedFromSeq
          : Math.max(this.retainedFromSeq, retainedFromSeq);
    }
    if (!last) return;
    this.persistHead(last.seq, last.mac, true);
  }

  private persistHead(seq: number, lastHash: string, sync: boolean): void {
    if (!this.auditKey) return;
    const head = makeHead(seq, lastHash, this.auditKey.chain_id, this.retainedFromSeq);
    writeHead(this.opts.localWriter.dir, head, { sync });
    this.head = head;
    // The floor is advanced after the head, so a crash can only leave it behind
    // the log. It is skipped when it is already at or beyond this sequence
    // number, which is every call but the first of a session.
    if (seq <= this.floorSeq) return;
    try {
      writeHeadFloor(this.opts.localWriter.dir, head, { sync });
      this.floorSeq = seq;
    } catch (err: unknown) {
      // The records are durable and `head.json` is anchored; only the second,
      // independent claim is missing. That reduces rollback detection to
      // `head.json` alone — worth saying out loud, but not worth refusing to
      // record anything over, so the memo is left unadvanced and the next commit
      // retries.
      this.reportFloorError(err);
    }
  }

  private reportFloorError(err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    if (this.floorErrorReported === message) return;
    this.floorErrorReported = message;
    console.error(
      `[audit] CHAIN ANCHOR DEGRADED: ${message}. Records are still being written and head.json is still ` +
        'anchored, but detecting a rollback now relies on head.json alone. Fix the anchor file and this ' +
        'recovers on the next record.',
    );
  }

  private buildEvent(partial: PendingEvent): AuditEvent {
    const key = this.auditKey;
    if (!key) {
      throw new Error('audit chain key is not established');
    }
    const seq = this.seq + 1;
    const prev_hash = this.lastHash;
    // The resolved identity comes from the request context, never from the
    // call site. With no context established this is the fail-closed
    // `'unresolved'` value: a record must never claim a database it did not
    // resolve.
    const identity = currentResolvedDbIdentity();

    const base = {
      id: partial.id || crypto.randomUUID(),
      ts: new Date().toISOString(),
      agent_id: this.opts.agentId,
      project: partial.project,
      resolved_db_alias: identity.resolved_db_alias,
      resolved_database: identity.resolved_database,
      user_id: partial.user_id,
      actor: partial.actor ?? 'user',
      role: partial.role,
      action: partial.action,
      decision: partial.decision,
      outcome: partial.outcome,
      permission_level: partial.permission_level,
      seq,
      chain_id: key.chain_id,
      prev_hash,
    };

    // Optional fields are only set when present: an explicit `undefined` would
    // canonicalise differently before and after the JSON round trip, and the
    // MAC would then never verify.
    const event: AuditEvent = { ...base, mac: '', hash: '' };
    if (partial.db_alias_asserted !== undefined)
      event.db_alias_asserted = partial.db_alias_asserted;
    if (partial.statement_fingerprint !== undefined)
      event.statement_fingerprint = partial.statement_fingerprint;
    if (partial.statement_preview !== undefined)
      event.statement_preview = partial.statement_preview;
    if (partial.denial_reason !== undefined) event.denial_reason = partial.denial_reason;
    if (partial.error_code !== undefined) event.error_code = partial.error_code;
    if (partial.duration_ms !== undefined) event.duration_ms = partial.duration_ms;
    if (partial.rows_affected !== undefined) event.rows_affected = partial.rows_affected;
    if (partial.rows_returned !== undefined) event.rows_returned = partial.rows_returned;
    if (partial.migration_plan_id !== undefined)
      event.migration_plan_id = partial.migration_plan_id;
    if (partial.cancel_target_user_id !== undefined)
      event.cancel_target_user_id = partial.cancel_target_user_id;
    if (partial.cancel_target_project !== undefined)
      event.cancel_target_project = partial.cancel_target_project;
    if (partial.cancel_target_db_alias !== undefined)
      event.cancel_target_db_alias = partial.cancel_target_db_alias;

    const mac = computeMac(event, key.key);
    event.mac = mac;
    event.hash = mac;
    return event;
  }

  private async record(partial: PendingEvent, durable: boolean): Promise<void> {
    await this.ensureChain();
    const event = this.buildEvent(partial);
    await this.opts.localWriter.append(event, { durable });
    this.seq = event.seq;
    this.lastHash = event.mac;
    this.eventsWritten++;
    this.writeErrorReported = null;
    void this.opts.cloudWriter.log(event).catch((err) => {
      console.error('[audit] cloud write failed:', err);
    });
  }

  private async buildVerifier(): Promise<ChainVerifier | null> {
    try {
      await this.ensureChain();
    } catch {
      return null;
    }
    if (!this.auditKey) return null;
    return new ChainVerifier(this.auditKey.key, {
      chainId: this.auditKey.chain_id,
      expectedSeq: this.retainedFromSeq ?? 1,
    });
  }

  /* ---------------------------------------------------------------- */
  /* Queue and write lane                                              */
  /* ---------------------------------------------------------------- */

  /**
   * Serialises every record write. This is what keeps `seq`, `prev_hash` and the
   * anchored head consistent, and it is FIFO, so records enter the chain in
   * admission order.
   *
   * A lane slot is held for the duration of one append only, which is what lets
   * a decision record overtake queued telemetry instead of waiting behind it.
   */
  private runInWriteLane<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.writeLane.then(fn, fn);
    this.writeLane = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }

  /**
   * Records an admission: takes a slot in the outstanding-work count and, if
   * the high-water mark is already exceeded, books an overflow admission. Every
   * entry point (queued or straight through) goes through here, so the reported
   * count describes the real backlog rather than one particular lane.
   */
  private admit(): void {
    if (this.pending >= this.opts.bufferSize) {
      this.overflowPending++;
    }
    this.pending++;
  }

  /**
   * The guaranteed path: straight to the write lane, never queued.
   *
   * Nothing here can be dropped or rejected for buffer pressure, and the caller
   * never waits for queue room — only for its own append.
   */
  private async writeThrough(partial: PendingEvent, durable: boolean): Promise<void> {
    this.admit();
    try {
      await this.runInWriteLane(() => this.record(partial, durable));
    } finally {
      this.pending--;
      try {
        await this.reportOverflowIfDue();
      } finally {
        this.settleIfIdle();
      }
    }
  }

  /**
   * Queues a fire-and-forget, non-decision record.
   *
   * A full queue is *not* an error and never rejects the caller for pressure:
   * the **oldest** entries are dropped to make room (drop-oldest, matching
   * `CloudClient.maxQueueItems`, finding M-07) and every drop is counted,
   * logged, persisted and handed to `onDrop`. Rejecting in-flight callers
   * instead turned buffer pressure into a global query-kill switch and dropped
   * the denial records that matter most (finding M-04).
   *
   * Only records that carry no authorization decision reach here — see
   * {@link AuditSink.log} — so the eviction can never touch an allow/deny.
   */
  private enqueueQueued(work: () => Promise<void>): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (this.queue.length >= this.opts.maxQueueItems) {
        const excess = this.queue.length - this.opts.maxQueueItems + 1;
        const evicted = this.queue.splice(0, excess);
        this.pending -= evicted.length;
        this.reportDrop({
          count: evicted.length,
          reason: 'queue_overflow',
          queueDepth: this.queue.length,
          maxQueueItems: this.opts.maxQueueItems,
        });
        for (const entry of evicted) {
          entry.reject(
            new Error(
              `audit queue overflow: ${evicted.length} queued record(s) dropped to stay within ` +
                `maxQueueItems=${this.opts.maxQueueItems}`,
            ),
          );
        }
      }
      this.admit();
      this.queue.push({ work, resolve, reject });
      void this.drain();
    });
  }

  /**
   * Single serial worker for the queue.
   *
   * Work queued while the worker is shutting down must not be lost: the queue is
   * re-checked immediately after `draining` is cleared, with no `await` in
   * between, so an entry can never be stranded with nobody left to run it.
   */
  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;

    try {
      while (this.queue.length > 0) {
        const entry = this.queue.shift()!;
        try {
          // Through the lane, one slot at a time: a decision record admitted
          // while this entry waited goes in ahead of it rather than behind the
          // whole backlog.
          await this.runInWriteLane(entry.work);
          entry.resolve();
        } catch (err: unknown) {
          this.eventsFailed++;
          this.reportWriteError(err);
          entry.reject(err);
        } finally {
          this.pending--;
        }
        await this.reportOverflowIfDue();
      }
      await this.reportOverflowIfDue(true);
    } finally {
      // No `await` between clearing `draining` and re-checking the queue: an
      // entry queued while the worker was shutting down can never be stranded.
      this.draining = false;
      if (this.queue.length > 0) {
        void this.drain();
      } else {
        this.settleIfIdle();
      }
    }
  }

  /**
   * Releases a waiting `flush()` once nothing is outstanding — no queued entry,
   * no write in flight. Straight-through records call this as they settle, so a
   * flush cannot return while a decision record is still being written.
   */
  private settleIfIdle(): void {
    if (!this.pendingFlush) return;
    if (this.draining || this.queue.length > 0 || this.pending > 0) return;
    const resolve = this.pendingFlush;
    this.pendingFlush = null;
    resolve();
  }

  /**
   * Writes the queue-pressure record: how many records were admitted above the
   * high-water mark, and how many were dropped outright. Both numbers are read
   * before they are reset (the previous code reset first, so the record always
   * reported the wrong number).
   */
  private async reportOverflowIfDue(final = false): Promise<void> {
    if (this.overflowPending === 0 && this.overflowDropped === 0) return;
    if (
      !final &&
      this.pending >= this.opts.bufferSize &&
      this.overflowPending + this.overflowDropped < OVERFLOW_REPORT_THRESHOLD
    ) {
      return;
    }
    const admitted = this.overflowPending;
    const dropped = this.overflowDropped;
    this.overflowPending = 0;
    this.overflowDropped = 0;
    this.overflowTotal += admitted;

    const event: PendingEvent = {
      actor: 'system',
      action: 'audit_overflow',
      decision: 'deny',
      outcome: 'n/a',
      denial_reason: 'buffer_overflow',
      project: '__system__',
      user_id: '__system__',
      role: 'system',
      permission_level: 'unknown',
      statement_preview:
        `${admitted} audit records were admitted above the queue high-water mark of ${this.opts.bufferSize}; ` +
        `${dropped} were dropped, and every allow/deny decision record is written straight through and never dropped`,
    };

    this.pending++;
    try {
      await this.runInWriteLane(() => this.record(event, false));
    } catch (err: unknown) {
      // The overflow record is itself audit data; if it cannot be written the
      // write error is already surfaced by record()'s caller path.
      this.reportWriteError(err);
    } finally {
      this.pending--;
    }
  }

  /**
   * Counts a drop, says so out loud, and hands it to the `onDrop` marker hook —
   * the same contract as `CloudClient.onDrop`. Audit loss is counted and
   * reported, never discarded quietly.
   */
  private reportDrop(drop: AuditDrop): void {
    this.dropped += drop.count;
    this.overflowDropped += drop.count;
    if (this.dropped === drop.count || this.dropped % DROP_REPORT_INTERVAL === 0) {
      console.error(
        `[audit] dropped ${drop.count} queued record(s) (${drop.reason}); queue at ` +
          `${drop.queueDepth}/${drop.maxQueueItems}, total dropped ${this.dropped}. Authorization ` +
          'decisions (allow/deny) are never queued, so no decision record is dropped this way.',
      );
    }
    try {
      this.opts.onDrop?.(drop);
    } catch (err: unknown) {
      console.error('[audit] drop marker hook failed:', err);
    }
  }

  /**
   * Complains once per distinct failure so audit loss is never silent. The
   * writer already announced a persistence failure, so this stays quiet rather
   * than printing the same problem twice.
   */
  private reportWriteError(err: unknown): void {
    const message = err instanceof Error ? err.message : String(err);
    if (this.writeErrorReported === message) return;
    this.writeErrorReported = message;
    if (this.opts.localWriter.getHealth().last_error === message) return;
    console.error(
      `[audit] write failed: ${message}. Audit records are being LOST. ` +
        'Check sw-agent status / the audit directory.',
    );
  }
}

/**
 * Whether `decision` is an authorization decision — the records that carry the
 * security-relevant "this was permitted / this was refused" claim.
 *
 * These are never queued, so no queue policy can drop them. Everything else
 * (`pending`/`approved`/`rejected`/`expired`, i.e. manual-approval lifecycle
 * telemetry) is queueable and droppable under sustained pressure.
 */
function isAuthorizationDecision(decision: AuditDecision): boolean {
  return decision === 'allow' || decision === 'deny';
}

function matchesFilter(
  event: AuditEvent,
  filter: AuditFilter,
  sinceTs: number | null,
  untilTs: number | null,
): boolean {
  if (filter.project && event.project !== filter.project) return false;
  if (filter.user_id && event.user_id !== filter.user_id) return false;
  if (filter.action && event.action !== filter.action) return false;
  if (filter.decision && event.decision !== filter.decision) return false;
  if (filter.outcome && event.outcome !== filter.outcome) return false;
  if (sinceTs !== null || untilTs !== null) {
    const ts = new Date(event.ts).getTime();
    if (sinceTs !== null && ts < sinceTs) return false;
    if (untilTs !== null && ts >= untilTs) return false;
  }
  return true;
}
