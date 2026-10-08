import * as crypto from 'crypto';
import { LOCK_TIMEOUT_MS, MAX_STATEMENT_TIMEOUT_MS, PoolManager, markSessionDirty } from './pool';
import { loadMachineConfig } from '../config/machine-config';
import { DbEntry } from '../config/db-config';
import { MigrationRunPayload, MigrationResultPayload } from '../protocol/messages';
import { InFlightRequest, SimpleResult, StatementResult, runExtended } from './types';
import { detectNonTransactional } from './non-tx-detector';
import { assertSingleReadStatement } from './statement-classifier';
import { previewStatement } from '../audit/redact';
import { sanitizeErrorText } from '../audit/sanitize';
import { DEFAULTS, LIMITS } from '../protocol/constants';
import { AgentMessage, Role } from '../protocol/envelope';

export class MigrationInProgressError extends Error {
  /** Error catalog code. Not a SQLSTATE: `safePgCode` requires exactly 5. */
  public readonly code = 'migration_in_progress';
  constructor(message: string) {
    super(message);
    this.name = 'MigrationInProgressError';
  }
}

export class MigrationStrategyConflictError extends Error {
  public readonly code = 'migration_strategy_conflict';
  constructor(message: string) {
    super(message);
    this.name = 'MigrationStrategyConflictError';
  }
}

/**
 * The plan could not be verified: something in it does not parse, contains
 * more than one statement, or is a statement form the agent cannot prove runs
 * inside a transaction block. The run is refused rather than guessed at.
 */
export class MigrationPlanUnsafeError extends Error {
  public readonly code = 'migration_plan_unsafe';
  constructor(message: string) {
    super(message);
    this.name = 'MigrationPlanUnsafeError';
  }
}

/**
 * The migration stopped partway with statements already committed.
 *
 * `MigrationRunner.run` never *resolves* with `status: 'partial'`: a caller
 * that only inspects a returned value can therefore never mistake a
 * half-applied schema for a success. The per-statement detail is on
 * {@link MigrationPartiallyAppliedError.result} for a caller that wants to
 * report it.
 */
export class MigrationPartiallyAppliedError extends Error {
  public readonly code = 'migration_partial';
  public readonly result: MigrationResultPayload;
  public readonly pg_error_code?: string;
  constructor(message: string, result: MigrationResultPayload) {
    super(message);
    this.name = 'MigrationPartiallyAppliedError';
    this.result = result;
    const failed = result.statements.find((s) => s.status === 'failed');
    this.pg_error_code = failed?.pg_error_code;
  }
}

/** The run exceeded its overall deadline and was abandoned. */
export class MigrationTimeoutError extends Error {
  public readonly code = 'migration_timeout';
  constructor(message: string) {
    super(message);
    this.name = 'MigrationTimeoutError';
  }
}

/**
 * Absolute ceiling on one migration statement, in milliseconds. A caller
 * cannot raise it, and it can never exceed the agent-wide statement ceiling in
 * `pool.ts` — nothing is allowed to turn `statement_timeout` off.
 */
export const MAX_MIGRATION_STATEMENT_TIMEOUT_MS = Math.min(
  DEFAULTS.MIGRATION_TIMEOUT_MS,
  MAX_STATEMENT_TIMEOUT_MS,
);

/** Absolute ceiling on the whole migration run, in milliseconds. */
export const MAX_MIGRATION_DEADLINE_MS = DEFAULTS.MIGRATION_TIMEOUT_MS;

/** How long a migration statement may wait for a lock before it is cancelled. */
export const MIGRATION_LOCK_TIMEOUT_MS = LOCK_TIMEOUT_MS;

export interface MigrationBudget {
  /** `statement_timeout` applied to every statement of the run. */
  statementTimeoutMs: number;
  /** Wall-clock budget for the whole run, enforced by the runner. */
  deadlineMs: number;
  /** `lock_timeout` applied to every statement of the run. */
  lockTimeoutMs: number;
}

/** PostgreSQL's SQLSTATE for a statement cancelled by a timeout or a cancel request. */
const PG_QUERY_CANCELED = '57014';

/**
 * Internal marker: the run was torn down by a cancellation or by the overall
 * deadline. It never leaves this module — callers see {@link
 * MigrationTimeoutError} or {@link MigrationPartiallyAppliedError}.
 */
class RunInterrupted extends Error {
  /** Which edge tore the run down. */
  public readonly reason: 'aborted' | 'deadline';
  constructor(reason: 'aborted' | 'deadline') {
    super(`migration run interrupted: ${reason}`);
    this.name = 'RunInterrupted';
    this.reason = reason;
  }
}

/**
 * The exact integer that reaches `SET statement_timeout = …`.
 *
 * The value is interpolated into SQL, so it is re-validated where it is used
 * instead of trusted from the caller: only a finite, positive, safe integer
 * survives, and anything else becomes the server-owned ceiling. Nothing a remote
 * caller can put in `timeout_ms` reaches the statement text verbatim, and a
 * clamped value can never be `0` — which PostgreSQL reads as "no timeout".
 */
function safeTimeoutMs(value: number, ceilingMs: number): number {
  if (!Number.isFinite(value) || !Number.isSafeInteger(value) || value <= 0) {
    return ceilingMs;
  }
  return Math.min(value, ceilingMs);
}

/**
 * Turn a caller-supplied `timeout_ms` into the three server-side budgets.
 *
 * The number is never trusted: it is floored to an integer, and clamped to
 * {@link MAX_MIGRATION_STATEMENT_TIMEOUT_MS} / {@link MAX_MIGRATION_DEADLINE_MS}.
 * `0`, a negative number, `NaN` and `Infinity` all mean "use the server
 * default" — never "no timeout", which is how a remote caller would otherwise
 * be able to remove the ceiling by asking for zero.
 */
export function resolveMigrationBudget(requestedTimeoutMs?: number): MigrationBudget {
  const requested =
    typeof requestedTimeoutMs === 'number' &&
    Number.isFinite(requestedTimeoutMs) &&
    requestedTimeoutMs > 0
      ? Math.floor(requestedTimeoutMs)
      : undefined;

  const statementTimeoutMs =
    requested === undefined
      ? MAX_MIGRATION_STATEMENT_TIMEOUT_MS
      : Math.min(requested, MAX_MIGRATION_STATEMENT_TIMEOUT_MS);
  const deadlineMs =
    requested === undefined
      ? MAX_MIGRATION_DEADLINE_MS
      : Math.min(requested, MAX_MIGRATION_DEADLINE_MS);

  return {
    statementTimeoutMs,
    deadlineMs,
    lockTimeoutMs: Math.min(MIGRATION_LOCK_TIMEOUT_MS, statementTimeoutMs),
  };
}

/**
 * Refuse a plan whose entries are not exactly one statement each.
 *
 * node-postgres takes the simple query protocol whenever `values` is falsy, and
 * that protocol executes *every* semicolon-separated statement in one round
 * trip. `SELECT 1; DROP TABLE users` is therefore two commands to PostgreSQL and
 * one string to everything above it — the C-01 mechanism, reachable through the
 * migration path.
 *
 * The verdict comes from the PostgreSQL parse tree, so a `;` inside a string
 * literal, a dollar-quoted body, a quoted identifier or a comment cannot trip
 * it, a single trailing terminator is not a second statement, and a real second
 * statement always is. Anything that does not parse exactly once is refused,
 * which also covers a plan written for a PostgreSQL version this agent cannot
 * parse: an unverifiable entry is never executed.
 */
async function assertOneStatementPerEntry(statements: string[]): Promise<void> {
  const offenders: number[] = [];
  for (let i = 0; i < statements.length; i++) {
    try {
      await assertSingleReadStatement(statements[i]);
    } catch {
      offenders.push(i);
    }
  }
  if (offenders.length === 0) return;
  throw new MigrationPlanUnsafeError(
    `Migration plan contains entries that are not exactly one statement ` +
      `(index ${offenders.map((i) => i + 1).join(', ')}). Refusing the plan: an entry that ` +
      'hides a second command behind a semicolon would be executed as two commands, and ' +
      'one the agent could not parse cannot be verified.',
  );
}

/**
 * Read the `locked` column of a `pg_try_advisory_*_lock` result.
 *
 * Only an explicit `true` counts as taken: a missing or non-boolean answer fails
 * closed, because a run that proceeded while believing it held the lock would
 * have no mutual exclusion at all.
 */
function lockTaken(res: SimpleResult): boolean {
  return (res.rows[0] as { locked?: unknown } | undefined)?.locked === true;
}

export interface MigrationRunnerOptions {
  poolManager: PoolManager;
  /**
   * Per-installation secret the advisory lock key is derived from. Defaults to
   * the agent token in the machine config, which is generated once per install
   * and never leaves the host.
   */
  lockSecret?: string;
}

export interface MigrationContext {
  dbEntry: DbEntry;
  request_id: string;
  project: string;
  user: { id: string; role: Role };
  db_alias: string;
  /** Called for each statement status change. */
  onProgress?: (event: AgentMessage) => void | Promise<void>;
  abortSignal?: AbortSignal;
  registerInFlight?: (req: InFlightRequest) => void;
  unregisterInFlight?: (request_id: string) => void;
}

/**
 * Advisory lock key for SW migrations.
 *
 * Keyed with HMAC-SHA256 over a per-installation secret. The previous version
 * hashed the project name with a bare MD5, so anybody who could guess (or was
 * told) a project name could compute the lock key, take the lock from another
 * session, and deny migrations for that project indefinitely. A keyed MAC is
 * not derivable by a third party with database access, because the secret never
 * reaches the database.
 */
export function advisoryLockKey(
  projectName: string,
  secret: string,
): { key1: number; key2: number } {
  const mac = crypto
    .createHmac('sha256', secret)
    .update(`schema-weaver:migration-lock:v1:${projectName}`)
    .digest();
  const key1 = mac.readInt32BE(0);
  let key2 = mac.readInt32BE(4);
  if (key1 === key2) {
    key2 = key1 === 0x7fffffff ? key1 - 1 : key1 + 1;
  }
  return { key1, key2 };
}

export class MigrationRunner {
  private readonly poolManager: PoolManager;
  private readonly injectedLockSecret?: string;
  private resolvedLockSecret: string | null = null;

  constructor(opts: MigrationRunnerOptions) {
    this.poolManager = opts.poolManager;
    this.injectedLockSecret = opts.lockSecret;
  }

  /**
   * The installation secret the lock key is keyed with.
   *
   * An explicit option wins (tests, embedders). Otherwise the agent token from
   * the machine config is used: it is per-installation, secret, and stable
   * across processes, which is exactly what mutual exclusion between two agents
   * needs. If the machine config cannot be read the fallback is a random
   * per-process secret — still unguessable from outside, so the lock key cannot
   * be pre-taken by anyone with database access.
   */
  private lockSecret(): string {
    if (this.injectedLockSecret && this.injectedLockSecret.length > 0) {
      return this.injectedLockSecret;
    }
    if (this.resolvedLockSecret !== null) return this.resolvedLockSecret;
    try {
      this.resolvedLockSecret = loadMachineConfig().agent_token;
    } catch {
      this.resolvedLockSecret = crypto.randomBytes(32).toString('hex');
    }
    return this.resolvedLockSecret;
  }

  async run(payload: MigrationRunPayload, ctx: MigrationContext): Promise<MigrationResultPayload> {
    const startTime = Date.now();

    // Step 1: Validate
    if (payload.statements.length === 0) {
      if (payload.dry_run) {
        return {
          plan_id: payload.plan_id,
          status: 'dry_run_ok',
          statements: [],
          total_ms: Date.now() - startTime,
          rolled_back_indices: [],
        };
      }
      throw new Error('Migration run payload contains no statements');
    }

    if (payload.statements.length > LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION) {
      throw new Error(
        `Migration statement count exceeds maximum limit (${LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION})`,
      );
    }

    for (const stmt of payload.statements) {
      if (!stmt.trim()) {
        throw new Error('Migration payload contains an empty statement');
      }
      if (Buffer.byteLength(stmt, 'utf8') > LIMITS.MAX_STATEMENT_LENGTH) {
        throw new Error(
          `Statement length exceeds maximum allowed limit (${LIMITS.MAX_STATEMENT_LENGTH})`,
        );
      }
    }

    // Step 2: Verify the plan before a connection or a lock is taken. Two
    // independent checks, both driven by the PostgreSQL parse tree and both
    // failing closed: every entry must be EXACTLY ONE statement, and every
    // entry must be one whose transactionality the agent can prove.
    await assertOneStatementPerEntry(payload.statements);

    const nonTxCheck = await detectNonTransactional(payload.statements);

    if (nonTxCheck.unparseable_indices.length > 0) {
      throw new MigrationPlanUnsafeError(
        `Migration plan contains statements that PostgreSQL cannot parse ` +
          `(index ${nonTxCheck.unparseable_indices.map((i) => i + 1).join(', ')}). ` +
          'Refusing to run an unverified plan.',
      );
    }

    if (nonTxCheck.ambiguous_indices.length > 0) {
      throw new MigrationPlanUnsafeError(
        `Migration plan contains statements that cannot be verified as transactional ` +
          `(index ${nonTxCheck.ambiguous_indices.map((i) => i + 1).join(', ')}): ` +
          `${nonTxCheck.summary}. Refusing to run an unverified plan.`,
      );
    }

    const strategy = payload.strategy;

    // Step 3: Dry run (parse only, no execution, no connection)
    if (payload.dry_run) {
      const statementResults: StatementResult[] = [];
      const conflictIndices = new Set(
        strategy === 'single_tx' ? nonTxCheck.non_tx_indices : ([] as number[]),
      );
      let allPassed = true;

      for (let i = 0; i < payload.statements.length; i++) {
        const stmt = payload.statements[i];
        const stmtStart = Date.now();

        if (conflictIndices.has(i)) {
          allPassed = false;
          statementResults.push({
            index: i,
            status: 'failed',
            ms: Date.now() - stmtStart,
            rows_affected: 0,
            error: `${nonTxCheck.summary} — strategy='single_tx' cannot run this plan`,
          });
          continue;
        }

        try {
          // Parse-only validation. The previous implementation executed
          // transactional DDL inside BEGIN/ROLLBACK against the production
          // database during a "dry run"; anything the classifier wrongly
          // called transactional really ran.
          await assertSingleReadStatement(stmt);

          statementResults.push({
            index: i,
            status: 'success',
            ms: Date.now() - stmtStart,
            rows_affected: 0,
          });
        } catch (err: unknown) {
          allPassed = false;
          statementResults.push({
            index: i,
            status: 'failed',
            ms: Date.now() - stmtStart,
            rows_affected: 0,
            error: err instanceof Error ? err.message : String(err),
            pg_error_code:
              err && typeof err === 'object' && 'code' in err
                ? String((err as Record<string, unknown>).code)
                : undefined,
          });
        }
      }

      return {
        plan_id: payload.plan_id,
        status: allPassed ? 'dry_run_ok' : 'dry_run_failed',
        statements: statementResults,
        total_ms: Date.now() - startTime,
        rolled_back_indices: [],
      };
    }

    // Previously the runner silently rewrote a caller-requested single_tx
    // migration into per_statement, which turns an all-or-nothing migration
    // into a sequence of individually-committed statements. A partial
    // migration leaves the schema half-applied and was reported as a success.
    // Now the conflict is an explicit error the caller must resolve. A dry run
    // reports it in the result instead of throwing, because that is what the
    // caller asked dry runs for.
    if (nonTxCheck.has_non_transactional && strategy === 'single_tx') {
      throw new MigrationStrategyConflictError(
        `Migration requested single_tx but contains statements that cannot run inside a ` +
          `transaction (${nonTxCheck.summary}). Re-submit with strategy='per_statement' ` +
          'if partial application is acceptable.',
      );
    }

    // Step 4: Budgets. Every statement runs under a server-controlled
    // statement_timeout and lock_timeout, and the run's own wall-clock deadline
    // is raced against each in-flight statement below, so the run cannot outlive
    // its deadline even if a single statement is slow. `timeout_ms` from the
    // caller is honoured but never trusted: `resolveMigrationBudget` clamps it.
    const budget = resolveMigrationBudget(payload.timeout_ms);

    // Step 5: Acquire a connection and take the advisory lock
    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);

    // A migration always leaves state that `release()` cannot undo: an open
    // transaction, session-level GUCs, a session-scoped advisory lock. Declaring
    // the session dirty HERE, before the first statement that can change it,
    // means the pool destroys the connection on every exit path — including an
    // exception thrown between BEGIN and the `finally` below — instead of
    // handing a half-used session to the next request. The cost is one
    // reconnect per migration.
    markSessionDirty(client);

    // The overall deadline starts once the backend is in hand: connection
    // setup is already bounded by the pool's connectionTimeoutMillis, and the
    // lock is taken with pg_try_advisory_* so it never blocks either.
    const deadlineAt = Date.now() + budget.deadlineMs;

    /**
     * Why the run was torn down early, if it was. `null` while it is healthy.
     * First cause wins: a deadline that expires while a cancellation is already
     * unwinding the run must not overwrite the reason its caller is waiting on.
     */
    let interruption: 'aborted' | 'deadline' | null = null;
    let rejectInterrupt: (reason: RunInterrupted) => void = () => undefined;
    /**
     * Rejects the instant the run is torn down. Every in-flight statement is
     * raced against it, which is what makes the deadline a bound on the run's
     * wall clock and not merely a check between statements: without the race a
     * single statement that outlives the budget is still waited out in full,
     * holding the advisory lock the whole time.
     */
    const interrupted = new Promise<never>((_resolve, reject) => {
      rejectInterrupt = reject;
    });
    // A run is usually torn down between statements, when nothing is racing
    // this promise, and a rejection nobody awaits is an unhandled rejection at
    // process level. Marking it handled here does not stop `Promise.race` from
    // seeing it later.
    void interrupted.catch(() => undefined);

    const interrupt = (cause: 'aborted' | 'deadline'): void => {
      if (interruption !== null) return;
      interruption = cause;
      rejectInterrupt(new RunInterrupted(cause));
    };

    const deadlineTimer = setTimeout(() => {
      interrupt('deadline');
    }, budget.deadlineMs);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      abort: abortController,
      is_streaming: false,
    };

    // The listener is attached BEFORE the request is registered, and a signal
    // that is already aborted is honoured immediately. An `abort` event that
    // fired before `addEventListener` never fires again, so a canceller that
    // aborts during registration (or a caller that hands in an aborted signal)
    // would otherwise be ignored and the run would execute in full and take the
    // advisory lock for a request nobody is waiting for.
    const onAbort = () => {
      // Abort whichever controller the canceller can reach: `registerInFlight`
      // hands it `inFlightRequest.abort`, and the dispatcher substitutes its own
      // controller there. Leaving that one unaborted would report
      // `local_abort: false` for a cancellation the runner did act on.
      if (!abortController.signal.aborted) abortController.abort();
      if (!inFlightReq.abort.signal.aborted) inFlightReq.abort.abort();
      interrupt('aborted');
    };

    if (ctx.abortSignal) {
      ctx.abortSignal.addEventListener('abort', onAbort);
    }
    if (ctx.abortSignal?.aborted) {
      onAbort();
    }

    // The canceller can only ever fire `InFlightRequest.abort`. It is observed
    // here as well, so a caller that keeps this runner's own controller instead
    // of substituting its own still stops the run instead of letting a
    // cancelled migration carry on to its commit.
    abortController.signal.addEventListener('abort', onAbort);

    if (ctx.registerInFlight) {
      ctx.registerInFlight(inFlightReq);
    }

    // `registerInFlight` can abort synchronously — the canceller, or a harness
    // standing in for it — and `signal.aborted` is the only trace that leaves,
    // so the state of both controllers is re-read after registration rather than
    // trusted to have produced an event.
    if (inFlightReq.abort.signal.aborted || ctx.abortSignal?.aborted === true) {
      interrupt('aborted');
    }

    const { key1, key2 } = advisoryLockKey(ctx.project, this.lockSecret());
    const statementResults: StatementResult[] = [];
    const rolledBackIndices: number[] = [];
    let migrationStatus: 'committed' | 'rolled_back' | 'partial' = 'committed';
    const outcome = (): 'committed' | 'rolled_back' | 'partial' => migrationStatus;
    let transactionOpen = false;
    let sessionLockHeld = false;
    let abandonedForDeadline = false;
    /**
     * A statement was still running on the backend when the run was torn down,
     * so the session may have state nobody can see. It is destroyed rather than
     * recycled, and the explicit unlock is skipped because it would be queued
     * behind the very statement that overran.
     */
    let statementAbandonedInFlight = false;
    let appliedStatementTimeout: number | null = null;

    /**
     * Topology that must not appear in anything this run puts on the wire.
     * Every error PostgreSQL raises quotes the row, the literal or the value it
     * choked on (`invalid input syntax for type integer: "alice@corp.com"`), and
     * a connection failure names the host, port, user and database.
     */
    const topology = {
      host: ctx.dbEntry.host,
      port: ctx.dbEntry.port,
      user: ctx.dbEntry.user,
      database: ctx.dbEntry.database,
      project: ctx.project,
    };

    /**
     * Progress event for one statement.
     *
     * The preview is redacted and the error text is scrubbed, because both leave
     * the process: a `migration_progress` event is a WebSocket frame bound for the
     * cloud and the browser. The verbatim message is still recorded on
     * {@link StatementResult.error} for the local audit log.
     */
    const emitProgress = (
      index: number,
      stmt: string,
      status: 'running' | 'success' | 'failed',
      extra?: { ms?: number; error?: string },
    ): void => {
      if (!ctx.onProgress) return;
      void ctx.onProgress({
        v: 1,
        id: crypto.randomUUID(),
        type: 'event',
        project: ctx.project,
        user: ctx.user,
        db_alias: ctx.db_alias,
        ts: Date.now(),
        payload: {
          kind: 'migration_progress',
          data: {
            plan_id: payload.plan_id,
            statement_index: index,
            statement_sql_preview: previewStatement(stmt),
            status,
            ...(extra?.ms !== undefined ? { ms: extra.ms } : {}),
            ...(extra?.error !== undefined
              ? { error: sanitizeErrorText(extra.error, { topology }) }
              : {}),
          },
        },
      });
    };

    /**
     * Apply the timeouts for the next statement. Inside `single_tx` this is
     * `SET LOCAL`, which PostgreSQL reverts at COMMIT/ROLLBACK; in
     * `per_statement` each statement is its own implicit transaction, so the
     * session form is the only one that takes effect — `SET LOCAL` outside a
     * transaction block is a silent no-op (H-07), which is how migrations used
     * to run with no timeout at all.
     *
     * The value is exactly the clamped budget, NOT the wall clock still left in
     * the run. Capping it by the remaining budget made the number PostgreSQL was
     * asked to enforce drift down by however long the run had already spent
     * taking its lock, so a caller that asked for 60000 got 59999 and every
     * statement of a long run got a different timeout than the one that was
     * requested and audited. The overall deadline is enforced by the runner
     * itself (`interrupted` above), which is what bounds the run — not by
     * shaving the server-side timeout.
     *
     * Both values are re-validated by {@link safeTimeoutMs} and the `LOCAL`
     * prefix is one of two literals, so this text cannot carry SQL. It still
     * goes over the extended protocol like every other statement, so no code
     * path in this file can silently acquire the simple protocol.
     */
    const applyBudget = async (): Promise<void> => {
      const statementTimeoutMs = safeTimeoutMs(
        budget.statementTimeoutMs,
        MAX_MIGRATION_STATEMENT_TIMEOUT_MS,
      );
      const lockTimeoutMs = safeTimeoutMs(budget.lockTimeoutMs, MIGRATION_LOCK_TIMEOUT_MS);
      const local = transactionOpen ? 'LOCAL ' : '';
      if (appliedStatementTimeout !== statementTimeoutMs) {
        await runExtended(client, `SET ${local}statement_timeout = ${statementTimeoutMs}`);
        await runExtended(client, `SET ${local}lock_timeout = ${lockTimeoutMs}`);
        appliedStatementTimeout = statementTimeoutMs;
      }
    };

    const markRolledBack = (upToIndex: number): void => {
      for (let j = 0; j < upToIndex; j++) {
        rolledBackIndices.push(j);
      }
    };

    const endTransaction = async (): Promise<void> => {
      if (!transactionOpen) return;
      try {
        await runExtended(client, 'ROLLBACK');
      } catch {
        // The transaction state is unknown. `markSessionDirty` above means this
        // connection is destroyed rather than recycled, which is the only way
        // the next request is guaranteed not to inherit it.
      }
      transactionOpen = false;
    };

    const abandonRun = async (index: number, timedOut: boolean): Promise<void> => {
      if (timedOut) abandonedForDeadline = true;
      if (strategy === 'single_tx') {
        migrationStatus = 'rolled_back';
        await endTransaction();
        markRolledBack(index);
      } else {
        migrationStatus = 'partial';
      }
    };

    try {
      if (strategy === 'single_tx') {
        await runExtended(client, 'BEGIN');
        transactionOpen = true;

        // Transaction-scoped lock: PostgreSQL releases it at COMMIT/ROLLBACK,
        // including when the connection dies mid-migration, so it cannot leak
        // onto a pooled session.
        const lockRes = await runExtended(
          client,
          'SELECT pg_try_advisory_xact_lock($1, $2) AS locked',
          [key1, key2],
        );
        if (!lockTaken(lockRes)) {
          await endTransaction();
          throw new MigrationInProgressError(
            'Database migration is currently in progress for this project.',
          );
        }
      } else {
        // No wrapping transaction in per_statement mode, so the lock is
        // session-scoped and the `finally` below is the only thing that
        // releases it. That is why the client is destroyed, never recycled.
        const lockRes = await runExtended(client, 'SELECT pg_try_advisory_lock($1, $2) AS locked', [
          key1,
          key2,
        ]);
        if (!lockTaken(lockRes)) {
          throw new MigrationInProgressError(
            'Database migration is currently in progress for this project.',
          );
        }
        sessionLockHeld = true;
      }

      // Step 6: Execute loop
      for (let i = 0; i < payload.statements.length; i++) {
        const stmt = payload.statements[i];

        // Cooperative checkpoint. A cancellation or an expired deadline stops the
        // run here, before the next statement is ever sent.
        if (interruption !== null) {
          await abandonRun(i, interruption === 'deadline');
          break;
        }
        if (deadlineAt - Date.now() <= 0) {
          interrupt('deadline');
          await abandonRun(i, true);
          break;
        }

        await applyBudget();

        const stmtStart = Date.now();
        emitProgress(i, stmt, 'running');

        try {
          // Extended query protocol: node-postgres only takes the simple
          // protocol (which executes every semicolon-separated command in one
          // round trip) when `values` is falsy, so this pins the statement
          // count to the one the plan declared. PostgreSQL answers a second
          // command in the same Parse with `42601`.
          //
          // Raced against `interrupted`, so a run that is cancelled or runs out
          // of deadline stops waiting on a statement the backend may still be
          // executing. The abandoned query is left to the server-side
          // `statement_timeout` above and to the cancellation the canceller
          // issues with `pg_cancel_backend`, both of which surface as `57014`.
          const runRes = await Promise.race([runExtended(client, stmt), interrupted]);
          const duration = Date.now() - stmtStart;

          statementResults.push({
            index: i,
            status: 'success',
            ms: duration,
            rows_affected: runRes.rowCount || 0,
          });
          emitProgress(i, stmt, 'success', { ms: duration });
        } catch (err: unknown) {
          const duration = Date.now() - stmtStart;
          const wasInterrupted = err instanceof RunInterrupted;
          const message = wasInterrupted
            ? err.reason === 'deadline'
              ? `Migration exceeded its overall deadline of ${budget.deadlineMs}ms ` +
                `while statement ${i + 1} was still running; the run was abandoned.`
              : `Migration was cancelled by the caller while statement ${i + 1} was still running.`
            : err instanceof Error
              ? err.message
              : String(err);

          statementResults.push({
            index: i,
            status: 'failed',
            ms: duration,
            rows_affected: 0,
            error: message,
            // A statement torn down locally has the same SQLSTATE PostgreSQL
            // would have produced: `57014`, query_canceled.
            pg_error_code: wasInterrupted
              ? PG_QUERY_CANCELED
              : err && typeof err === 'object' && 'code' in err
                ? String((err as Record<string, unknown>).code)
                : undefined,
          });
          emitProgress(i, stmt, 'failed', { ms: duration, error: message });

          if (wasInterrupted) {
            // The backend may still be running that statement, so nothing about
            // this session can be proven: the next request must not inherit it.
            // `markSessionDirty` destroys the connection, and terminating the
            // backend is what actually stops the statement and releases the
            // advisory lock.
            statementAbandonedInFlight = true;
          }

          await abandonRun(i, wasInterrupted && err.reason === 'deadline');
          break;
        }
      }

      if (transactionOpen) {
        // An interrupted run is never committed. In `single_tx` that is the whole
        // difference between a migration that applied and one that did not, so
        // the COMMIT is gated on the run still being healthy — not only on the
        // statements having all succeeded.
        if (interruption === null && outcome() === 'committed') {
          await runExtended(client, 'COMMIT');
          transactionOpen = false;
        } else {
          if (interruption !== null && strategy === 'single_tx') {
            // The deadline or a cancellation landed after the last statement
            // succeeded. Rolling back is the only outcome that matches what the
            // database did, so the status must not stay `committed`.
            migrationStatus = 'rolled_back';
          }
          await endTransaction();
          markRolledBack(payload.statements.length);
        }
      }

      const result: MigrationResultPayload = {
        plan_id: payload.plan_id,
        status: outcome(),
        statements: statementResults,
        total_ms: Date.now() - startTime,
        rolled_back_indices: rolledBackIndices,
      };

      if (outcome() === 'partial') {
        // Name the cause, because "partial" alone does not tell a caller whether
        // it should retry the plan or ask for a bigger budget — and do not claim
        // work is committed when the run was abandoned before any of it landed.
        const appliedCount = result.statements.filter((s) => s.status === 'success').length;
        const cause =
          interruption === 'deadline'
            ? `Migration exceeded its overall deadline of ${budget.deadlineMs}ms and was abandoned`
            : interruption === 'aborted'
              ? 'Migration was cancelled by the caller and was abandoned'
              : 'Migration stopped partway';
        const consequence =
          appliedCount === 0
            ? 'Nothing was committed, but the run did not complete.'
            : `${appliedCount} earlier statement(s) are already committed and were not rolled ` +
              'back. Verify the applied schema before retrying.';
        throw new MigrationPartiallyAppliedError(`${cause}: ${consequence}`, result);
      }

      if (abandonedForDeadline) {
        throw new MigrationTimeoutError(
          `Migration exceeded its overall deadline of ${budget.deadlineMs}ms and was abandoned. ` +
            'Every statement was rolled back.',
        );
      }

      return result;
    } catch (err: unknown) {
      await endTransaction();
      throw err;
    } finally {
      clearTimeout(deadlineTimer);

      // Release the advisory lock on every exit path. Without this a single
      // failed migration left the lock held on a pooled connection, blocking
      // every later migration for this project until the pool recycled it.
      // `markSessionDirty` above already guarantees the connection is destroyed
      // either way, so a failed unlock needs no separate handling here.
      if (sessionLockHeld) {
        // A statement abandoned in flight may still be executing on the backend,
        // and node-postgres queues everything behind an in-flight query — this
        // unlock included — so sending it would wait out the statement the
        // deadline just gave up on. It is not needed either way: PostgreSQL
        // releases a session-scoped advisory lock when the backend goes away,
        // and the connection is destroyed on this path.
        if (!statementAbandonedInFlight) {
          try {
            await runExtended(client, 'SELECT pg_advisory_unlock($1, $2)', [key1, key2]);
          } catch {
            // The lock may survive on a backend that is about to be destroyed.
          }
        }
        sessionLockHeld = false;
      }

      if (ctx.abortSignal) {
        ctx.abortSignal.removeEventListener('abort', onAbort);
      }
      abortController.signal.removeEventListener('abort', onAbort);
      if (ctx.unregisterInFlight) {
        ctx.unregisterInFlight(ctx.request_id);
      }
      release();
    }
  }
}
