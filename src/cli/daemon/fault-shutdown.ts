/**
 * Fail-closed shutdown on an unexpected process-level fault.
 *
 * Node's default behaviour for `uncaughtException` and `unhandledRejection` is
 * to print and terminate. Installing a handler that only records the error
 * OVERRIDES that default: the process stays alive, keeps its PostgreSQL pools,
 * its permission state and its audit writer, and keeps answering queries while
 * running in a state nobody reasoned about. For a long-lived daemon that holds
 * database credentials and executes DDL, "keep serving after an unknown fault"
 * is the wrong answer — the correct answer is to stop, leave a durable trace,
 * and let the supervisor restart it.
 *
 * Everything here is injectable so a test can assert the exit DECISION without
 * killing the test runner: `exit`, `log`, the flush hooks and the clock are all
 * parameters, and no module-level `process.exit` call exists in this file.
 *
 * ## The non-fatal rejection tag
 *
 * `unhandledRejection` is fail-closed by default, because a rejected promise
 * nobody handled is a bug by definition and this daemon holds credentials. The
 * single exception has to be explicit and greppable, so the only value that is
 * allowed to be swallowed is one that a call site deliberately tagged:
 *
 * ```ts
 * markNonFatalRejection(new Error('wake-channel reconnect already in flight'));
 * ```
 *
 * It sets a non-enumerable symbol on the reason object. A `Symbol`, not a
 * string field: it cannot collide with a database column, an error message or
 * a JSON body, it does not survive serialisation (so it cannot be replayed by
 * anything reading the value back), and nothing outside this module can set it
 * except by calling {@link markNonFatalRejection}. A plain
 * `{ nonFatal: true }` flag would be forgeable by any rejected object, which
 * would make the tag no control at all.
 */

import * as fs from 'fs';

/** Which process-level event produced the fault. */
export type FaultKind = 'uncaughtException' | 'unhandledRejection';

/**
 * Exit code used for a fail-closed fault. `EX_SOFTWARE` from `sysexits.h`: an
 * internal software error, as opposed to a usage or configuration error. Any
 * non-zero value satisfies `Restart=on-failure`; a distinct one means a fault
 * restart is greppable in the journal and separable from an ordinary crash.
 */
export const FAULT_EXIT_CODE = 70;

/**
 * Upper bound on the best-effort flush before the process exits anyway.
 *
 * Short on purpose. The flush exists to get the last audit record onto the disk,
 * not to complete an orderly shutdown: a daemon that cannot flush in two seconds
 * is a daemon whose I/O is stuck, and waiting longer only widens the window in
 * which a half-released pool keeps serving. Well under the five seconds the
 * regression test allows.
 */
export const FAULT_FLUSH_TIMEOUT_MS = 2_000;

/**
 * Marker for a rejection a call site has decided is safe to log and continue
 * from. Non-enumerable, so the tag cannot be discovered by enumeration or
 * serialisation of the reason.
 */
export const NON_FATAL_REJECTION_TAG = Symbol.for('sw-agent.nonFatalRejection');

/**
 * Tags a rejection as deliberately non-fatal.
 *
 * Only for a rejection that is genuinely a duplicate/benign outcome — a wake
 * reconnect already in flight, a cancellation racing a completion. NEVER for a
 * failure to record an audit record, to release a permit, to classify SQL, or to
 * do anything the product promises not to hide.
 */
export function markNonFatalRejection<T>(reason: T): T {
  if (reason === null || (typeof reason !== 'object' && typeof reason !== 'function')) {
    return reason;
  }
  try {
    Object.defineProperty(reason, NON_FATAL_REJECTION_TAG, {
      value: true,
      enumerable: false,
      configurable: true,
      writable: false,
    });
  } catch {
    // A frozen or sealed reason cannot be tagged, so it stays fatal. That is the
    // safe direction: a caller that cannot record its intent does not get the
    // benefit of the doubt.
  }
  return reason;
}

/** True when {@link markNonFatalRejection} was applied to this exact value. */
export function isNonFatalRejection(reason: unknown): boolean {
  return (
    reason !== null &&
    (typeof reason === 'object' || typeof reason === 'function') &&
    (reason as Record<symbol, unknown>)[NON_FATAL_REJECTION_TAG] === true
  );
}

/** What the fault handler is allowed to touch. Every field is injectable. */
export interface FaultShutdownDeps {
  /**
   * Records the fault in `errors.jsonl`. Must never throw; a fault handler that
   * throws has replaced a contained failure with an uncontained one.
   */
  track: (err: unknown, opts: { op: FaultKind; level: 'fatal' | 'error' | 'warn' }) => void;
  /**
   * Best-effort: makes the last appended record durable (append + fsync).
   * Separate from `track` because `track` must not do I/O that can block.
   */
  flushLocalLog?: () => void;
  /** Drains and fsyncs the audit sink. Registered by the daemon runtime. */
  flushAudit?: () => Promise<void>;
  /** Releases every PostgreSQL pool. Registered by the daemon runtime. */
  closePools?: () => Promise<void>;
  /** Operator/journal line. Must be synchronous; the exit can follow at once. */
  log?: (line: string) => void;
  /** Terminates the process. Injected so a test can observe the decision. */
  exit: (code: number) => void;
  /** Upper bound on the flush. Defaults to {@link FAULT_FLUSH_TIMEOUT_MS}. */
  flushTimeoutMs?: number;
}

/** The decision the handler reached. Every field is asserted by the tests. */
export interface FaultShutdownDecision {
  /** True when this call asked the process to terminate. */
  exit_requested: boolean;
  /** The code passed to `exit`, or null when no exit was requested. */
  exit_code: number | null;
  /** True when this call was a no-op because an earlier fault is already exiting. */
  suppressed_by_earlier_fault: boolean;
  /** True when the rejection carried the explicit non-fatal tag. */
  non_fatal: boolean;
  /** True when every flush hook completed within the timeout. */
  flushed: boolean;
  /** True when the flush did not complete in time and the exit was forced. */
  flush_timed_out: boolean;
}

function textOf(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  try {
    return String(err);
  } catch {
    return '<unprintable rejection reason>';
  }
}

/**
 * One-shot fault handler for the whole process.
 *
 * Idempotent by construction: the first fault latches `firing` and every later
 * one — including an `unhandledRejection` that lands while the first fault's
 * flush is still in flight — returns a suppressed decision without a second
 * flush and without a second `exit`. Without the latch, an uncaught exception
 * followed immediately by the rejection it caused would flush and close twice,
 * and the second `close()` on an already-closed pool rejects, which is exactly
 * the kind of cascading undefined behaviour this module exists to stop.
 */
export interface FaultShutdownController {
  handle(kind: FaultKind, err: unknown): Promise<FaultShutdownDecision>;
  /** True once the first fatal fault has started the exit path. */
  isFiring(): boolean;
  /**
   * Registers the audit/pool handles after construction.
   *
   * Needed because the daemon builds its audit sink and `PoolManager` AFTER it
   * installs the process handlers — the handlers must exist before the parser
   * load so a startup crash is tracked, and the sink does not exist until after
   * that. Refuses once a fault is in flight: swapping the flush set mid-shutdown
   * is how a half-completed flush becomes two.
   */
  setHooks(hooks: Pick<FaultShutdownDeps, 'flushAudit' | 'closePools'>): boolean;
}

/** A decision that does nothing, used for the suppressed and non-fatal paths. */
function inertDecision(overrides: Partial<FaultShutdownDecision> = {}): FaultShutdownDecision {
  return {
    exit_requested: false,
    exit_code: null,
    suppressed_by_earlier_fault: false,
    non_fatal: false,
    flushed: false,
    flush_timed_out: false,
    ...overrides,
  };
}

/**
 * Builds the controller. One per process; the process handlers hold a reference
 * to it so they share the latch.
 */
export function createFaultShutdownController(deps: FaultShutdownDeps): FaultShutdownController {
  const timeoutMs = deps.flushTimeoutMs ?? FAULT_FLUSH_TIMEOUT_MS;
  const log = deps.log ?? defaultSyncLog;
  // Read through a mutable holder so `setHooks` can register the audit and pool
  // handles that only exist after the process handlers are installed.
  const flushLocalLog = deps.flushLocalLog;
  let flushAudit = deps.flushAudit;
  let closePools = deps.closePools;
  let firing = false;

  /** Runs every hook, never exceeding `timeoutMs`, and never rejecting. */
  const flushEverything = async (): Promise<{ flushed: boolean; timedOut: boolean }> => {
    const work: Array<() => void | Promise<void>> = [];
    if (flushLocalLog) work.push(flushLocalLog);
    if (flushAudit) work.push(flushAudit);
    if (closePools) work.push(closePools);
    if (work.length === 0) return { flushed: true, timedOut: false };

    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<'timeout'>((resolve) => {
      timer = setTimeout(() => resolve('timeout'), timeoutMs);
      // Never hold the event loop open for the deadline alone: if the flush
      // finishes early the timer must not keep a stopped process alive.
      timer.unref?.();
    });
    const ran = (async () => {
      for (const hook of work) {
        try {
          await hook();
        } catch (err) {
          // A hook that fails is exactly why we are here. Log it and keep going:
          // the remaining hooks may still get the audit chain onto the disk.
          log(`[fatal] flush step failed during fault shutdown: ${textOf(err)}`);
        }
      }
      return 'done' as const;
    })();

    try {
      const outcome = await Promise.race([ran, deadline]);
      return { flushed: outcome === 'done', timedOut: outcome === 'timeout' };
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  return {
    isFiring: () => firing,

    setHooks(hooks) {
      if (firing) {
        log(
          '[fatal] refusing to register fault-shutdown hooks: a fault is already in flight, so ' +
            'the flush set must not change mid-shutdown.',
        );
        return false;
      }
      if (hooks.flushAudit) flushAudit = hooks.flushAudit;
      if (hooks.closePools) closePools = hooks.closePools;
      return true;
    },

    async handle(kind, err) {
      const nonFatal = kind === 'unhandledRejection' && isNonFatalRejection(err);

      if (nonFatal) {
        // Recorded at `warn`, never at `fatal`: this is the one path that keeps
        // the process alive, so it must be visibly distinguishable in
        // errors.jsonl from a fault that stopped the daemon.
        try {
          deps.track(err, { op: kind, level: 'warn' });
        } catch {
          // Never let tracking throw from a process handler.
        }
        log(
          `[warn] unhandledRejection tagged non-fatal (${textOf(err)}); the daemon continues. ` +
            'Untagged rejections are fail-closed.',
        );
        return inertDecision({ non_fatal: true });
      }

      if (firing) {
        log(
          `[fatal] ${kind} during fault shutdown; already exiting, so this one is recorded only. ` +
            `${textOf(err)}`,
        );
        try {
          deps.track(err, { op: kind, level: 'error' });
        } catch {
          // ignore
        }
        return inertDecision({ suppressed_by_earlier_fault: true });
      }

      firing = true;
      log(
        `[fatal] ${kind}: ${textOf(err)}` +
          '\n[fatal] Flushing the audit sink and releasing the pools, then exiting ' +
          `${FAULT_EXIT_CODE} so the supervisor can restart a clean process.` +
          '\n[fatal] The daemon does not continue after an unhandled fault: its pools, its ' +
          'permission state and its audit writer are all in an undefined state.',
      );

      try {
        deps.track(err, { op: kind, level: 'fatal' });
      } catch {
        // ignore
      }

      const { flushed, timedOut } = await flushEverything();
      if (timedOut) {
        log(
          `[fatal] The fault flush did not complete within ${timeoutMs}ms; exiting anyway. ` +
            'The last audit records may be missing — `sw-agent audit verify` will report the ' +
            'chain as truncated.',
        );
      } else {
        log('[fatal] Fault flush complete; the last audit record is durable.');
      }

      // Exit LAST, and unconditionally. Every path above is wrapped, so the only
      // way to reach here is with the decision made; nothing after this line can
      // prevent the exit, which is the property that makes the handler
      // fail-closed rather than fail-open.
      try {
        deps.exit(FAULT_EXIT_CODE);
      } catch {
        // An injected `exit` that throws must not re-enter the handler.
      }
      return {
        exit_requested: true,
        exit_code: FAULT_EXIT_CODE,
        suppressed_by_earlier_fault: false,
        non_fatal: false,
        flushed,
        flush_timed_out: timedOut,
      };
    },
  };
}

/**
 * Writes to fd 2 synchronously.
 *
 * `process.stderr.write` is asynchronous when stderr is a pipe or a file, so a
 * message written with it can be lost to `process.exit` immediately afterwards —
 * and a systemd unit pipes stderr to the journal. `fs.writeSync` cannot be
 * reordered against the exit, which matters because this is the last thing the
 * daemon says before it dies.
 */
function defaultSyncLog(line: string): void {
  try {
    fs.writeSync(2, `${line}\n`);
  } catch {
    try {
      fs.writeSync(1, `${line}\n`);
    } catch {
      // Nothing left to try; the exit still happens.
    }
  }
}
