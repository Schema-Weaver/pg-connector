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
    maxMs?: number
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
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Compute jittered backoff (±20% of base delay) to prevent thundering herd.
 * Optional — use only if you want to add jitter on top of Backoff.
 */
export function withJitter(delayMs: number, jitterPct: number = 0.2): number {
  const jitter = delayMs * jitterPct;
  return Math.round(delayMs - jitter + (Math.random() * 2 * jitter));
}
