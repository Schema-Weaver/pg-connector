import { createHash } from 'crypto';

export interface RegisteredPlan {
  plan_id: string;
  /** Hash of the statements (for matching). */
  statements_hash: string;
  /** When the plan was registered (epoch ms). */
  registered_at: number;
  /** When the plan expires (epoch ms). Default 5 min. */
  expires_at: number;
  /** The user_id who registered it (for audit). */
  registered_by: string;
  /** Optional: risk level (low/medium/high) — browser computes this. */
  risk_level?: 'low' | 'medium' | 'high';
}

export interface PlanRegistryOptions {
  /** How long plans stay valid. Default 300_000 (5 min). */
  ttlMs?: number;
  /** Max plans in registry (LRU eviction). Default 100. */
  maxPlans?: number;
}

export class PlanRegistry {
  private plans: Map<string, RegisteredPlan> = new Map();
  private readonly opts: Required<PlanRegistryOptions>;

  constructor(opts?: PlanRegistryOptions) {
    this.opts = {
      ttlMs: opts?.ttlMs ?? 300_000,
      maxPlans: opts?.maxPlans ?? 100,
    };
  }

  /**
   * Register a migration plan.
   * Called when browser sends a `plan_register` event.
   */
  register(
    planId: string,
    statements: string[],
    registeredBy: string,
    riskLevel?: 'low' | 'medium' | 'high',
  ): RegisteredPlan {
    // If registry is at max, evict the oldest plan (LRU)
    if (this.plans.size >= this.opts.maxPlans) {
      const oldestKey = this.plans.keys().next().value;
      if (oldestKey !== undefined) {
        this.plans.delete(oldestKey);
      }
    }

    const now = Date.now();
    const plan: RegisteredPlan = {
      plan_id: planId,
      statements_hash: this.hashStatements(statements),
      registered_at: now,
      expires_at: now + this.opts.ttlMs,
      registered_by: registeredBy,
      risk_level: riskLevel,
    };

    this.plans.set(planId, plan);
    return plan;
  }

  /** Check if a plan is valid (exists, not expired, statements match). */
  validate(
    planId: string,
    statements: string[],
  ): { valid: boolean; reason?: string; plan?: RegisteredPlan } {
    const plan = this.plans.get(planId);
    if (!plan) {
      return { valid: false, reason: 'Plan ID not found in registry' };
    }
    if (Date.now() > plan.expires_at) {
      this.unregister(planId);
      return { valid: false, reason: 'Plan expired' };
    }
    const hash = this.hashStatements(statements);
    if (hash !== plan.statements_hash) {
      return { valid: false, reason: 'Statements do not match registered plan' };
    }
    // Update access order for LRU cache
    this.plans.delete(planId);
    this.plans.set(planId, plan);
    return { valid: true, plan };
  }

  /** Remove a plan (after migration runs or fails). */
  unregister(planId: string): void {
    this.plans.delete(planId);
  }

  /** Get all registered plans (for debugging). */
  list(): RegisteredPlan[] {
    return Array.from(this.plans.values());
  }

  /** Purge expired plans. Called periodically. */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [id, plan] of this.plans.entries()) {
      if (now > plan.expires_at) {
        this.plans.delete(id);
        purged++;
      }
    }
    return purged;
  }

  /** Compute a stable hash of statements. */
  private hashStatements(statements: string[]): string {
    const normalized = statements
      .map((s) => s.trim().replace(/\s+/g, ' ').toLowerCase())
      .join('|||');
    return createHash('sha256').update(normalized).digest('hex');
  }
}
