import { createHash } from 'crypto';
import { Role } from '../protocol/envelope';
import { PermissionLevel, PlanConsumeRefusal, PlanRegistrationRefusal } from './types';
import {
  hasCapability,
  isAtLeastAsPermissive,
  isAtLeastAsPrivileged,
  isStrictlyMorePrivileged,
} from './role-policy';

export interface RegisteredPlan {
  plan_id: string;
  /** Hash of the statements (for matching). */
  statements_hash: string;
  /** How many statements were registered. Each must be exactly one statement. */
  statement_count: number;
  /** When the plan was registered (epoch ms). */
  registered_at: number;
  /** When the plan expires (epoch ms). Default 5 min. */
  expires_at: number;
  /** The user_id who registered it (for audit). */
  registered_by: string;
  /**
   * The project the plan was registered against, as the **resolved** database
   * entry's `project_name` — never the frame's claim.
   *
   * every other authority a plan carries (identity, role, permission
   * level) was bound to the registration, and the database was not. A statement
   * set reviewed and approved against a development database therefore executed
   * unchanged against production. Required: a registration that cannot name its
   * database is refused rather than stored unbound.
   */
  project: string;
  /** The resolved `db_alias` of the entry the plan was registered against. */
  db_alias: string;
  /**
   * The role the registrant held at registration time.
   *
   * `null` means the caller did not attest a principal. Such a plan is
   * unattested: it may only ever be executed by the user id that registered it
   * (no escalation from a more privileged role, because the registrant role is
   * unknown) and its permission level is not bound at all. The dispatcher must
   * pass the principal; see `register()`.
   */
  registered_by_role: Role | null;
  /**
   * The permission level in force when the plan was registered.
   *
   * `null` for an unattested plan. A recorded level is a floor on execution: a
   * plan registered while the database was at `full` may not be executed at
   * `auto_upgrade`, where no human ever saw it.
   */
  registered_permission_level: PermissionLevel | null;
  /** Optional: risk level (low/medium/high) — browser computes this. */
  risk_level?: 'low' | 'medium' | 'high';
}

/** The principal on whose authority a plan is registered. */
export interface PlanPrincipal {
  user_id: string;
  role: Role;
  permission_level: PermissionLevel;
  /**
   * The resolved database the plan is registered against. Both parts are
   * required: `consume()`/`assertExecutionScope()` compare them to the frame's
   * resolved entry, and a plan that cannot be compared is a plan that could
   * execute anywhere.
   */
  project?: string;
  db_alias?: string;
}

/**
 * The database a plan execution is being evaluated for, as the resolved entry.
 */
export interface PlanExecutionScope {
  project: string;
  db_alias: string;
}

export interface PlanRegistryOptions {
  /** How long plans stay valid. Default 300_000 (5 min). */
  ttlMs?: number;
  /** Max plans in registry (LRU eviction). Default 100. */
  maxPlans?: number;
}

/** Outcome of a registration attempt. Refusals are decisions, not exceptions. */
export type RegisterResult =
  | { ok: true; plan: RegisteredPlan }
  | { ok: false; code: PlanRegistrationRefusal; reason: string };

/**
 * Outcome of consuming a plan for execution.
 *
 * A consumption is the *only* decision that hands out execution authority, so
 * it is a single synchronous step: validate, authorise, destroy. See
 * `PlanRegistry.consume()`.
 */
export type ConsumeResult =
  | { ok: true; plan: RegisteredPlan }
  | { ok: false; code: PlanConsumeRefusal; reason: string };

/**
 * In-memory registry of single-use migration plans, keyed by plan id.
 *
 * Every question about a plan is asked about **one** id: `validate()` to inspect,
 * `consume()` to decide and hand out authority, `unregister()` for administrative
 * removal. There is deliberately no "list every live plan" accessor — it had no
 * production caller, and an enumeration API over live plan ids invites exactly the
 * probing that the single-id refusals are written to prevent (finding M-22). Do
 * not reintroduce one for debugging: log the id you are about to look up.
 */
export class PlanRegistry {
  private plans: Map<string, RegisteredPlan> = new Map();
  /**
   * Tombstones of plans that were consumed, oldest first.
   *
   * Without them a consumed plan is indistinguishable from one that was never
   * registered, so a replay attempt reads as a typo. They carry the id and the
   * consumption time only — no statements, no user id, no role — so a refusal
   * built from them says "this id was already spent" and nothing about any
   * other plan. Bounded to `maxPlans` entries.
   */
  private consumed: Map<string, number> = new Map();
  private readonly opts: Required<PlanRegistryOptions>;

  constructor(opts?: PlanRegistryOptions) {
    this.opts = {
      ttlMs: opts?.ttlMs ?? 300_000,
      maxPlans: opts?.maxPlans ?? 100,
    };
  }

  /**
   * Whether this principal may register a migration plan at all.
   *
   * This is the source of truth for the `plan_register` entry gate so the
   * dispatcher and the registry cannot disagree:
   *   - `read_only` never registers plans; there is nothing to approve a
   *     write against.
   *   - a role without the `migration_run` capability never registers plans.
   */
  canRegister(
    role: Role,
    permissionLevel: PermissionLevel,
  ): { allowed: boolean; code?: PlanRegistrationRefusal; reason?: string } {
    if (permissionLevel === 'read_only') {
      return {
        allowed: false,
        code: 'read_only_permission_level',
        reason: `Plan registration is refused at permission level 'read_only'`,
      };
    }
    if (!hasCapability(role, 'migration_run')) {
      return {
        allowed: false,
        code: 'role_lacks_migration_run',
        reason: `Role '${role}' lacks the 'migration_run' capability and cannot register plans`,
      };
    }
    return { allowed: true };
  }

  /**
   * Register a migration plan on behalf of `principal`.
   *
   * Registration is an authorization event, so the plan records WHO registered
   * it, WITH WHAT ROLE, and AT WHAT PERMISSION LEVEL. Without all three the
   * registry is a self-attesting allow-list: the same untrusted principal
   * registers the plan and runs it, and a statement-hash match proves nothing.
   *
   * `principal` is optional only so the record can distinguish "no principal
   * attested" from "no principal": an unattested plan is stored but is
   * restricted to its registrant and carries no permission-level floor. Callers
   * must pass it.
   */
  register(
    planId: string,
    statements: string[],
    registeredBy: string,
    riskLevel?: 'low' | 'medium' | 'high',
    principal?: PlanPrincipal,
  ): RegisterResult {
    if (!principal) {
      return {
        ok: false,
        code: 'unattested_principal',
        reason:
          'Plan registration requires the registering principal (user id, role and ' +
          'permission level). Refusing to store an unattested plan.',
      };
    }

    const gate = this.canRegister(principal.role, principal.permission_level);
    if (!gate.allowed) {
      return {
        ok: false,
        code: gate.code ?? 'unattested_principal',
        reason: gate.reason ?? 'Plan registration refused',
      };
    }

    if (registeredBy !== principal.user_id) {
      return {
        ok: false,
        code: 'unattested_principal',
        reason:
          'Plan registration refused: the registering user id does not match the ' +
          'attested principal.',
      };
    }

    // the registration must name the resolved database it belongs to.
    // Stored unbound, the plan's statement hash and provenance survive a change
    // of database and it executes unchanged against production.
    const scope = scopeOf(principal.project, principal.db_alias);
    if (!scope) {
      return {
        ok: false,
        code: 'unscoped_plan_registration',
        reason:
          'Plan registration requires the resolved project and db_alias the plan is bound ' +
          'to. Refusing to store a plan that is not bound to a database.',
      };
    }

    // M-22: expiry was enforced only by whichever lookup happened to notice, so
    // a plan nobody ever ran stayed in the map until the process exited. Purging
    // on the registration path keeps the registry bounded without a timer.
    // `expires_at` is `registered_at + ttlMs` (300s by default), so a plan
    // registered moments ago is never a purge candidate.
    this.purgeExpired();

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
      statement_count: statements.length,
      registered_at: now,
      expires_at: now + this.opts.ttlMs,
      registered_by: principal.user_id,
      registered_by_role: principal.role,
      registered_permission_level: principal.permission_level,
      project: scope.project,
      db_alias: scope.db_alias,
      risk_level: riskLevel,
    };

    this.plans.set(planId, plan);
    return { ok: true, plan };
  }

  /**
   * Look up a live plan, distinguishing "never registered" from "already
   * consumed".
   *
   * Both refusals are about this id only: neither mentions another plan, a
   * user, a role or a statement, so probing for someone else's plan id tells
   * the prober nothing beyond "no such plan".
   */
  private lookup(
    planId: string,
  ): { ok: true; plan: RegisteredPlan } | { ok: false; code: PlanConsumeRefusal; reason: string } {
    const plan = this.plans.get(planId);
    if (plan) {
      return { ok: true, plan };
    }
    if (this.consumed.has(planId)) {
      return {
        ok: false,
        code: 'plan_already_consumed',
        reason:
          `Plan '${planId}' has already been consumed; a migration plan is single-use ` +
          'and cannot be replayed',
      };
    }
    return { ok: false, code: 'plan_not_registered', reason: 'Plan ID not found in registry' };
  }

  /**
   * Check if a plan is valid (exists, not expired, statements match).
   *
   * This does NOT consume the plan and does NOT check who is asking, so it is
   * an inspection helper only. Anything about to execute a plan must call
   * `consume()`, which is the single atomic hand-off of authority.
   */
  validate(
    planId: string,
    statements: string[],
  ): { valid: boolean; reason?: string; plan?: RegisteredPlan } {
    const found = this.lookup(planId);
    if (!found.ok) {
      return { valid: false, reason: found.reason };
    }
    const plan = found.plan;
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

  /**
   * Validate, authorise and destroy `planId` in one synchronous step.
   *
   * `check()` in the permission pipeline is async, so authority must not be
   * handed out by a `validate()` … `unregister()` pair: that sequence is only
   * single-use by accident of the current call graph, and any `await` added
   * between the two turns it into a replay of the same plan. Here the plan
   * leaves the map in the same synchronous step that grants it, so a second
   * caller — whatever it interleaved at — sees a tombstone and is refused.
   *
   * A refused attempt does NOT burn the plan: an unauthorised runner must not
   * be able to invalidate somebody else's registration by trying it. Expiry is
   * the only other way a plan leaves the map.
   */
  consume(
    planId: string,
    statements: string[],
    runner: { user_id: string; role: Role; permission_level: PermissionLevel; scope?: PlanExecutionScope },
  ): ConsumeResult {
    const found = this.lookup(planId);
    if (!found.ok) {
      return found;
    }
    const plan = found.plan;

    if (Date.now() > plan.expires_at) {
      this.unregister(planId);
      return { ok: false, code: 'plan_expired', reason: 'Plan expired' };
    }

    if (this.hashStatements(statements) !== plan.statements_hash) {
      return {
        ok: false,
        code: 'statements_changed',
        reason: 'Statements do not match registered plan',
      };
    }

    const scopeVerdict = assertPlanScope(plan, runner.scope);
    if (!scopeVerdict.ok) {
      return scopeVerdict;
    }

    const provenance = this.mayExecutePlan(plan, runner);
    if (!provenance.allowed) {
      return {
        ok: false,
        code:
          plan.registered_by_role === null || plan.registered_permission_level === null
            ? 'principal_not_attested'
            : !isAtLeastAsPermissive(runner.permission_level, plan.registered_permission_level)
              ? 'registered_at_more_permissive_level'
              : 'runner_not_privileged',
        reason: provenance.reason ?? 'insufficient authority',
      };
    }

    this.plans.delete(planId);
    this.rememberConsumed(planId);
    return { ok: true, plan };
  }

  /**
   * Inspect a plan without consuming it and check only its database binding.
   *
   * The dispatcher calls this before the permission pipeline runs, because the
   * registry cannot see the frame on its own: `AutoUpgradeChecker` (which owns
   * the `consume()` call) receives an `ActionRequest` and today forwards only
   * the principal. Comparing here means the check cannot be skipped by a code
   * path that reaches `consume()` some other way — and a plan id that is not
   * registered at all passes, because a `migration_run` at `full` legitimately
   * needs no plan.
   *
   * A refused attempt does NOT burn the plan: an out-of-scope runner must not be
   * able to invalidate somebody else's registration.
   */
  assertExecutionScope(
    planId: string,
    scope: PlanExecutionScope,
  ): { ok: true } | { ok: false; code: 'plan_scope_mismatch'; reason: string } {
    const plan = this.plans.get(planId);
    // Unknown or already consumed: the consume path reports it, with a refusal
    // that says nothing about other plans.
    if (!plan) return { ok: true };
    const verdict = assertPlanScope(plan, scope);
    if (verdict.ok) return verdict;
    return {
      ok: false,
      code: 'plan_scope_mismatch',
      reason:
        `Plan ${planId} was registered against project '${plan.project}' (alias ` +
        `'${plan.db_alias}') and may not be executed against project '${scope.project}' ` +
        `(alias '${scope.db_alias}')`,
    };
  }

  /**
   * Whether `runner` may execute `plan`.
   *
   * Four independent conditions, all fail-closed:
   *   0. The runner's resolved database must equal the one the plan was
   *      registered against. See {@link assertPlanScope}; enforced by
   *      `consume()` when the runner supplies a scope and by
   *      {@link assertExecutionScope} on the request path.
   *   1. The runner's role must be at least as privileged as the role the plan
   *      was registered under. Authority is not retained across a demotion: a
   *      plan registered by an `admin` is admin authority even when the same
   *      user id now presents a weaker role.
   *   2. The runner must be the registering principal, or hold a STRICTLY more
   *      privileged role. An admin may run a developer's plan; a peer may not
   *      run another peer's, because the plan is authority exercised at the
   *      registrant's level.
   *   3. The plan may only be executed at a permission level at least as
   *      permissive as the one it was registered under, so a plan that needed
   *      no human at `full` cannot be executed unattended at `auto_upgrade`.
   *
   * An unattested plan (no role or level recorded) may only be executed by the
   * user that registered it.
   */
  mayExecutePlan(
    plan: RegisteredPlan,
    runner: { user_id: string; role: Role; permission_level: PermissionLevel; scope?: PlanExecutionScope },
  ): { allowed: boolean; reason?: string } {
    const scopeVerdict = assertPlanScope(plan, runner.scope);
    if (!scopeVerdict.ok) {
      return { allowed: false, reason: scopeVerdict.reason };
    }

    if (plan.registered_by_role === null || plan.registered_permission_level === null) {
      if (plan.registered_by !== runner.user_id) {
        return {
          allowed: false,
          reason:
            `Plan ${plan.plan_id} was registered without an attested principal, so a ` +
            'different user may not execute it; only the registering user id may',
        };
      }
      return { allowed: true };
    }

    if (!isAtLeastAsPrivileged(runner.role, plan.registered_by_role)) {
      return {
        allowed: false,
        reason:
          `Plan ${plan.plan_id} was registered under role '${plan.registered_by_role}', ` +
          `which role '${runner.role}' does not match or exceed`,
      };
    }

    if (
      plan.registered_by !== runner.user_id &&
      !isStrictlyMorePrivileged(runner.role, plan.registered_by_role)
    ) {
      return {
        allowed: false,
        reason:
          `Plan ${plan.plan_id} was registered by '${plan.registered_by}' ` +
          `(role '${plan.registered_by_role}'); a different user may not execute it unless ` +
          `their role is strictly more privileged, and role '${runner.role}' is not`,
      };
    }

    if (!isAtLeastAsPermissive(runner.permission_level, plan.registered_permission_level)) {
      return {
        allowed: false,
        reason:
          `Plan ${plan.plan_id} was registered at permission level ` +
          `'${plan.registered_permission_level}' and may not be executed at the more ` +
          `restrictive level '${runner.permission_level}'`,
      };
    }

    return { allowed: true };
  }

  /**
   * Remove a plan (after migration runs or fails).
   *
   * This is administrative removal, not a consumption: no tombstone is left,
   * so a later use of the id is reported as unknown rather than as a replay.
   * `consume()` is what a migration run must use.
   */
  unregister(planId: string): void {
    this.plans.delete(planId);
    this.consumed.delete(planId);
  }

  /**
   * Drop plans whose TTL has elapsed. Called on the registration path, so an
   * expired plan never occupies a slot or survives until process exit.
   *
   * Expiry is `expires_at = registered_at + ttlMs`, so a plan registered
   * moments ago has `expires_at` five minutes in the future and can never be
   * swept by this. Nothing here decides authorisation.
   */
  purgeExpired(): number {
    const now = Date.now();
    let purged = 0;
    for (const [id, plan] of this.plans.entries()) {
      if (now > plan.expires_at) {
        this.plans.delete(id);
        purged++;
      }
    }
    for (const [id, consumedAt] of this.consumed.entries()) {
      if (now - consumedAt > this.opts.ttlMs) {
        this.consumed.delete(id);
      }
    }
    return purged;
  }

  /** Record a consumption as a tombstone, bounded to `maxPlans` entries. */
  private rememberConsumed(planId: string): void {
    this.consumed.delete(planId);
    this.consumed.set(planId, Date.now());
    while (this.consumed.size > this.opts.maxPlans) {
      const oldest = this.consumed.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.consumed.delete(oldest);
    }
  }

  /**
   * Compute a stable hash of statements.
   *
   * Whitespace is collapsed and case folded so the comparison cannot be
   * defeated by re-spacing, and the entries are length-delimited so
   * `['A','BC']` and `['AB','C']` cannot collide.
   */
  private hashStatements(statements: string[]): string {
    const normalized = statements
      .map((s) => {
        const flat = s.trim().replace(/\s+/g, ' ').toLowerCase();
        return `${flat.length}:${flat}`;
      })
      .join('|');
    return createHash('sha256').update(normalized).digest('hex');
  }
}

/**
 * A registration scope, or null when either half is missing.
 *
 * Trimmed and required non-empty: `''` would be a database named by nothing, and
 * comparing it against a real alias would have to be treated as a match by every
 * string comparison downstream.
 */
function scopeOf(project: unknown, dbAlias: unknown): PlanExecutionScope | null {
  const p = typeof project === 'string' ? project.trim() : '';
  const a = typeof dbAlias === 'string' ? dbAlias.trim() : '';
  if (p.length === 0 || a.length === 0) return null;
  return { project: p, db_alias: a };
}

/**
 * Whether `scope` is the database `plan` was registered against.
 *
 * Fail-closed in both directions: a plan with no recorded scope and a runner
 * with no supplied scope are both refused, so a caller cannot reach an unbound
 * plan by simply not telling the registry which database it is talking about.
 * `assertExecutionScope` on the request path is what supplies the scope for a
 * caller (`AutoUpgradeChecker`) that does not forward one itself.
 */
function assertPlanScope(
  plan: RegisteredPlan,
  scope: PlanExecutionScope | undefined,
): { ok: true } | { ok: false; code: 'plan_scope_mismatch'; reason: string } {
  const registered = scopeOf(plan.project, plan.db_alias);
  if (!registered) {
    return {
      ok: false,
      code: 'plan_scope_mismatch',
      reason:
        `Plan ${plan.plan_id} is not bound to a database, so it may not be executed. ` +
        'Register it again against the database it is intended for.',
    };
  }
  const requested = scopeOf(scope?.project, scope?.db_alias);
  if (!requested) {
    return {
      ok: false,
      code: 'plan_scope_mismatch',
      reason:
        `Execution scope for plan ${plan.plan_id} is unknown, so it may not be executed. ` +
        'The resolved project and db_alias must both be supplied.',
    };
  }
  if (registered.project !== requested.project || registered.db_alias !== requested.db_alias) {
    return {
      ok: false,
      code: 'plan_scope_mismatch',
      reason:
        `Plan ${plan.plan_id} is bound to project '${registered.project}' (alias ` +
        `'${registered.db_alias}') and may not be executed against project ` +
        `'${requested.project}' (alias '${requested.db_alias}')`,
    };
  }
  return { ok: true };
}
