import { ActionRequest, AutoUpgradeResult, PlanConsumeRefusal } from './types';
import { PlanRegistry, type PlanExecutionScope } from './plan-registry';
import { hasCapability } from './role-policy';
import { classifyStatement } from '../execution/statement-classifier';
import { SqlParseError, SqlParserUnavailableError } from '../execution/sql-parser';

export interface AutoUpgradeOptions {
  planRegistry: PlanRegistry;
}

export class AutoUpgradeChecker {
  private readonly opts: AutoUpgradeOptions;

  constructor(opts: AutoUpgradeOptions) {
    this.opts = opts;
  }

  /**
   * Check whether auto-upgrade should be granted.
   *
   * Only meaningful when permission_level === 'auto_upgrade'.
   *
   * Auto-upgrade is granted only when ALL of the following hold:
   *   - the effective permission level really is `auto_upgrade`; this checker
   *     grants nothing at `read_only`, `manual` or `full`, so a caller that
   *     reaches it on the wrong path is refused rather than trusted
   *   - the message really is a `migration_run`
   *   - the role holds `migration_run`
   *   - a plan id is present and is registered, unexpired, and its statements
   *     hash matches the statements being submitted
   *   - the plan's registering principal is bound to this execution: the runner
   *     is the registrant, or holds a strictly more privileged role, and the
   *     permission level at execution is at least as permissive as the level the
   *     plan was registered under
   *   - every statement parses, is exactly one statement, and is not a read
   *   - the plan is consumed, so it cannot be replayed
   *
   * The last four conditions are decided by ONE synchronous call into the
   * registry (`consume()`), not by a validate-then-authorise-then-delete
   * sequence: `consume()` removes the plan in the same tick it grants it, so
   * no interleaving of two `migration_run` frames can ever be granted twice.
   *
   * Without the provenance rules the registry is a self-attesting allow-list:
   * the same untrusted principal registers the plan and runs it, so a statement
   * hash match proves nothing at all.
   */
  async check(req: ActionRequest, statements?: string[]): Promise<AutoUpgradeResult> {
    // Rule 0: this checker exists to satisfy `auto_upgrade` and nothing else.
    // `PermissionChecker` only calls it at that level, so any other level means
    // a caller reached the upgrade path directly; refuse rather than upgrade.
    if (req.permission_level !== 'auto_upgrade') {
      return {
        granted: false,
        reason: `Auto-upgrade is only available at permission level 'auto_upgrade', got ${req.permission_level}`,
      };
    }

    // Rule 1: must be a migration_run message
    if (req.message_type !== 'migration_run') {
      return {
        granted: false,
        reason: `Auto-upgrade only available for migration_run, got ${req.message_type}`,
      };
    }

    // Rule 2: role must allow migration_run
    if (!hasCapability(req.role, 'migration_run')) {
      return {
        granted: false,
        reason: `Role ${req.role} cannot run migrations`,
      };
    }

    // Rule 3: plan_id must be present
    if (!req.plan_id) {
      return { granted: false, reason: 'No plan_id provided for migration_run' };
    }

    // Rule 4: statements must be present
    if (!statements || statements.length === 0) {
      return { granted: false, reason: 'No statements provided for validation' };
    }

    // Rule 5: every statement must parse AND be exactly one statement
    const classifications = [];
    for (let i = 0; i < statements.length; i++) {
      let c;
      try {
        c = await classifyStatement(statements[i]);
      } catch (err: unknown) {
        // Fail closed: an unparseable statement or an unavailable parser is a
        // refusal, never a guess.
        const detail =
          err instanceof SqlParseError || err instanceof SqlParserUnavailableError
            ? err.message
            : String(err);
        return {
          granted: false,
          reason: `Statement ${i + 1} could not be verified: ${detail}`,
        };
      }
      if (c.statement_count !== 1) {
        return {
          granted: false,
          reason: `Statement ${i + 1} contains ${c.statement_count} statements; each plan entry must be exactly one statement`,
        };
      }
      if (c.type === 'read') {
        return {
          granted: false,
          reason: `Migration plan contains a read-only statement: ${c.verb}. Auto-upgrade not granted for reads.`,
        };
      }
      if (c.type === 'unknown') {
        return {
          granted: false,
          reason: `Migration plan contains an unclassifiable statement: ${c.verb}`,
        };
      }
      if (c.read_violations.includes('executable_block')) {
        return {
          granted: false,
          reason: `Migration plan statement ${i + 1} (${c.verb} ${c.kind}) can execute arbitrary code and is never auto-approved`,
        };
      }
      classifications.push(c);
    }

    // Rule 6 + 7: the plan must be registered, unexpired, bound to exactly
    // these statements, and authorise THIS principal — and it is destroyed in
    // the same synchronous step, so a second frame that arrives while the
    // statements above were being parsed finds a tombstone and is refused.
    // The runner is bound to the RESOLVED database, not to what the frame claimed.
    // A plan registered against production must not be executable by a frame that
    // says `dev` while resolving to production, and `assertPlanScope` is
    // fail-closed, so a caller with no resolved identity at all is refused here
    // and again in `dispatcher`'s pre-flight `assertExecutionScope`.
    const consumption = this.opts.planRegistry.consume(req.plan_id, statements, {
      user_id: req.user.id,
      role: req.role,
      permission_level: req.permission_level,
      scope: resolvedScopeOf(req),
    });
    if (!consumption.ok) {
      const provenanceRefusals: PlanConsumeRefusal[] = [
        'runner_not_privileged',
        'principal_not_attested',
        'registered_at_more_permissive_level',
      ];
      return {
        granted: false,
        reason: provenanceRefusals.includes(consumption.code)
          ? `Plan provenance rejected: ${consumption.reason}`
          : `Plan validation failed: ${consumption.reason}`,
      };
    }

    return {
      granted: true,
      reason: `Auto-upgrade granted for migration plan ${req.plan_id} (${classifications.length} statement(s) verified)`,
    };
  }
}

/**
 * The database this request is actually about.
 *
 * Prefers the resolved identity the dispatcher looked up over the pair the frame
 * asserted. Both halves are required: a scope missing either one is `undefined`,
 * which `PlanRegistry.assertPlanScope` refuses rather than treats as a wildcard.
 */
function resolvedScopeOf(req: ActionRequest): PlanExecutionScope | undefined {
  const project = req.resolved_project ?? req.project;
  const dbAlias = req.resolved_db_alias ?? req.db_alias;
  if (typeof project !== 'string' || project.length === 0) return undefined;
  if (typeof dbAlias !== 'string' || dbAlias.length === 0) return undefined;
  return { project, db_alias: dbAlias };
}
