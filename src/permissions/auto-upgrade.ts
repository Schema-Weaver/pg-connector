import { ActionRequest, AutoUpgradeResult } from './types';
import { PlanRegistry } from './plan-registry';
import { hasCapability } from './role-policy';
import { classifyStatement } from '../execution/statement-classifier';

export interface AutoUpgradeOptions {
  planRegistry: PlanRegistry;
}

export class AutoUpgradeChecker {
  private readonly opts: AutoUpgradeOptions;

  constructor(opts: AutoUpgradeOptions) {
    this.opts = opts;
  }

  /**
   * Check if auto-upgrade should be granted for this request.
   * Only meaningful when permission_level === 'auto_upgrade'.
   */
  check(req: ActionRequest, statements?: string[]): AutoUpgradeResult {
    // Rule 1: must be a migration_run message
    if (req.message_type !== 'migration_run') {
      return {
        granted: false,
        reason: `Auto-upgrade only available for migration_run, got ${req.message_type}`,
      };
    }

    // Rule 4: role must allow migration_run
    if (!hasCapability(req.role, 'migration_run')) {
      return {
        granted: false,
        reason: `Role ${req.role} cannot run migrations`,
      };
    }

    // Rule 2: plan_id must be registered and valid
    if (!req.plan_id) {
      return {
        granted: false,
        reason: 'No plan_id provided for migration_run',
      };
    }

    if (!statements || statements.length === 0) {
      return {
        granted: false,
        reason: 'No statements provided for validation',
      };
    }

    const validation = this.opts.planRegistry.validate(req.plan_id, statements);
    if (!validation.valid) {
      return {
        granted: false,
        reason: `Plan validation failed: ${validation.reason}`,
      };
    }

    // Rule 3: statements must be DDL or migration (not just read)
    for (const stmt of statements) {
      const c = classifyStatement(stmt);
      if (c.type === 'read') {
        return {
          granted: false,
          reason: `Migration plan contains a read-only statement: ${c.verb}. Auto-upgrade not granted for reads.`,
        };
      }
      if (c.type === 'unknown') {
        // safe default: reject
        return {
          granted: false,
          reason: `Migration plan contains an unclassifiable statement: ${c.verb}`,
        };
      }
    }

    return {
      granted: true,
      reason: `Auto-upgrade granted for migration plan ${req.plan_id}`,
    };
  }
}
