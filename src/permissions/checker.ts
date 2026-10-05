import { ActionRequest, PermissionDecision, PermissionLevel } from './types';
import {
  hasCapability,
  capabilityForClassification,
  capabilityForMessageType,
} from './role-policy';
import { AutoUpgradeChecker } from './auto-upgrade';
import { ManualApprovalHandler } from './manual-approval';
import { PlanRegistry } from './plan-registry';
import { classifyStatement } from '../execution/statement-classifier';

export { PermissionLevel };

export interface PermissionCheckerOptions {
  autoUpgradeChecker: AutoUpgradeChecker;
  manualApprovalHandler: ManualApprovalHandler;
  planRegistry: PlanRegistry;
}

export class PermissionChecker {
  public readonly opts: PermissionCheckerOptions;

  constructor(opts: PermissionCheckerOptions) {
    this.opts = opts;
  }

  /**
   * Check if a request should be allowed.
   * This is the ONLY method the dispatcher calls.
   *
   * For 'approval_required' decisions, this method ALSO triggers the approval
   * flow (sends the event to browser). The dispatcher awaits the result.
   */
  async check(
    req: ActionRequest,
    statements?: string[],
  ): Promise<PermissionDecision> {
    // Step 1: Anti-spoofing — re-classify the SQL, don't trust browser intent
    const actualClassification = classifyStatement(req.sql);
    if (req.intent !== actualClassification.type && req.intent !== 'migration') {
      // Browser claimed intent=read but SQL is actually write → reject
      return {
        allowed: false,
        reason: `Intent mismatch: browser claimed '${req.intent}' but SQL is '${actualClassification.type}'`,
        code: 'intent_mismatch',
      };
    }

    // Step 2: Role check — does the role allow this action at all?
    const messageTypeCap = capabilityForMessageType(req.message_type);
    if (messageTypeCap && !hasCapability(req.role, messageTypeCap)) {
      return {
        allowed: false,
        reason: `Role '${req.role}' cannot perform '${messageTypeCap}'`,
        code: 'role_insufficient',
      };
    }

    const classificationCap = capabilityForClassification(actualClassification);
    if (classificationCap && !hasCapability(req.role, classificationCap)) {
      return {
        allowed: false,
        reason: `Role '${req.role}' cannot run '${actualClassification.type}' statements`,
        code: 'role_insufficient',
      };
    }

    // Step 3: Permission level check
    switch (req.permission_level) {
      case 'full':
        // Everything allowed (role check already passed)
        return { allowed: true, reason: 'Full permission', code: 'allowed' };

      case 'read_only':
        // Only reads allowed
        if (actualClassification.type === 'read') {
          return {
            allowed: true,
            reason: 'Read allowed in read_only mode',
            code: 'allowed',
          };
        }
        return {
          allowed: false,
          reason: `Read-only mode: cannot run '${actualClassification.type}' statement`,
          code: 'permission_denied',
        };

      case 'auto_upgrade': {
        // Reads always allowed
        if (actualClassification.type === 'read') {
          return { allowed: true, reason: 'Read allowed', code: 'allowed' };
        }

        // Writes/ddl only if this is a valid migration run
        const upgrade = this.opts.autoUpgradeChecker.check(req, statements);
        if (upgrade.granted) {
          return {
            allowed: true,
            reason: upgrade.reason,
            code: 'auto_upgrade_granted',
          };
        }
        return {
          allowed: false,
          reason: `Auto-upgrade not granted: ${upgrade.reason}`,
          code: 'plan_not_registered',
        };
      }

      case 'manual': {
        // Reads always allowed
        if (actualClassification.type === 'read') {
          return { allowed: true, reason: 'Read allowed', code: 'allowed' };
        }

        // Everything else needs approval
        const expiresAt = Date.now() + 60_000;
        const approvalRequest = {
          request_id: req.request_id,
          sql: req.sql,
          sql_preview: req.sql.substring(0, 200),
          intent: actualClassification.type as 'write' | 'ddl' | 'migration',
          db_alias: req.db_alias,
          expires_at: expiresAt,
        };

        // Trigger the approval flow (this sends the event to browser)
        const approval = await this.opts.manualApprovalHandler.requestApproval({
          ...approvalRequest,
          project: req.project,
          user: req.user,
        });

        if (approval.approved) {
          return { allowed: true, reason: 'Approved by user', code: 'allowed' };
        }
        return {
          allowed: false,
          reason: approval.reason || 'Approval denied',
          code: 'permission_denied',
          approval_request: approvalRequest,
        };
      }
      default:
        return {
          allowed: false,
          reason: `Invalid permission level '${req.permission_level}'`,
          code: 'permission_denied',
        };
    }
  }
}
