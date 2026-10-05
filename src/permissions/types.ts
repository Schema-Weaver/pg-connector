import { Role } from '../protocol/envelope';
import { StatementClassification } from '../execution/types';

export type PermissionLevel = 'read_only' | 'auto_upgrade' | 'manual' | 'full';

/** What the user is trying to do. */
export interface ActionRequest {
  /** The user's role in the workspace. */
  role: Role;
  /** Effective permission level (already resolved from override + default). */
  permission_level: PermissionLevel;
  /** Classified SQL (from statement-classifier). */
  classification: StatementClassification;
  /** Original SQL (for re-validation if needed). */
  sql: string;
  /** Browser-claimed intent (advisory only — we re-parse to verify). */
  intent: 'read' | 'write' | 'ddl' | 'migration';
  /** If intent=migration, the plan_id claimed by browser. */
  plan_id?: string;
  /** The message type (query, stream_query, migration_run, etc.). */
  message_type: string;
  /** The request_id (for tracking approval). */
  request_id: string;
  /** Which DB alias this targets. */
  db_alias: string;
  /** The project name. */
  project: string;
  /** The user context. */
  user: { id: string; role: Role };
}

/** Outcome of a permission check. */
export interface PermissionDecision {
  /** Whether the action can proceed. */
  allowed: boolean;
  /** Why allowed or denied. */
  reason: string;
  /** Stable code for audit + browser UI. */
  code:
    | 'allowed'
    | 'role_insufficient'
    | 'permission_denied'
    | 'approval_required'
    | 'plan_not_registered'
    | 'intent_mismatch'
    | 'auto_upgrade_granted';
  /** If code='approval_required', this is the approval request to send to browser. */
  approval_request?: {
    request_id: string;
    sql: string;
    sql_preview: string;
    intent: 'write' | 'ddl' | 'migration';
    db_alias: string;
    expires_at: number;
  };
}

/** Result of auto-upgrade evaluation. */
export interface AutoUpgradeResult {
  /** Whether the auto-upgrade was granted. */
  granted: boolean;
  /** Why granted or denied. */
  reason: string;
}

/** Result of manual approval flow. */
export interface ManualApprovalResult {
  /** Whether approval was given. */
  approved: boolean;
  /** Who approved/denied (user_id). */
  approved_by?: string;
  /** Why not approved (timeout, denied, etc.). */
  reason?: string;
}
