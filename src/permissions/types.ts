import { Role } from '../protocol/envelope';
import { StatementClassification } from '../execution/types';

export type PermissionLevel = 'read_only' | 'auto_upgrade' | 'manual' | 'full';

/** What the user is trying to do. */
export interface ActionRequest {
  /** The user's role in the workspace. */
  role: Role;
  /** Effective permission level (already resolved from override + default). */
  permission_level: PermissionLevel;
  /** Original SQL. */
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
  /**
   * The RESOLVED database identity, when the caller has resolved it.
   *
   * `project` and `db_alias` above are what the frame *claimed*; these are what
   * the agent actually looked up. The audit trail records the resolved pair, and
   * a plan is bound to the resolved pair, so a frame that names one database
   * while executing against another cannot satisfy a plan registered against
   * either. Omitted only by callers with no resolution step (the local CLI,
   * tests), where the claimed values are the only ones there are.
   */
  resolved_project?: string;
  resolved_db_alias?: string;
  /** The user context. */
  user: { id: string; role: Role };
  /**
   * Approval nonce for this request. Agent-minted only: `ManualApprovalHandler`
   * mints it locally when the approval is parked, so a value arriving from the
   * wire must never populate this field. It is recorded here so a decision can
   * be correlated with the approval event that carried it.
   */
  approval_nonce?: string;
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
    | 'plan_not_registered'
    | 'intent_mismatch'
    | 'auto_upgrade_granted'
    /** PostgreSQL could not parse the statement; denied rather than guessed. */
    | 'unparseable_statement'
    /** The parser found more than one statement; refused outright. */
    | 'multiple_statements'
    /** The parser could not be loaded; denied rather than falling back. */
    | 'parser_unavailable'
    /**
     * `intent: 'migration'` was claimed on a message that is not a
     * `migration_run`. The value is meaningful only on that path, so the claim
     * is refused instead of being treated as an exemption from anti-spoofing.
     */
    | 'intent_not_applicable';
  /**
   * The classification the decision was based on. Returned so the execution
   * layer uses the exact same verdict rather than re-parsing and possibly
   * disagreeing.
   */
  classification?: StatementClassification;
  /** Populated when approval was requested and refused/expired. */
  approval_request?: {
    request_id: string;
    /**
     * Redacted and length-capped. The full statement text must never leave the
     * agent: it can carry PII literals that the cloud and the browser's audit
     * view would otherwise store.
     */
    sql_preview: string;
    intent: 'write' | 'ddl';
    db_alias: string;
  };
}

/**
 * Refusal of a `plan_register` event, produced by `PlanRegistry` — the single
 * source of truth for who may register a migration plan and at what level.
 */
export type PlanRegistrationRefusal =
  | 'read_only_permission_level'
  | 'role_lacks_migration_run'
  | 'unattested_principal'
  /** the registration did not name the resolved project and db_alias. */
  | 'unscoped_plan_registration';

/** Why a registered plan may or may not be executed by a given principal. */
export type PlanProvenanceRefusal =
  | 'plan_not_registered'
  | 'plan_expired'
  | 'statements_changed'
  | 'runner_not_privileged'
  | 'registered_at_more_permissive_level'
  | 'principal_not_attested'
  /** the plan is bound to a different project/db_alias than this run. */
  | 'plan_scope_mismatch';

/**
 * Refusal of a single consumption of a plan, produced by
 * `PlanRegistry.consume()`.
 *
 * `plan_already_consumed` is kept separate from `plan_not_registered` on
 * purpose: "you may not run this, it is not yours / not bound to these
 * statements" and "you already ran this" are different operator problems, and
 * collapsing them hides a replay attempt behind a typo. Neither code reveals
 * anything about any *other* plan id.
 */
export type PlanConsumeRefusal = PlanProvenanceRefusal | 'plan_already_consumed';

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
