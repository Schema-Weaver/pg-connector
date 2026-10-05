import { Role } from '../protocol/envelope';
import { PermissionLevel } from '../permissions/types';

export type AuditAction =
  | 'query'
  | 'stream_query'
  | 'migration_run'
  | 'cancel'
  | 'introspect'
  | 'plan_register'
  | 'manual_approval'
  | 'audit_overflow';

export type AuditDecision =
  | 'allow'
  | 'deny'
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired';

export type AuditOutcome =
  | 'success'
  | 'error'
  | 'cancelled'
  | 'n/a';

export interface AuditEvent {
  id: string;
  ts: string;
  agent_id: string;
  project: string;
  user_id: string;
  role: Role;
  action: AuditAction;
  decision: AuditDecision;
  outcome: AuditOutcome;
  statement_fingerprint?: string;
  statement_preview?: string;
  permission_level: PermissionLevel;
  denial_reason?: string;
  error_code?: string;
  duration_ms?: number;
  rows_affected?: number;
  rows_returned?: number;
  migration_plan_id?: string;
  prev_hash: string;
  hash: string;
}

export interface AuditFilter {
  project?: string;
  user_id?: string;
  action?: AuditAction;
  decision?: AuditDecision;
  outcome?: AuditOutcome;
  since?: string;
  until?: string;
  limit?: number;
}

export interface AuditQueryResult {
  events: AuditEvent[];
  total: number;
  chain_intact: boolean;
  broken_at?: number;
}
