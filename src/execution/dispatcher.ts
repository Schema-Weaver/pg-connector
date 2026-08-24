import * as crypto from 'crypto';
import { AgentMessage } from '../protocol/envelope';
import { PoolManager, PoolError } from './pool';
import { QueryRunner } from './query-runner';
import { MigrationRunner } from './migration-runner';
import { Canceller } from './canceller';
import { Introspector } from './introspection';
import { DbEntry } from '../config/db-config';
import {
  QueryPayload,
  StreamQueryPayload,
  MigrationRunPayload,
  IntrospectPayload,
  CancelPayload,
  EventPayload,
  ApprovalResponseEvent
} from '../protocol/messages';
import { makeError, ErrorCode } from '../protocol/errors';
import { PermissionChecker } from '../permissions/checker';
import { PlanRegistry } from '../permissions/plan-registry';
import { MachineConfig } from '../config/machine-config';
import { classifyStatement } from './statement-classifier';
import { hasCapability } from '../permissions/role-policy';
import { PermissionDecision } from '../permissions/types';
import { AuditSink } from '../audit/sink';
import { AuditAction } from '../audit/types';
import { fingerprintStatement, previewStatement } from '../audit/redact';

export interface DispatcherOptions {
  poolManager: PoolManager;
  queryRunner: QueryRunner;
  migrationRunner: MigrationRunner;
  canceller: Canceller;
  introspector: Introspector;
  permissionChecker: PermissionChecker;
  planRegistry: PlanRegistry;
  /** Look up DB entry by project name (one DB per project), falling back to db_alias. */
  lookupDb: (project: string, alias?: string) => DbEntry | null;
  /** Look up machine config (for default permission). */
  getMachineConfig: () => MachineConfig;
  /** Send a message back to the browser. */
  send: (msg: AgentMessage) => Promise<void>;
  /** Optional audit sink for logging decisions and outcomes. */
  auditSink?: AuditSink;
}

export class Dispatcher {
  private readonly opts: DispatcherOptions;

  constructor(opts: DispatcherOptions) {
    this.opts = opts;
  }

  private async sendResponse(msg: AgentMessage, payload: unknown): Promise<void> {
    await this.opts.send({
      v: 1,
      id: crypto.randomUUID(),
      type: 'response',
      project: msg.project,
      user: msg.user,
      db_alias: msg.db_alias,
      ts: Date.now(),
      payload: {
        request_id: msg.id,
        ...(payload as object),
      },
    });
  }

  private async sendError(msg: AgentMessage, code: ErrorCode, message: string, pg_error?: { code: string; severity: string; detail?: string; hint?: string; position?: number }): Promise<void> {
    await this.opts.send({
      v: 1,
      id: crypto.randomUUID(),
      type: 'error',
      project: msg.project,
      user: msg.user,
      db_alias: msg.db_alias,
      ts: Date.now(),
      payload: makeError(code, msg.id, { message, pg_error }),
    });
  }

  async handlePlanRegister(msg: AgentMessage, statements: string[], riskLevel?: 'low' | 'medium' | 'high'): Promise<void> {
    const planId = `plan_${crypto.randomUUID()}`;
    this.opts.planRegistry.register(planId, statements, msg.user.id, riskLevel);
    
    if (this.opts.auditSink) {
      await this.opts.auditSink.logSync({
        id: msg.id,
        project: msg.project,
        user_id: msg.user.id,
        role: msg.user.role,
        action: 'plan_register',
        decision: 'allow',
        outcome: 'n/a',
        permission_level: 'full',
        migration_plan_id: planId,
        statement_preview: previewStatement(statements.join('; ')),
      });
    }
    
    await this.sendResponse(msg, {
      ok: true,
      data: { plan_id: planId, expires_in_ms: 300_000 },
    });
  }

  async handle(msg: AgentMessage): Promise<void> {
    const dbEntry = this.opts.lookupDb(msg.project, msg.db_alias);
    const abortController = new AbortController();
    const startTime = Date.now();

    try {
      if (!dbEntry && msg.type !== 'ping') {
        return this.sendError(msg, 'db_unavailable', `Database configuration not found for project "${msg.project}"`);
      }

      const machineConfig = this.opts.getMachineConfig();
      const permissionLevel = dbEntry ? (dbEntry.permission_override ?? machineConfig.default_permission) : machineConfig.default_permission;

      if (msg.type === 'ping') {
        return this.sendResponse(msg, { ok: true, data: { agent_time: Date.now() } });
      }

      if (msg.type === 'cancel') {
        const canCancel = hasCapability(msg.user.role, 'cancel');
        if (!canCancel) {
          if (this.opts.auditSink) {
            await this.opts.auditSink.logSync({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'cancel',
              decision: 'deny',
              outcome: 'n/a',
              permission_level: permissionLevel,
              denial_reason: 'role_denied',
            });
          }
          return this.sendError(msg, 'role_insufficient', `Role '${msg.user.role}' cannot cancel requests`);
        }

        const targetId = (msg.payload as CancelPayload).target_id;
        const targetReq = this.opts.canceller.getInFlight().get(targetId);
        
        if (!targetReq) {
          if (this.opts.auditSink) {
            await this.opts.auditSink.logSync({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'cancel',
              decision: 'deny',
              outcome: 'n/a',
              permission_level: permissionLevel,
              denial_reason: 'cancel_target_not_found',
            });
          }
          return this.sendError(msg, 'cancel_target_not_found', `No in-flight request matches the target_id.`);
        }

        const targetDbEntry = this.opts.lookupDb(targetReq.message?.project || msg.project, targetReq.message?.db_alias || msg.db_alias);
        if (!targetDbEntry) {
          throw new PoolError('connection_failed', 'Project database configuration not found.');
        }

        if (this.opts.auditSink) {
          await this.opts.auditSink.logSync({
            project: msg.project,
            user_id: msg.user.id,
            role: msg.user.role,
            action: 'cancel',
            decision: 'allow',
            outcome: 'n/a',
            permission_level: permissionLevel,
          });
        }

        const cancelResult = await this.opts.canceller.cancel(targetId, targetDbEntry);
        const elapsedMs = Date.now() - startTime;
        
        if (this.opts.auditSink) {
          this.opts.auditSink.log({
            id: msg.id,
            project: msg.project,
            user_id: msg.user.id,
            role: msg.user.role,
            action: 'cancel',
            decision: 'allow',
            outcome: 'success',
            permission_level: permissionLevel,
            duration_ms: elapsedMs,
          });
        }
        
        return this.sendResponse(msg, {
          request_id: msg.id,
          ok: true,
          data: cancelResult,
        });
      }

      if (msg.type === 'event') {
        const payload = msg.payload as EventPayload;
        if (payload.kind === 'plan_register') {
          const data = payload.data as unknown as { statements: string[]; risk_level?: 'low' | 'medium' | 'high'; riskLevel?: 'low' | 'medium' | 'high' };
          await this.handlePlanRegister(msg, data.statements, data.risk_level || data.riskLevel);
          return;
        }
        if (payload.kind === 'approval_response') {
          const data = payload.data as ApprovalResponseEvent;
          const handled = this.opts.permissionChecker.opts.manualApprovalHandler.handleResponse(data);
          
          if (this.opts.auditSink && handled) {
            await this.opts.auditSink.logSync({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'manual_approval',
              decision: data.approved ? 'approved' : 'rejected',
              outcome: 'n/a',
              permission_level: permissionLevel,
            });
          }
          
          await this.sendResponse(msg, { ok: true, data: { handled } });
          return;
        }
        throw new Error(`invalid_message: Agent does not accept event kind '${payload.kind}'`);
      }

      let sql = '';
      let statements: string[] | undefined;
      let intent: 'read' | 'write' | 'ddl' | 'migration' = 'read';
      let planId: string | undefined;

      if (msg.type === 'query' || msg.type === 'stream_query') {
        const payload = msg.payload as QueryPayload | StreamQueryPayload;
        sql = payload.sql;
        intent = payload.intent;
        planId = payload.plan_id;
      } else if (msg.type === 'migration_run') {
        const payload = msg.payload as MigrationRunPayload;
        statements = payload.statements;
        sql = statements[0] ?? '';
        intent = 'migration';
        planId = payload.plan_id;
      } else if (msg.type === 'introspect') {
        if (!hasCapability(msg.user.role, 'introspect')) {
          if (this.opts.auditSink) {
            await this.opts.auditSink.logSync({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'introspect',
              decision: 'deny',
              outcome: 'n/a',
              permission_level: permissionLevel,
              denial_reason: 'role_denied',
            });
          }
          return this.sendError(msg, 'role_insufficient', `Role '${msg.user.role}' cannot introspect`);
        }
        
        if (this.opts.auditSink) {
          await this.opts.auditSink.logSync({
            project: msg.project,
            user_id: msg.user.id,
            role: msg.user.role,
            action: 'introspect',
            decision: 'allow',
            outcome: 'n/a',
            permission_level: permissionLevel,
          });
        }
        
        const result = await this.opts.introspector.introspect(msg.payload as IntrospectPayload, dbEntry!);
        const elapsedMs = Date.now() - startTime;
        
        if (this.opts.auditSink) {
          this.opts.auditSink.log({
            id: msg.id,
            project: msg.project,
            user_id: msg.user.id,
            role: msg.user.role,
            action: 'introspect',
            decision: 'allow',
            outcome: 'success',
            permission_level: permissionLevel,
            duration_ms: elapsedMs,
          });
        }

        await this.sendResponse(msg, {
          request_id: msg.id,
          ok: true,
          data: result,
        });
        return;
      } else {
        return this.sendError(msg, 'invalid_message', `Cannot handle message type '${msg.type}' from browser`);
      }

      if (msg.type === 'query' || msg.type === 'stream_query' || msg.type === 'migration_run') {
        const classification = classifyStatement(sql);
        const decision = await this.opts.permissionChecker.check({
          role: msg.user.role,
          permission_level: permissionLevel,
          classification,
          sql,
          intent,
          plan_id: planId,
          message_type: msg.type,
          request_id: msg.id,
          db_alias: msg.db_alias,
          project: msg.project,
          user: msg.user,
        }, statements);

        if (!decision.allowed) {
          let errorCode = mapDecisionCodeToErrorCode(decision.code);
          let isManualApprovalFailure = false;
          if (decision.code === 'permission_denied' && decision.reason === 'timeout') {
            errorCode = 'MANUAL_APPROVAL_TIMEOUT';
            isManualApprovalFailure = true;
          } else if (decision.code === 'permission_denied' && decision.reason === 'denied') {
            errorCode = 'MANUAL_APPROVAL_REJECTED';
            isManualApprovalFailure = true;
          }

          if (this.opts.auditSink && !isManualApprovalFailure) {
            await this.opts.auditSink.logSync({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: mapMessageTypeToAuditAction(msg.type),
              decision: 'deny',
              outcome: 'n/a',
              permission_level: permissionLevel,
              denial_reason: decision.code,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              migration_plan_id: planId,
            });
          }
          return this.sendError(msg, errorCode, decision.reason);
        }

        if (this.opts.auditSink) {
          await this.opts.auditSink.logSync({
            project: msg.project,
            user_id: msg.user.id,
            role: msg.user.role,
            action: mapMessageTypeToAuditAction(msg.type),
            decision: 'allow',
            outcome: 'n/a',
            permission_level: permissionLevel,
            statement_fingerprint: fingerprintStatement(sql),
            statement_preview: previewStatement(sql),
            migration_plan_id: planId,
          });
        }
      }

      if (msg.type === 'query') {
        try {
          const result = await this.opts.queryRunner.runOneShot(msg.payload as QueryPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            registerInFlight: (req) => {
              req.message = msg;
              this.opts.canceller.register(req);
            },
            unregisterInFlight: (reqId) => {
              this.opts.canceller.unregister(reqId);
            },
            abortSignal: abortController.signal,
          });
          
          const elapsedMs = Date.now() - startTime;
          
          if (this.opts.auditSink) {
            this.opts.auditSink.log({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'query',
              decision: 'allow',
              outcome: 'success',
              permission_level: permissionLevel,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              rows_affected: result.rows_affected,
              rows_returned: result.rows?.length ?? 0,
            });
          }

          await this.sendResponse(msg, {
            request_id: msg.id,
            ok: true,
            data: result,
          });
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string; name?: string };
          
          if (this.opts.auditSink) {
            const outcome: 'error' | 'cancelled' = (errorObj.name === 'QueryCancelledError' || errorObj.code === '57014') ? 'cancelled' : 'error';
            this.opts.auditSink.log({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'query',
              decision: 'allow',
              outcome,
              permission_level: permissionLevel,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: errorObj.code ?? 'INTERNAL',
            });
          }
          throw err;
        }
      } else if (msg.type === 'stream_query') {
        try {
          await this.opts.queryRunner.runStreaming(msg.payload as StreamQueryPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            registerInFlight: (req) => {
              req.message = msg;
              this.opts.canceller.register(req);
            },
            unregisterInFlight: (reqId) => {
              this.opts.canceller.unregister(reqId);
            },
            onChunk: async (chunk) => {
              await this.opts.send({
                v: 1,
                id: crypto.randomUUID(),
                type: 'stream_chunk',
                project: msg.project,
                user: msg.user,
                db_alias: msg.db_alias,
                ts: Date.now(),
                payload: chunk,
              });
            },
            onEnd: async (end) => {
              const elapsedMs = Date.now() - startTime;
              
              if (this.opts.auditSink) {
                this.opts.auditSink.log({
                  id: msg.id,
                  project: msg.project,
                  user_id: msg.user.id,
                  role: msg.user.role,
                  action: 'stream_query',
                  decision: 'allow',
                  outcome: 'success',
                  permission_level: permissionLevel,
                  statement_fingerprint: fingerprintStatement(sql),
                  statement_preview: previewStatement(sql),
                  duration_ms: elapsedMs,
                  rows_returned: end.total_rows,
                });
              }
              
              await this.opts.send({
                v: 1,
                id: crypto.randomUUID(),
                type: 'stream_end',
                project: msg.project,
                user: msg.user,
                db_alias: msg.db_alias,
                ts: Date.now(),
                payload: end,
              });
            },
            abortSignal: abortController.signal,
          });
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string; name?: string };
          
          if (this.opts.auditSink) {
            const outcome: 'error' | 'cancelled' = (errorObj.name === 'QueryCancelledError' || errorObj.code === '57014') ? 'cancelled' : 'error';
            
            // Map common stream error names to code format for audit logging
            let errorCode = errorObj.code ?? 'INTERNAL';
            if (errorObj.name === 'StreamTooLargeError') {
              errorCode = 'STREAM_ROW_LIMIT';
            } else if (errorObj.name === 'CellSizeLimitError') {
              errorCode = 'CELL_SIZE_LIMIT';
            }
            
            this.opts.auditSink.log({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'stream_query',
              decision: 'allow',
              outcome,
              permission_level: permissionLevel,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: errorCode,
            });
          }
          throw err;
        }
      } else if (msg.type === 'migration_run') {
        try {
          const result = await this.opts.migrationRunner.run(msg.payload as MigrationRunPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            project: msg.project,
            user: msg.user,
            db_alias: msg.db_alias,
            registerInFlight: (req) => {
              req.message = msg;
              this.opts.canceller.register(req);
            },
            unregisterInFlight: (reqId) => {
              this.opts.canceller.unregister(reqId);
            },
            onProgress: async (progress) => {
              await this.opts.send(progress);
            },
            abortSignal: abortController.signal,
          });
          
          const elapsedMs = Date.now() - startTime;
          
          if (this.opts.auditSink) {
            this.opts.auditSink.log({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'migration_run',
              decision: 'allow',
              outcome: result.status === 'committed' ? 'success' : 'error',
              permission_level: permissionLevel,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              migration_plan_id: planId,
            });
          }

          if (result.status === 'rolled_back') {
            const failedStmt = result.statements.find(s => s.status === 'failed');
            const errorMsg = failedStmt?.error || 'A migration statement failed.';
            const pgCode = failedStmt?.pg_error_code;
            const pg_error = pgCode ? { code: pgCode, severity: 'ERROR' } : undefined;
            return this.sendError(msg, 'migration_statement_failed', errorMsg, pg_error);
          }

          await this.sendResponse(msg, {
            request_id: msg.id,
            ok: true,
            data: result,
          });
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string };
          
          if (this.opts.auditSink) {
            this.opts.auditSink.log({
              id: msg.id,
              project: msg.project,
              user_id: msg.user.id,
              role: msg.user.role,
              action: 'migration_run',
              decision: 'allow',
              outcome: 'error',
              permission_level: permissionLevel,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: errorObj.code ?? 'INTERNAL',
              migration_plan_id: planId,
            });
          }
          throw err;
        }
      }

    } catch (err: unknown) {
      const errorPayload = this.mapErrorToPayload(err, msg.id);
      await this.opts.send({
        v: 1,
        id: crypto.randomUUID(),
        type: 'error',
        project: msg.project,
        user: msg.user,
        db_alias: msg.db_alias,
        ts: Date.now(),
        payload: errorPayload,
      });
    }
  }

  private mapErrorToPayload(err: unknown, requestId: string): unknown {
    if (err instanceof PoolError) {
      const code = err.code;
      if (code === 'env_var_missing') {
        return makeError('env_var_missing', requestId, { message: err.message });
      }
      if (code === 'connection_failed') {
        return makeError('db_unavailable', requestId, { message: err.message });
      }
      if (code === 'auth_failed') {
        return makeError('db_auth_failed', requestId, { message: err.message });
      }
      if (code === 'db_not_found') {
        return makeError('db_unavailable', requestId, { message: err.message });
      }
      if (code === 'ssl_error') {
        return makeError('db_ssl_error', requestId, { message: err.message });
      }
    }

    const errorObj = err as {
      name?: string;
      code?: string;
      message?: string;
      severity?: string;
      detail?: string;
      hint?: string;
      position?: string;
    };

    if (errorObj.name === 'QueryTooLargeError') {
      return makeError('query_too_large', requestId, { message: errorObj.message });
    }

    if (errorObj.name === 'StreamTooLargeError') {
      return makeError('STREAM_ROW_LIMIT', requestId, { message: errorObj.message });
    }

    if (errorObj.name === 'CellSizeLimitError') {
      return makeError('CELL_SIZE_LIMIT', requestId, { message: errorObj.message });
    }

    if (errorObj.name === 'MigrationInProgressError') {
      return makeError('migration_in_progress', requestId, { message: errorObj.message });
    }

    if (errorObj.name === 'QueryCancelledError' || errorObj.code === '57014') {
      return makeError('query_cancelled', requestId, { message: errorObj.message || 'Query was cancelled' });
    }

    if (errorObj.message && errorObj.message.startsWith('invalid_message:')) {
      return makeError('invalid_message', requestId, { message: errorObj.message });
    }

    if (errorObj.message && errorObj.message.startsWith('unknown_message_type:')) {
      return makeError('unknown_message_type', requestId, { message: errorObj.message });
    }

    if (errorObj.severity !== undefined && errorObj.code !== undefined) {
      const pg_error = {
        code: String(errorObj.code),
        severity: String(errorObj.severity),
        detail: errorObj.detail || undefined,
        hint: errorObj.hint || undefined,
        position: errorObj.position ? parseInt(errorObj.position, 10) : undefined,
      };

      if (errorObj.code === '40P01') {
        return makeError('execution_failed', requestId, {
          pg_error,
          message: 'Deadlock detected: ' + errorObj.message,
        });
      }

      return makeError('execution_failed', requestId, {
        pg_error,
        message: errorObj.message,
      });
    }

    return makeError('internal_error', requestId, { message: errorObj.message || String(err) });
  }
}

function mapDecisionCodeToErrorCode(code: PermissionDecision['code']): ErrorCode {
  switch (code) {
    case 'role_insufficient':
      return 'role_insufficient';
    case 'permission_denied':
      return 'permission_denied';
    case 'approval_required':
      return 'approval_timeout';
    case 'plan_not_registered':
      return 'migration_plan_not_registered';
    case 'intent_mismatch':
      return 'permission_denied';
    default:
      return 'permission_denied';
  }
}

function mapMessageTypeToAuditAction(msgType: string): AuditAction {
  switch (msgType) {
    case 'query':
      return 'query';
    case 'stream_query':
      return 'stream_query';
    case 'migration_run':
      return 'migration_run';
    default:
      return 'query';
  }
}
