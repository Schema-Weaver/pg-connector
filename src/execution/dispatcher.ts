import * as crypto from 'crypto';
import { AgentMessage, EventKind, Role } from '../protocol/envelope';
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
  ApprovalResponseEvent,
} from '../protocol/messages';
import { makeError, ERROR_CATALOG, ErrorCode } from '../protocol/errors';
import { PermissionChecker } from '../permissions/checker';
import { PlanRegistry } from '../permissions/plan-registry';
import { MachineConfig } from '../config/machine-config';
import { hasCapability, isStrictlyMorePrivileged } from '../permissions/role-policy';
import type { StatementClassification } from './types';
import { PermissionDecision, PermissionLevel } from '../permissions/types';
import { APPROVAL_STRANDED_SLACK_MS } from '../permissions/manual-approval';
import { AuditSink } from '../audit/sink';
import { AuditAction } from '../audit/types';
import {
  UNRESOLVED_DB_IDENTITY,
  resolvedIdentityOf,
  withResolvedDatabase,
} from '../audit/context';
import { fingerprintStatement, previewStatement } from '../audit/redact';
import { RateLimiter, type RateLimitedAction, type RateLimitPermit } from './rate-limiter';
import {
  normaliseLookupResult,
  type DatabaseLookupRefusal,
  type DatabaseLookupResult,
  type DatabaseRefusalCode,
  type LookupDbFn,
} from './database-lookup';
import { validateMigrationResultPayload } from '../protocol/validate';
import { functionEffectResolverForPool } from './function-effects';
import {
  POOL_ERROR_MESSAGES,
  sanitizeErrorText,
  sanitizePgError,
  sanitizeReason,
  type SanitizeOptions,
} from '../audit/sanitize';

export interface DispatcherOptions {
  poolManager: PoolManager;
  queryRunner: QueryRunner;
  migrationRunner: MigrationRunner;
  canceller: Canceller;
  introspector: Introspector;
  permissionChecker: PermissionChecker;
  planRegistry: PlanRegistry;
  /**
   * Look up the DB entry for a frame's `(project, db_alias)`.
   *
   * Returning the rich `DatabaseLookupResult` lets the caller say *why* a frame
   * resolved to nothing (out of scope, no allow-list configured, or a
   * project/alias collision) so the refusal is audited under a distinct reason
   * instead of a generic "unavailable". A plain `DbEntry | null` is still
   * accepted and is read as "no such database".
   */
  lookupDb: LookupDbFn;
  /** Look up machine config (for default permission). */
  getMachineConfig: () => MachineConfig;
  /** Send a message back to the browser. */
  send: (msg: AgentMessage) => Promise<void>;
  /**
   * Transport drain signal, awaited by the streaming fetch loop before every
   * cursor fetch (audit H-10). Supplying it is what makes the pause/resume real:
   * `send` alone only stops the producer when the socket write callback fires,
   * which cannot see bytes already queued in the transport.
   *
   * Optional by design. Without it a stream still completes — it just
   * self-throttles on each awaited chunk send instead of the send buffer.
   */
  waitForDrain?: () => Promise<void>;
  /** Optional audit sink for logging decisions and outcomes. */
  auditSink?: AuditSink;
  /**
   * Budget and concurrency control for inbound work. Defaults to a process-wide
   * limiter; an explicit instance is only for tests and for a host that wants
   * its own policy.
   */
  rateLimiter?: RateLimiter;
}

export class Dispatcher {
  private readonly opts: DispatcherOptions;
  private readonly rateLimiter: RateLimiter;

  constructor(opts: DispatcherOptions) {
    this.opts = opts;
    this.rateLimiter = opts.rateLimiter ?? new RateLimiter();
  }

  private async sendResponse(
    msg: AgentMessage,
    payload: unknown,
    resolvedAlias?: string,
  ): Promise<void> {
    await this.opts.send({
      v: 1,
      id: crypto.randomUUID(),
      type: 'response',
      project: msg.project,
      user: msg.user,
      // The RESOLVED alias, so the browser's view of "which database answered"
      // matches the audit trail. Falling back to the asserted alias is only for
      // frames that resolved to no database at all (`ping`), where there is
      // nothing truer to send.
      db_alias: resolvedAlias ?? msg.db_alias,
      ts: Date.now(),
      payload: {
        request_id: msg.id,
        ...(payload as object),
      },
    });
  }

  /**
   * `pg_error` is deliberately limited to the two allow-listed fields. Passing
   * `detail` or `hint` here is a compile error on purpose: both routinely carry
   * row data (`DETAIL:  Key (email)=(alice@corp.com) already exists.`) and the
   * risk only ever grows.
   */
  private async sendError(
    msg: AgentMessage,
    code: ErrorCode,
    message: string,
    pg_error?: { code: string; severity: string },
    resolvedAlias?: string,
  ): Promise<void> {
    await this.opts.send({
      v: 1,
      id: crypto.randomUUID(),
      type: 'error',
      project: msg.project,
      user: msg.user,
      db_alias: resolvedAlias ?? msg.db_alias,
      ts: Date.now(),
      payload: makeError(code, msg.id, { message, pg_error }),
    });
  }

  /**
   * Register a migration plan. Callers must have passed `evaluateEventGate`;
   * this method re-checks the shape of the payload and never invents an
   * effective permission level for the audit record.
   */
  async handlePlanRegister(
    msg: AgentMessage,
    statements: string[],
    riskLevel: 'low' | 'medium' | 'high' | undefined,
    permissionLevel: PermissionLevel,
    resolvedAlias?: string,
  ): Promise<void> {
    // Re-asserted so the method is safe to call from anywhere, not only from
    // `handleEvent`. Denials are audited by the caller, so nothing is logged
    // twice.
    const gate = this.evaluateGate(msg, permissionLevel);
    if (!gate.allowed) {
      return this.sendError(msg, gate.errorCode, gate.reason, undefined, resolvedAlias);
    }

    if (
      !Array.isArray(statements) ||
      statements.length === 0 ||
      statements.some((s) => typeof s !== 'string' || s.trim().length === 0)
    ) {
      return this.sendError(
        msg,
        'payload_invalid',
        'A migration plan must contain at least one non-empty statement.',
        undefined,
        resolvedAlias,
      );
    }

    const planId = `plan_${crypto.randomUUID()}`;
    // the plan is bound to the RESOLVED database, so a statement set
    // reviewed here cannot later be executed against a different entry. The
    // registry refuses a registration that cannot name one.
    const registered = this.opts.planRegistry.register(planId, statements, msg.user.id, riskLevel, {
      user_id: msg.user.id,
      role: msg.user.role,
      permission_level: permissionLevel,
      project: msg.project,
      db_alias: resolvedAlias ?? msg.db_alias,
    });

    // Fail closed. Without the principal the registry refuses to store
    // anything, and issuing a plan_id for a plan that does not exist would be
    // a lie in the audit trail and a dead end for the browser.
    if (!registered.ok) {
      await this.auditDeny(msg, permissionLevel, {
        action: 'plan_register',
        denial_reason: registered.code,
      });
      return this.sendError(msg, 'permission_denied', registered.reason, undefined, resolvedAlias);
    }

    if (this.opts.auditSink) {
      await this.opts.auditSink.logSync({
        ...this.auditBase(msg, permissionLevel),
        action: 'plan_register',
        decision: 'allow',
        outcome: 'n/a',
        // The level the registration was actually authorised at. This used to
        // be the literal 'full', which misrepresented every registration.
        migration_plan_id: planId,
        statement_preview: previewStatement(statements.join('; ')),
      });
    }

    await this.sendResponse(
      msg,
      {
        ok: true,
        data: { plan_id: planId, expires_in_ms: 300_000 },
      },
      resolvedAlias,
    );
  }

  /**
   * Derive the authorization decision for an inbound `event` frame.
   *
   * `PlanRegistry.canRegister` owns the plan-registration decision, so asking
   * it directly is what keeps the entry gate and the registry from disagreeing.
   */
  private evaluateGate(msg: AgentMessage, permissionLevel: PermissionLevel): EventGateDecision {
    const kind = (msg.payload as EventPayload | undefined)?.kind;
    return evaluateEventGate(kind, msg.user.role, permissionLevel, (role, level) =>
      this.opts.planRegistry.canRegister(role, level),
    );
  }

  /**
   * Handle an inbound `event` frame.
   *
   * Every kind is authorized before any handler runs. The previous
   * implementation dispatched `approval_response` and `plan_register` from the
   * top of `handle()`, ahead of the query/migration permission pipeline, so a
   * `viewer` could resolve another user's pending manual approval and could
   * register an arbitrary migration plan for later replay at `auto_upgrade`.
   */
  private async handleEvent(
    msg: AgentMessage,
    permissionLevel: PermissionLevel,
    resolvedAlias?: string,
  ): Promise<void> {
    const payload = msg.payload as EventPayload;
    const kind: EventKind | undefined = payload?.kind;
    const gate = this.evaluateGate(msg, permissionLevel);

    if (!gate.allowed) {
      if (gate.auditAction) {
        await this.auditDeny(msg, permissionLevel, {
          action: gate.auditAction,
          denial_reason: gate.code,
        });
      }
      return this.sendError(msg, gate.errorCode, gate.reason, undefined, resolvedAlias);
    }

    if (kind === 'plan_register') {
      const data = payload.data as unknown as {
        statements: string[];
        risk_level?: 'low' | 'medium' | 'high';
        riskLevel?: 'low' | 'medium' | 'high';
      };
      return this.handlePlanRegister(
        msg,
        data.statements,
        data.risk_level || data.riskLevel,
        permissionLevel,
        resolvedAlias,
      );
    }

    const data = payload.data as ApprovalResponseEvent;

    // `approved_by` is deliberately not forwarded. It is free text supplied by
    // the sender; the approver recorded in the audit trail comes from the
    // verified envelope via `actorId`, so a spoofed string cannot fabricate an
    // attestation.
    const outcome = this.opts.permissionChecker.opts.manualApprovalHandler.handleResponse(
      {
        request_id: typeof data?.request_id === 'string' ? data.request_id : '',
        approved: data?.approved === true,
        // Forwarded verbatim: the handler consumes it exactly once.
        approval_nonce: typeof data?.approval_nonce === 'string' ? data.approval_nonce : '',
      },
      { actorId: msg.user.id, actorRole: msg.user.role },
    );

    // Every refusal looks identical on the wire. The handler distinguishes
    // "no pending approval", "not the requesting user", "role may not approve"
    // and "nonce mismatch"; returning those reasons would tell an attacker
    // that a request id they chose really does have an approval pending under
    // somebody else's account.
    await this.sendResponse(
      msg,
      {
        ok: outcome.handled,
        data: outcome.handled
          ? { resolved: true, request_id: data.request_id }
          : { resolved: false, reason: 'no matching pending approval' },
      },
      resolvedAlias,
    );
    return;
  }

  /**
   * Handle one inbound frame.
   *
   * The frame's `(project, db_alias)` is resolved first and everything after —
   * every authorization decision, every database call, every audit record —
   * happens inside the resolved-database context. That ordering is the durable
   * half of the  fix: the audit sink takes the resolved identity from the
   * context, so no call site can write the frame's own claim into the record, and
   * a frame that resolves to nothing is recorded as `unresolved` rather than as
   * the database it asked for.
   */
  async handle(msg: AgentMessage): Promise<void> {
    const resolution = normaliseLookupResult(
      this.opts.lookupDb(msg.project, msg.db_alias),
      msg.project,
      msg.db_alias,
    );
    const identity = resolution.ok
      ? resolvedIdentityOf(resolution.entry)
      : UNRESOLVED_DB_IDENTITY;
    return withResolvedDatabase(identity, () => this.handleResolved(msg, resolution));
  }

  /**
   * The fields every audit record for one frame carries.
   *
   * Centralised so the asserted identity (`project`, `db_alias_asserted`) is
   * recorded identically on allows and denials: the resolved identity comes from
   * the sink's context, and these two come from the frame. A record that names
   * what the frame claimed and what the agent resolved is the only way a
   * mismatch like  is visible to anyone reading the trail afterwards.
   */
  private auditBase(msg: AgentMessage, permissionLevel: PermissionLevel) {
    return {
      id: msg.id,
      project: msg.project,
      db_alias_asserted: msg.db_alias,
      user_id: msg.user.id,
      role: msg.user.role,
      permission_level: permissionLevel,
    };
  }

  /** Awaited audit write, or a no-op when no sink is configured. */
  private async auditDeny(
    msg: AgentMessage,
    permissionLevel: PermissionLevel,
    fields: {
      action: AuditAction;
      denial_reason: string;
      outcome?: 'n/a';
      statement_fingerprint?: string;
      statement_preview?: string;
      migration_plan_id?: string;
      cancel_target_user_id?: string;
      cancel_target_project?: string;
      cancel_target_db_alias?: string;
    },
  ): Promise<void> {
    if (!this.opts.auditSink) return;
    await this.opts.auditSink.logSync({
      ...this.auditBase(msg, permissionLevel),
      decision: 'deny',
      outcome: fields.outcome ?? 'n/a',
      ...fields,
    });
  }

  private async handleResolved(
    msg: AgentMessage,
    resolution: DatabaseLookupResult,
  ): Promise<void> {
    const dbEntry = resolution.ok ? resolution.entry : null;
    /**
     * The alias every outbound frame echoes. The RESOLVED one, never `msg.db_alias`:
     * echoing the asserted alias back is how a frame that named one database and
     * ran against another stayed invisible to the browser.
     */
    const resolvedAlias = dbEntry?.db_alias;
    const abortController = new AbortController();
    const startTime = Date.now();
    const machineConfig = this.opts.getMachineConfig();
    const permissionLevel = dbEntry
      ? (dbEntry.permission_override ?? machineConfig.default_permission)
      : machineConfig.default_permission;

    // Admission control runs before any work, including the database: a single
    // authenticated sender must not be able to saturate the connector or the
    // customer's database. The permit is released in the `finally` below, so a
    // rejected or failed request still gives its concurrency slot back.
    const permit = this.rateLimiter.tryAcquire(mapMessageTypeToRateLimitAction(msg.type), {
      agent_id: machineConfig.agent_id,
      user_id: msg.user.id,
      db_alias: dbEntry?.db_alias ?? msg.db_alias ?? '',
    });
    if (!permit.allowed) {
      // Admission control refusals are refusals, and  is the finding that a
      // refusal nothing records is indistinguishable from a request that never
      // arrived. Recorded with the reason code so the trail distinguishes a
      // rate-limit from an authorization decision without leaking which was which
      // to the caller (the wire error stays `rate_limited`).
      await this.auditDeny(msg, permissionLevel, {
        action: mapMessageTypeToAuditAction(msg.type),
        denial_reason: safeAuditReason(permit.reason ?? 'rate_limit_exceeded'),
      });
      return this.sendError(
        msg,
        'rate_limited',
        rateLimitMessage(permit.reason, permit.scope),
        undefined,
        resolvedAlias,
      );
    }

    /**
     * Independent of the approval promise. Released by the watchdog below
     * if the request is still parked on a human when the approval window plus
     * slack has elapsed, so a stranded promise can never hold a concurrency
     * permit forever.
     */
    let watchdog: NodeJS.Timeout | null = null;
    /** Whether this frame already passed an authorization decision. */
    let authorized = false;

    try {
      if (!dbEntry && msg.type !== 'ping') {
        // Every way a frame can fail to resolve a database is now audited under
        // its own reason: unknown entry, out of scope, no allow-list configured,
        // or a project/alias collision (, ).
        const refusal = resolution as DatabaseLookupRefusal;
        await this.auditDeny(msg, permissionLevel, {
          action: mapMessageTypeToAuditAction(msg.type),
          denial_reason: refusal.code,
        });
        return this.sendError(
          msg,
          databaseRefusalErrorCode(refusal.code),
          databaseRefusalMessage(refusal),
          undefined,
          resolvedAlias,
        );
      }

      if (msg.type === 'ping') {
        return this.sendResponse(msg, { ok: true, data: { agent_time: Date.now() } }, resolvedAlias);
      }

      if (msg.type === 'cancel') {
        return this.handleCancel(msg, permissionLevel, resolvedAlias, startTime);
      }

      if (msg.type === 'event') {
        return this.handleEvent(msg, permissionLevel, resolvedAlias);
      }

      let sql = '';
      /** Set from the permission decision so execution cannot disagree with it. */
      let decisionClassification: StatementClassification | undefined;
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
          await this.auditDeny(msg, permissionLevel, {
            action: 'introspect',
            denial_reason: 'role_denied',
          });
          return this.sendError(
            msg,
            'role_insufficient',
            `Role '${msg.user.role}' cannot introspect`,
            undefined,
            resolvedAlias,
          );
        }

        authorized = true;
        if (this.opts.auditSink) {
          await this.opts.auditSink.logSync({
            ...this.auditBase(msg, permissionLevel),
            action: 'introspect',
            decision: 'allow',
            outcome: 'n/a',
          });
        }

        const result = await this.opts.introspector.introspect(
          msg.payload as IntrospectPayload,
          dbEntry!,
        );
        const elapsedMs = Date.now() - startTime;

        // Introspection returns the whole schema, so a caller that loops it is
        // exfiltrating. The rate limiter bounds how often it runs; this bounds
        // how much leaves in one response.
        const sizeVerdict = this.rateLimiter.checkIntrospectSize(serializedSizeOf(result));
        if (!sizeVerdict.allowed) {
          if (this.opts.auditSink) {
            this.opts.auditSink.log({
              ...this.auditBase(msg, permissionLevel),
              action: 'introspect',
              decision: 'allow',
              outcome: 'error',
              duration_ms: elapsedMs,
              error_code: 'RATE_LIMITED',
            });
          }
          return this.sendError(
            msg,
            'rate_limited',
            'Introspection snapshot exceeds the configured response budget. Request a narrower ' +
              'snapshot (for example without triggers or partitions).',
            undefined,
            resolvedAlias,
          );
        }

        if (this.opts.auditSink) {
          this.opts.auditSink.log({
            ...this.auditBase(msg, permissionLevel),
            action: 'introspect',
            decision: 'allow',
            outcome: 'success',
            duration_ms: elapsedMs,
          });
        }

        await this.sendResponse(
          msg,
          {
            request_id: msg.id,
            ok: true,
            data: result,
          },
          resolvedAlias,
        );
        return;
      } else {
        return this.sendError(
          msg,
          'invalid_message',
          `Cannot handle message type '${msg.type}' from browser`,
          undefined,
          resolvedAlias,
        );
      }

      if (msg.type === 'query' || msg.type === 'stream_query' || msg.type === 'migration_run') {
        // a plan is bound to the database it was registered against. The
        // registry cannot see this frame (the `consume()` call is made deeper in
        // the permission pipeline), so the binding is checked here, before any
        // authority is consulted. An unregistered plan id passes: a `migration_run`
        // at `full` legitimately needs no plan.
        if (planId) {
          const scopeVerdict = this.opts.planRegistry.assertExecutionScope(planId, {
            project: dbEntry?.project_name ?? msg.project,
            db_alias: dbEntry?.db_alias ?? '',
          });
          if (!scopeVerdict.ok) {
            await this.auditDeny(msg, permissionLevel, {
              action: mapMessageTypeToAuditAction(msg.type),
              denial_reason: 'plan_scope_mismatch',
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              migration_plan_id: planId,
            });
            return this.sendError(
              msg,
              'plan_scope_mismatch',
              'This migration plan was registered against a different project or database.',
              undefined,
              resolvedAlias,
            );
          }
        }

        // arm the independent watchdog BEFORE the check, because the
        // check is what can park the request on a human. It releases the
        // concurrency permit if the approval is still outstanding after the
        // window plus slack, so permit release never depends on the approval
        // promise settling.
        watchdog = this.armApprovalWatchdog(msg, permissionLevel, permit, { planId, sql });

        // The checker parses; we reuse its verdict rather than parsing again.
        //
        // the function-effect resolver answers "what can the functions
        // this statement calls actually do?" from `pg_proc` on the target
        // database. It is supplied here, and only here, because this is the one
        // place that knows which database the frame resolved to: OIDs — and
        // therefore which overloads exist — are per-database, so a resolver
        // built anywhere else would be answering about the wrong cluster. If it
        // cannot be built (no usable credentials, pool exhausted), the check
        // gets `analysed: false` and every statement that calls a function is
        // escalated rather than trusted.
        const decision = await this.opts.permissionChecker.check(
          {
            role: msg.user.role,
            permission_level: permissionLevel,
            sql,
            intent,
            plan_id: planId,
            message_type: msg.type,
            request_id: msg.id,
            db_alias: msg.db_alias,
            project: msg.project,
            // The RESOLVED pair, so a plan bound to production cannot be run by
            // a frame that names dev and the audit trail names the
            // database the statement actually reached.
            resolved_project: dbEntry?.project_name,
            resolved_db_alias: dbEntry?.db_alias,
            user: msg.user,
          },
          statements,
          dbEntry ? functionEffectResolverForPool(this.opts.poolManager, dbEntry) : undefined,
        );

        decisionClassification = decision.classification;

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
              ...this.auditBase(msg, permissionLevel),
              action: mapMessageTypeToAuditAction(msg.type),
              decision: 'deny',
              outcome: 'n/a',
              denial_reason: safeAuditReason(decision.code),
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              migration_plan_id: planId,
            });
          }
          // `decision.reason` can embed a parser error, and a parser error
          // quotes the SQL that failed — so it is redacted before it goes out.
          return this.sendError(
            msg,
            errorCode,
            sanitizeReason(decision.reason, sanitizeOptions(dbEntry)),
            undefined,
            resolvedAlias,
          );
        }

        authorized = true;
        if (this.opts.auditSink) {
          await this.opts.auditSink.logSync({
            ...this.auditBase(msg, permissionLevel),
            action: mapMessageTypeToAuditAction(msg.type),
            decision: 'allow',
            outcome: 'n/a',
            statement_fingerprint: fingerprintStatement(sql),
            statement_preview: previewStatement(sql),
            migration_plan_id: planId,
          });
        }
      }

      const classification = decisionClassification;

      if (msg.type === 'query') {
        try {
          const result = await this.opts.queryRunner.runOneShot(msg.payload as QueryPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            classification,
            registerInFlight: (req) => {
              req.message = msg;
              // The canceller can only abort `req.abort`, so the controller the
              // runner is already listening on is the one it must be handed.
              // Previously the canceller aborted a controller nobody observed.
              req.abort = abortController;
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
              ...this.auditBase(msg, permissionLevel),
              action: 'query',
              decision: 'allow',
              outcome: 'success',
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              rows_affected: result.rows_affected,
              rows_returned: result.rows?.length ?? 0,
            });
          }

          await this.sendResponse(
            msg,
            {
              request_id: msg.id,
              ok: true,
              data: result,
            },
            resolvedAlias,
          );
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string; name?: string };

          if (this.opts.auditSink) {
            const outcome: 'error' | 'cancelled' =
              errorObj.name === 'QueryCancelledError' || errorObj.code === '57014'
                ? 'cancelled'
                : 'error';
            this.opts.auditSink.log({
              ...this.auditBase(msg, permissionLevel),
              action: 'query',
              decision: 'allow',
              outcome,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: safeAuditCode(errorObj.code),
            });
          }
          throw err;
        }
      } else if (msg.type === 'stream_query') {
        // Exactly one terminal frame per request. A stream that dies partway
        // ends with an `error`; a stream that finished must not be followed by
        // a second `error` because the `stream_end` send itself failed after
        // the frame was written.
        let streamTerminated = false;
        try {
          await this.opts.queryRunner.runStreaming(msg.payload as StreamQueryPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            classification,
            registerInFlight: (req) => {
              req.message = msg;
              req.abort = abortController;
              this.opts.canceller.register(req);
            },
            unregisterInFlight: (reqId) => {
              this.opts.canceller.unregister(reqId);
            },
            // Forwarded verbatim so the runner can observe the transport buffer.
            // Undefined stays undefined: the runner then falls back to the
            // awaited send instead of calling a missing hook.
            waitForDrain: this.opts.waitForDrain,
            onChunk: async (chunk) => {
              // Not swallowed: a rejection here propagates out of the producer,
              // which rolls the cursor back and reaches the catch below, where
              // the terminal `error` frame is emitted.
              await this.opts.send({
                v: 1,
                id: crypto.randomUUID(),
                type: 'stream_chunk',
                project: msg.project,
                user: msg.user,
                db_alias: resolvedAlias ?? msg.db_alias,
                ts: Date.now(),
                payload: chunk,
              });
            },
            onEnd: async (end) => {
              if (streamTerminated) return;

              await this.opts.send({
                v: 1,
                id: crypto.randomUUID(),
                type: 'stream_end',
                project: msg.project,
                user: msg.user,
                db_alias: resolvedAlias ?? msg.db_alias,
                ts: Date.now(),
                payload: end,
              });
              streamTerminated = true;

              const elapsedMs = Date.now() - startTime;

              if (this.opts.auditSink) {
                this.opts.auditSink.log({
                  ...this.auditBase(msg, permissionLevel),
                  action: 'stream_query',
                  decision: 'allow',
                  outcome: 'success',
                  statement_fingerprint: fingerprintStatement(sql),
                  statement_preview: previewStatement(sql),
                  duration_ms: elapsedMs,
                  rows_returned: end.total_rows,
                });
              }
            },
            abortSignal: abortController.signal,
          });
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string; name?: string };

          if (this.opts.auditSink) {
            const outcome: 'error' | 'cancelled' =
              errorObj.name === 'QueryCancelledError' || errorObj.code === '57014'
                ? 'cancelled'
                : 'error';

            // Map common stream error names to code format for audit logging
            let errorCode = safeAuditCode(errorObj.code);
            if (errorObj.name === 'StreamTooLargeError') {
              errorCode = 'STREAM_ROW_LIMIT';
            } else if (errorObj.name === 'CellSizeLimitError') {
              errorCode = 'CELL_SIZE_LIMIT';
            }

            this.opts.auditSink.log({
              ...this.auditBase(msg, permissionLevel),
              action: 'stream_query',
              decision: 'allow',
              outcome,
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: errorCode,
            });
          }

          // A terminal frame already reached the browser. A second one would
          // leave it with two outcomes for a single request.
          if (streamTerminated) return;
          throw err;
        }
      } else if (msg.type === 'migration_run') {
        try {
          const result = await this.opts.migrationRunner.run(msg.payload as MigrationRunPayload, {
            dbEntry: dbEntry!,
            request_id: msg.id,
            project: msg.project,
            user: msg.user,
            db_alias: resolvedAlias ?? msg.db_alias,
            registerInFlight: (req) => {
              req.message = msg;
              req.abort = abortController;
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
              ...this.auditBase(msg, permissionLevel),
              action: 'migration_run',
              decision: 'allow',
              outcome: result.status === 'committed' ? 'success' : 'error',
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              migration_plan_id: planId,
            });
          }

          if (result.status === 'rolled_back') {
            const failedCode = failedStatementCode(result);
            // Curated by SQLSTATE, never the raw node-postgres message: a failed
            // statement's `error` is verbatim `err.message`, which embeds the
            // offending SQL, row values and connection details.
            const pg_error = failedCode ? { code: failedCode, severity: 'ERROR' } : undefined;
            const errorMsg = failedCode
              ? pgMessageForCode(failedCode)
              : 'A migration statement failed.';
            return this.sendError(
              msg,
              'migration_statement_failed',
              errorMsg,
              pg_error,
              resolvedAlias,
            );
          }

          if (result.status === 'partial') {
            // A partial result means statements are already committed on the
            // customer's database and the rest failed. Reporting `ok: true`
            // for that is a data-integrity incident with no rollback path, so
            // it leaves as an error even though the runner considers the run
            // finished. This is deliberately independent of what the runner
            // believes it can achieve.
            const failedCode = failedStatementCode(result);
            const pg_error = failedCode ? { code: failedCode, severity: 'ERROR' } : undefined;
            return this.sendError(
              msg,
              'migration_partial',
              'Migration stopped partway: earlier statements are already committed and were not ' +
                'rolled back. Verify the applied schema before retrying.',
              pg_error,
              resolvedAlias,
            );
          }

          if (
            result.status !== 'committed' &&
            result.status !== 'dry_run_ok' &&
            result.status !== 'dry_run_failed'
          ) {
            throw new Error(`migration_result_unexpected:${String(result.status)}`);
          }

          // The inbound migration_run payload is validated; the result leaving
          // the agent was not. A malformed result is a local fault and must not
          // be presented to the browser as a well-formed success.
          validateMigrationResultPayload(result);

          await this.sendResponse(
            msg,
            {
              request_id: msg.id,
              ok: true,
              data: sanitizeMigrationResult(result, dbEntry),
            },
            resolvedAlias,
          );
        } catch (err: unknown) {
          const elapsedMs = Date.now() - startTime;
          const errorObj = err as { code?: string };

          if (this.opts.auditSink) {
            this.opts.auditSink.log({
              ...this.auditBase(msg, permissionLevel),
              action: 'migration_run',
              decision: 'allow',
              outcome: 'error',
              statement_fingerprint: fingerprintStatement(sql),
              statement_preview: previewStatement(sql),
              duration_ms: elapsedMs,
              error_code: safeAuditCode(errorObj.code),
              migration_plan_id: planId,
            });
          }
          throw err;
        }
      }
    } catch (err: unknown) {
      const errorPayload = this.mapErrorToPayload(err, msg.id, dbEntry);
      // an internal failure reached the browser and must reach the trail
      // too. A path that fails before any authorization decision (or after one)
      // still happened, and "the request vanished" is not an acceptable record.
      if (this.opts.auditSink) {
        const errorObj = err as { code?: string; name?: string };
        this.opts.auditSink.log({
          ...this.auditBase(msg, permissionLevel),
          action: mapMessageTypeToAuditAction(msg.type),
          // Whatever the frame had already been authorised to do. An error
          // before any authorization decision is not a denial of a permitted
          // action, so it is not recorded as one.
          decision: authorized ? 'allow' : 'deny',
          outcome: 'error',
          ...(authorized ? {} : { denial_reason: 'internal_error' }),
          error_code: safeAuditCode(errorObj.code ?? errorObj.name),
          duration_ms: Date.now() - startTime,
        });
      }
      await this.opts.send({
        v: 1,
        id: crypto.randomUUID(),
        type: 'error',
        project: msg.project,
        user: msg.user,
        db_alias: resolvedAlias ?? msg.db_alias,
        ts: Date.now(),
        payload: errorPayload,
      });
    } finally {
      if (watchdog) clearTimeout(watchdog);
      permit.release();
    }
  }

  /**
   * Arm the independent approval watchdog for one request.
   *
   * Returns the timer so the caller can clear it. The watchdog fires only if an
   * approval for THIS request is still outstanding at the handler's reaper
   * deadline; if the request is merely running a long query, or already finished,
   * it does nothing. It releases the concurrency permit — `RateLimitPermit`
   * releases are idempotent, so the ordinary `finally` remains correct — and
   * records `approval_promise_stranded`, because a stranded promise is exactly
   * the condition that used to leak a permit per attack and disable the database
   * for everyone.
   */
  private armApprovalWatchdog(
    msg: AgentMessage,
    permissionLevel: PermissionLevel,
    permit: RateLimitPermit,
    context: { planId?: string; sql?: string } = {},
  ): NodeJS.Timeout {
    const handler = this.opts.permissionChecker.opts?.manualApprovalHandler;
    // Deliberately LATER than the handler's own reaper. The handler settles the
    // approval promise, which makes `isPending` false and retires this watchdog
    // without a second record; the watchdog is the backstop for a handler that
    // cannot settle at all, so exactly one `approval_promise_stranded` record is
    // ever written for one stranding.
    const deadlineMs =
      (handler?.getStrandedReaperMs?.() ?? 0) + APPROVAL_STRANDED_SLACK_MS || 250;
    return setTimeout(() => {
      try {
        if (!handler?.isPending?.(msg.id, msg.user.id)) return;
        permit.release();
        this.opts.auditSink?.log({
          ...this.auditBase(msg, permissionLevel),
          action: mapMessageTypeToAuditAction(msg.type),
          decision: 'deny',
          outcome: 'n/a',
          denial_reason: 'approval_promise_stranded',
          // The same identifying fields every other `migration_run` denial
          // carries. Without them a stranded record says only that *something*
          // was stranded: an investigator cannot tell which plan, or which
          // statement, and a single stray approval in a busy log is
          // indistinguishable from the leak this record exists to catch.
          ...(context.planId ? { migration_plan_id: context.planId } : {}),
          ...(context.sql
            ? {
                statement_fingerprint: fingerprintStatement(context.sql),
                statement_preview: previewStatement(context.sql),
              }
            : {}),
        });
      } catch (err: unknown) {
        console.error('[dispatcher] approval watchdog failed:', err);
      }
    }, deadlineMs);
  }

  /**
   * `cancel`, bound to the request it names.
   *
   * The only gate used to be `hasCapability(role, 'cancel')`, so any developer
   * could abort any other principal's in-flight query in any project, and the
   * target's database was resolved from the ATTACKER's project when the target
   * had none. Two binding conditions are now required on top of the capability:
   * the caller is the requesting principal, or holds a STRICTLY more privileged
   * role. The target's database comes from the target's own frame and nowhere
   * else.
   */
  private async handleCancel(
    msg: AgentMessage,
    permissionLevel: PermissionLevel,
    resolvedAlias: string | undefined,
    startTime: number,
  ): Promise<void> {
    if (!hasCapability(msg.user.role, 'cancel')) {
      await this.auditDeny(msg, permissionLevel, {
        action: 'cancel',
        denial_reason: 'role_denied',
      });
      return this.sendError(
        msg,
        'role_insufficient',
        `Role '${msg.user.role}' cannot cancel requests`,
        undefined,
        resolvedAlias,
      );
    }

    const targetId = (msg.payload as CancelPayload).target_id;
    const targetReq = this.opts.canceller.getInFlight().get(targetId);

    if (!targetReq) {
      await this.auditDeny(msg, permissionLevel, {
        action: 'cancel',
        denial_reason: 'cancel_target_not_found',
      });
      return this.sendError(
        msg,
        'cancel_target_not_found',
        `No in-flight request matches the target_id.`,
        undefined,
        resolvedAlias,
      );
    }

    const targetUser = targetReq.message?.user;
    const targetRole = targetUser?.role;
    // Both principals in the record: the refused caller and the owner of the
    // request they tried to touch. Without the second one the trail attributes
    // the attempt only to the attacker and says nothing about whose work it was.
    const targetFields = {
      cancel_target_user_id: targetUser?.id ?? '',
      cancel_target_project: targetReq.message?.project ?? '',
      cancel_target_db_alias: targetReq.message?.db_alias ?? '',
    };

    const ownsTarget = targetUser !== undefined && targetUser.id === msg.user.id;
    const outranksTarget = targetRole !== undefined && isStrictlyMorePrivileged(msg.user.role, targetRole);
    if (targetUser === undefined || (!ownsTarget && !outranksTarget)) {
      await this.auditDeny(msg, permissionLevel, {
        action: 'cancel',
        denial_reason: 'cancel_not_permitted',
        ...targetFields,
      });
      return this.sendError(
        msg,
        'cancel_not_permitted',
        'This request is not yours to cancel.',
        undefined,
        resolvedAlias,
      );
    }

    // The target's database, from the target's frame ONLY. The previous
    // `targetReq.message?.project || msg.project` meant an attacker whose own
    // project was configured could have a request in a different project
    // cancelled against the attacker's connection.
    const targetDbEntry = this.opts.lookupDb(
      targetReq.message?.project ?? '',
      targetReq.message?.db_alias,
    );
    const targetResolution = normaliseLookupResult(
      targetDbEntry,
      targetReq.message?.project ?? '',
      targetReq.message?.db_alias,
    );
    if (!targetResolution.ok) {
      await this.auditDeny(msg, permissionLevel, {
        action: 'cancel',
        denial_reason: 'cancel_target_not_found',
        ...targetFields,
      });
      return this.sendError(
        msg,
        'cancel_target_not_found',
        `No in-flight request matches the target_id.`,
        undefined,
        resolvedAlias,
      );
    }

    // A cancellation acts on the TARGET's database, so the record is attributed
    // to the database the cancellation actually reached.
    return withResolvedDatabase(resolvedIdentityOf(targetResolution.entry), async () => {
      if (this.opts.auditSink) {
        await this.opts.auditSink.logSync({
          ...this.auditBase(msg, permissionLevel),
          action: 'cancel',
          decision: 'allow',
          outcome: 'n/a',
          ...targetFields,
        });
      }

      const cancelResult = await this.opts.canceller.cancel(targetId, targetResolution.entry);
      const elapsedMs = Date.now() - startTime;

      if (this.opts.auditSink) {
        this.opts.auditSink.log({
          ...this.auditBase(msg, permissionLevel),
          action: 'cancel',
          decision: 'allow',
          outcome: 'success',
          duration_ms: elapsedMs,
          ...targetFields,
        });
      }

      return this.sendResponse(
        msg,
        {
          request_id: msg.id,
          ok: true,
          data: { target_id: targetId, ...cancelResult },
        },
        targetResolution.entry.db_alias,
      );
    });
  }

  /**
   * Map an internal failure to an outbound `error` payload.
   *
   * PostgreSQL errors are reduced to an allow-list of fields plus a curated
   * message per SQLSTATE. `detail` and `hint` are never forwarded: a duplicate
   * key violation ships `Key (email)=(alice@corp.com) already exists.` in
   * `detail`, and messages embed the offending SQL and absolute paths.
   */
  private mapErrorToPayload(err: unknown, requestId: string, dbEntry: DbEntry | null): unknown {
    const opts = sanitizeOptions(dbEntry);

    if (err instanceof PoolError) {
      // PoolError messages carry host, port, database user and file paths.
      return makeError(mapPoolErrorCode(err.code), requestId, {
        message: POOL_ERROR_MESSAGES[err.code] ?? sanitizePgError(err, opts).message,
      });
    }

    const errorObj = err as {
      name?: string;
      code?: string;
      message?: string;
      severity?: string;
    };

    if (errorObj.name === 'QueryTooLargeError') {
      return makeError('query_too_large', requestId, {
        message: sanitizeErrorText(errorObj.message, opts),
      });
    }

    if (errorObj.name === 'StreamTooLargeError') {
      return makeError('STREAM_ROW_LIMIT', requestId, {
        message: sanitizeErrorText(errorObj.message, opts),
      });
    }

    if (errorObj.name === 'CellSizeLimitError') {
      return makeError('CELL_SIZE_LIMIT', requestId, {
        message: sanitizeErrorText(errorObj.message, opts),
      });
    }

    if (errorObj.name === 'MigrationInProgressError') {
      return makeError('migration_in_progress', requestId, {
        message: sanitizeErrorText(errorObj.message, opts),
      });
    }

    if (errorObj.name === 'QueryCancelledError' || errorObj.code === '57014') {
      return makeError('query_cancelled', requestId, {
        message:
          errorObj.name === 'QueryCancelledError'
            ? 'Query was cancelled'
            : 'The statement exceeded the configured timeout.',
      });
    }

    if (errorObj.message && errorObj.message.startsWith('invalid_message:')) {
      return makeError('invalid_message', requestId, {
        message: 'The agent cannot accept this message.',
      });
    }

    if (errorObj.message && errorObj.message.startsWith('unknown_message_type:')) {
      return makeError('unknown_message_type', requestId, {
        message: 'The agent does not recognise this message type.',
      });
    }

    if (safePgCode(errorObj.code)) {
      const safe = sanitizePgError(err, opts);
      // `detail` is deliberately absent: it is where PostgreSQL puts
      // `Key (email)=(alice@corp.com) already exists.`. `hint` is always one
      // of our own curated strings, never the server's.
      const pg_error = {
        code: String(errorObj.code),
        severity: safeSeverity(safe.severity),
        hint: safe.hint,
      };
      return makeError('execution_failed', requestId, {
        pg_error,
        message: safe.message,
      });
    }

    return makeError('internal_error', requestId, {
      message: sanitizeErrorText(errorObj.message ?? String(err), opts),
    });
  }
}

function mapDecisionCodeToErrorCode(code: PermissionDecision['code']): ErrorCode {
  switch (code) {
    case 'role_insufficient':
      return 'role_insufficient';
    case 'permission_denied':
      return 'permission_denied';
    case 'plan_not_registered':
      return 'migration_plan_not_registered';
    case 'intent_mismatch':
      return 'permission_denied';
    case 'multiple_statements':
      return 'multiple_statements';
    case 'unparseable_statement':
      return 'unparseable_statement';
    case 'parser_unavailable':
      return 'parser_unavailable';
    default:
      return 'permission_denied';
  }
}

/**
 * Wire code for a lookup refusal.
 *
 * `database_not_found` and `database_out_of_scope` deliberately share the
 * curated `db_unavailable` answer: telling a caller "that project exists but is
 * out of scope" is a database-existence oracle across tenants, and the
 * distinction is preserved in the audit record instead. The two codes that name
 * the caller's own mistake — a project/alias collision and a missing allow-list —
 * are specific, because both are things only the operator can fix and neither
 * reveals another tenant's configuration.
 */
function databaseRefusalErrorCode(code: DatabaseRefusalCode): ErrorCode {
  switch (code) {
    case 'db_alias_project_mismatch':
      return 'db_alias_project_mismatch';
    case 'database_scope_not_configured':
      return 'database_scope_not_configured';
    default:
      return 'db_unavailable';
  }
}

/**
 * Curated text for a lookup refusal. The refusal's own `reason` is agent-authored
 * and data-free by construction (see `DatabaseLookupRefusal.reason`), but it is
 * not forwarded verbatim here either: every refusal on the wire gets the catalog
 * text for its code, so nothing derived from configuration reaches the browser.
 */
function databaseRefusalMessage(refusal: DatabaseLookupRefusal): string {
  return ERROR_CATALOG[databaseRefusalErrorCode(refusal.code)].default_message;
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

/**
 * Every inbound type maps onto a budget bucket. `response`, `stream_chunk` and
 * `stream_end` are agent-originated and fall into `other`, so an unexpected
 * type is metered rather than waved through.
 */
function mapMessageTypeToRateLimitAction(msgType: string): RateLimitedAction {
  switch (msgType) {
    case 'ping':
      return 'ping';
    case 'introspect':
      return 'introspect';
    case 'query':
      return 'query';
    case 'stream_query':
      return 'stream_query';
    case 'migration_run':
      return 'migration_run';
    case 'cancel':
      return 'cancel';
    case 'event':
      return 'event';
    default:
      return 'other';
  }
}

/** Curated text for a refusal. Never echoes an identifier the caller chose. */
function rateLimitMessage(reason: string | undefined, scope: string | undefined): string {
  if (
    reason === 'too_many_concurrent_requests' ||
    reason === 'too_many_concurrent_requests_for_database'
  ) {
    return 'Too many requests are already running. Wait for one to finish and retry.';
  }
  if (reason === 'introspection_snapshot_exceeds_budget') {
    return 'Introspection snapshot exceeds the configured response budget.';
  }
  if (scope === 'concurrency_global' || scope === 'concurrency_db') {
    return 'Too many requests are already running. Wait for one to finish and retry.';
  }
  return 'Request rate limit exceeded for this sender. Slow down and retry.';
}

/**
 * Serialized size of a response body. A value that cannot be measured counts as
 * infinite, so an unmeasurable payload is refused rather than forwarded.
 */
function serializedSizeOf(value: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(value) ?? '', 'utf8');
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

/* ------------------------------------------------------------------ */
/* Inbound event authorization (C-03, H-14)                           */
/* ------------------------------------------------------------------ */

interface EventGateDecision {
  allowed: boolean;
  errorCode: ErrorCode;
  reason: string;
  /** Audit action to record on denial; null when the frame is not an action. */
  auditAction: AuditAction | null;
  code: string;
}

/**
 * Decide whether an inbound `event` frame may be handled at all.
 *
 * This runs before any event handler. The `event` branch used to sit ahead of
 * the query/migration permission pipeline, so a `viewer` could resolve another
 * user's pending manual approval and could register an arbitrary migration
 * plan for later replay under `auto_upgrade` — the default level. Both kinds
 * now derive their required capability from the same `hasCapability` matrix
 * the query path uses, and any kind the agent does not accept inbound is
 * refused outright.
 *
 * `approval_response` requires both `query_write` and `ddl`: an approval can
 * authorise a write or a DDL statement, so the responder must be able to do
 * everything it can authorise.
 */
export function evaluateEventGate(
  kind: EventKind | undefined,
  role: Role,
  permissionLevel: PermissionLevel,
  canRegisterPlan?: (
    role: Role,
    permissionLevel: PermissionLevel,
  ) => { allowed: boolean; code?: string; reason?: string },
): EventGateDecision {
  if (kind === 'plan_register') {
    if (!hasCapability(role, 'migration_run')) {
      return {
        allowed: false,
        errorCode: 'role_insufficient',
        reason: `Role '${role}' cannot register migration plans`,
        auditAction: 'plan_register',
        code: 'role_denied',
      };
    }
    if (permissionLevel === 'read_only') {
      return {
        allowed: false,
        errorCode: 'permission_denied',
        reason: 'Migration plans cannot be registered while the database is in read_only mode',
        auditAction: 'plan_register',
        code: 'read_only_mode',
      };
    }
    // The registry is the authority; a refusal there overrides anything this
    // function concluded, because a plan that cannot be stored must not be
    // reported as registered.
    const verdict = canRegisterPlan?.(role, permissionLevel);
    if (verdict && !verdict.allowed) {
      return {
        allowed: false,
        errorCode: 'permission_denied',
        reason: verdict.reason ?? 'Plan registration refused',
        auditAction: 'plan_register',
        code: verdict.code ?? 'plan_registration_refused',
      };
    }
    return {
      allowed: true,
      errorCode: 'invalid_message',
      reason: '',
      auditAction: null,
      code: 'allowed',
    };
  }

  if (kind === 'approval_response') {
    const mayApprove = hasCapability(role, 'query_write') && hasCapability(role, 'ddl');
    if (!mayApprove) {
      return {
        allowed: false,
        errorCode: 'role_insufficient',
        reason: `Role '${role}' cannot approve write or DDL statements`,
        auditAction: 'manual_approval',
        code: 'role_denied',
      };
    }
    return {
      allowed: true,
      errorCode: 'invalid_message',
      reason: '',
      auditAction: null,
      code: 'allowed',
    };
  }

  // Agent-to-browser kinds and anything unrecognised are refused. They are not
  // audit-worthy: no database action was requested.
  return {
    allowed: false,
    errorCode: 'invalid_message',
    reason: 'The agent does not accept inbound event kind',
    auditAction: null,
    code: 'unsupported_event_kind',
  };
}

/* ------------------------------------------------------------------ */
/* Error sanitisation (H-05)                                           */
/* ------------------------------------------------------------------ */

/** Curated `ErrorCode` for each `PoolError` variant. */
const POOL_ERROR_CODES: Readonly<Record<string, ErrorCode>> = {
  env_var_missing: 'env_var_missing',
  connection_failed: 'db_unavailable',
  auth_failed: 'db_auth_failed',
  db_not_found: 'db_unavailable',
  ssl_error: 'db_ssl_error',
  pool_exhausted: 'db_pool_exhausted',
  unsafe_session_setting: 'db_unavailable',
};

/** A SQLSTATE is five upper-case alphanumerics; anything else is not one. */
function safePgCode(code: unknown): boolean {
  return typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code);
}

/** Severities PostgreSQL actually emits, plus a safe default. */
const PG_SEVERITIES: ReadonlySet<string> = new Set([
  'ERROR',
  'FATAL',
  'PANIC',
  'WARNING',
  'NOTICE',
  'DEBUG',
  'INFO',
]);

function safeSeverity(severity: unknown): string {
  if (typeof severity !== 'string') return 'ERROR';
  const normalized = severity.toUpperCase();
  return PG_SEVERITIES.has(normalized) ? normalized : 'ERROR';
}

/** Audit `error_code` must be a code, never free text. */
function safeAuditCode(code: unknown): string {
  return typeof code === 'string' && /^[A-Za-z0-9_.]{1,32}$/.test(code) ? code : 'INTERNAL';
}

/** Audit `denial_reason` comes from a closed enum; refuse anything else. */
function safeAuditReason(code: unknown): string {
  return typeof code === 'string' && /^[a-z0-9_]{1,32}$/.test(code) ? code : 'denied';
}

function mapPoolErrorCode(code: string): ErrorCode {
  return POOL_ERROR_CODES[code] ?? 'db_unavailable';
}

/**
 * Curated, data-free text for a SQLSTATE. Delegates to `sanitizePgError` so
 * there is exactly one place where SQLSTATEs are described, and so the answer
 * can never be derived from raw PostgreSQL output.
 */
function pgMessageForCode(code: string): string {
  return sanitizePgError({ code }).message;
}

/**
 * Sanitisation options for one request. `topology` lets `scrubTopology` remove
 * the exact host / database / user this request was made against, in addition
 * to the generic host/user/path/URL rules.
 */
function sanitizeOptions(dbEntry: DbEntry | null | undefined): SanitizeOptions {
  if (!dbEntry) return {};
  return {
    topology: {
      host: dbEntry.host,
      port: dbEntry.port,
      user: dbEntry.user,
      database: dbEntry.database,
      project: dbEntry.project_name,
    },
  };
}

/** The SQLSTATE of the statement that failed, when it is a real SQLSTATE. */
function failedStatementCode(result: {
  statements: Array<{ status: string; pg_error_code?: string }>;
}): string | undefined {
  const failed = result.statements.find((s) => s.status === 'failed');
  return failed?.pg_error_code !== undefined && safePgCode(failed.pg_error_code)
    ? failed.pg_error_code
    : undefined;
}

/**
 * Per-statement errors are verbatim PostgreSQL messages, and a migration
 * failure routinely includes row data (`Key (email)=(alice@corp.com) already
 * exists.`). Reduce every one of them before the result leaves the process.
 */
function sanitizeMigrationResult<
  T extends { statements: Array<{ error?: string; pg_error_code?: string }> },
>(result: T, dbEntry: DbEntry | null): T {
  const opts = sanitizeOptions(dbEntry);
  return {
    ...result,
    statements: result.statements.map((s) => {
      if (s.error === undefined) return s;
      return { ...s, error: sanitizeErrorText(s.error, opts) };
    }),
  };
}
