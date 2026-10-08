import { ActionRequest, PermissionDecision, PermissionLevel } from './types';
import type { StatementClassification } from '../execution/types';
import {
  hasCapability,
  capabilityForClassification,
  capabilityForMessageType,
  explainWhyNotAProvableRead,
  isProvableRead,
} from './role-policy';
import { AutoUpgradeChecker } from './auto-upgrade';
import { ManualApprovalHandler } from './manual-approval';
import { PlanRegistry } from './plan-registry';
import { classifyStatement } from '../execution/statement-classifier';
import type { FunctionEffectResolver } from '../execution/function-effects';
import { SqlParseError, SqlParserUnavailableError } from '../execution/sql-parser';
import { previewStatement } from '../audit/redact';

export { PermissionLevel };

export interface PermissionCheckerOptions {
  autoUpgradeChecker: AutoUpgradeChecker;
  manualApprovalHandler: ManualApprovalHandler;
  planRegistry: PlanRegistry;
  /**
   * Optional default resolver for function-effect analysis.
   *
   * When omitted, `check()`'s own `resolveFunctionEffects` argument is used,
   * and when THAT is omitted too the analysis reports nothing was analysable —
   * so every statement that calls a function is escalated. Supplying it here
   * keeps one resolver per database entry rather than one per call.
   */
  resolveFunctionEffects?: FunctionEffectResolver;
}

export class PermissionChecker {
  public readonly opts: PermissionCheckerOptions;

  constructor(opts: PermissionCheckerOptions) {
    this.opts = opts;
  }

  /**
   * Decide whether a request may proceed. This is the ONLY method the
   * dispatcher calls.
   *
   * Order of checks (all of them must pass):
   *   0. Parse. A statement we cannot parse is denied, never guessed at. A
   *      parse error and an unavailable parser are both terminal.
   *   1. Exactly one statement. Multi-statement execution is refused outright
   *      because node-postgres uses the simple query protocol when no bind
   *      parameters are supplied, and the simple protocol runs every
   *      semicolon-separated statement.
   *   2. Anti-spoofing. The browser-claimed intent must match the parsed
   *      classification. No intent value exempts the request from this check;
   *      `intent: 'migration'` is accepted only on the `migration_run` message
   *      type and never in place of the comparison.
   *   3. Role capability for the message type and for the parsed class. A
   *      classification that is not a *provable* read requires `ddl`.
   *   4. Permission level.
   *
   * @param resolveFunctionEffects Answers "what can this function call do?"
   *      from `pg_proc` on a live connection. It is an argument, not a global,
   *      because only the caller knows which database the statement is about —
   *      and OIDs, and therefore which overloads exist, are per-database. A
   *      caller that cannot supply one gets `analysed: false`, and every
   *      statement that calls a function is then escalated rather than
   *      trusted.
   */
  async check(
    req: ActionRequest,
    statements?: string[],
    resolveFunctionEffects?: FunctionEffectResolver,
  ): Promise<PermissionDecision> {
    const resolveEffects =
      resolveFunctionEffects ?? this.opts.resolveFunctionEffects ?? undefined;
    // ---- Step 0: parse. Fail closed. ------------------------------------
    // A migration_run carries an array of statements. Classifying only the
    // first one was a hole: `['SELECT 1', 'DROP TABLE users']` passed the read
    // check on statements[0] and then executed the DROP. Every statement is
    // classified, and the most restrictive result governs.
    const isMigrationRun = req.message_type === 'migration_run';
    const perStatement: StatementClassification[] = [];

    const statementsToParse = isMigrationRun ? (statements ?? [req.sql]) : [req.sql];

    for (let i = 0; i < statementsToParse.length; i++) {
      let c: StatementClassification;
      try {
        c = await classifyStatement(statementsToParse[i], {
          resolveFunctionEffects: resolveEffects,
        });
      } catch (err: unknown) {
        if (err instanceof SqlParserUnavailableError) {
          return {
            allowed: false,
            reason:
              'The PostgreSQL parser is unavailable, so the statement cannot be verified. ' +
              'Refusing to execute unverified SQL.',
            code: 'parser_unavailable',
          };
        }
        if (err instanceof SqlParseError) {
          const where = statementsToParse.length > 1 ? ` (statement ${i + 1})` : '';
          return {
            allowed: false,
            reason: `PostgreSQL could not parse the statement${where}: ${err.message}`,
            code: 'unparseable_statement',
          };
        }
        throw err;
      }
      perStatement.push(c);
    }

    const actualClassification = aggregateClassification(perStatement);

    // ---- Step 1: single-statement invariant -----------------------------
    // Every plan entry must be exactly one statement, otherwise the simple
    // query protocol can run extra statements the classifier never saw.
    const empty = perStatement.find((c) => c.statement_count === 0);
    if (empty) {
      return {
        allowed: false,
        reason:
          'The statement contains no executable SQL (comments or whitespace only). ' +
          'Nothing to verify, so nothing is executed.',
        code: 'unparseable_statement',
        classification: actualClassification,
      };
    }
    const offenders = perStatement.filter((c) => c.statement_count !== 1);
    if (offenders.length > 0) {
      const where = statementsToParse.length > 1 ? ' in migration plan' : '';
      return {
        allowed: false,
        reason:
          `Expected exactly one statement${where} but PostgreSQL's parser found ` +
          `${offenders[0].statement_count} in one of them. Multi-statement execution is ` +
          'refused because it would run every statement regardless of how it is classified.',
        code: 'multiple_statements',
        classification: actualClassification,
      };
    }

    // ---- Step 2: anti-spoofing -----------------------------------------
    // No intent value grants an exemption. `intent` is advisory input; the
    // parsed classification is the only thing that decides. The previous
    // implementation carried `&& req.intent !== 'migration'`, which let a
    // caller disable this check entirely by claiming an intent the message type
    // does not support.
    const claimed = req.intent;
    const actualType = actualClassification.type;

    if (claimed === 'migration' && !isMigrationRun) {
      return {
        allowed: false,
        reason:
          `Intent 'migration' is only meaningful on a migration_run message, not on ` +
          `'${req.message_type}'. The statement was parsed as '${actualType}' ` +
          `(${actualClassification.verb}); 'migration' is not an exemption from intent verification.`,
        code: 'intent_not_applicable',
        classification: actualClassification,
      };
    }

    const intentMatches =
      claimed === actualType ||
      // A migration_run's `intent` is 'migration' and its payload is a plan, not
      // a single statement, so there is no single parsed type to compare with.
      (claimed === 'migration' && isMigrationRun);

    if (!intentMatches) {
      return {
        allowed: false,
        reason: `Intent mismatch: request declared '${claimed}' but PostgreSQL parsed it as '${actualType}' (${actualClassification.verb}${
          actualClassification.kind !== actualClassification.verb
            ? ' ' + actualClassification.kind
            : ''
        })`,
        code: 'intent_mismatch',
        classification: actualClassification,
      };
    }

    // ---- Step 3: role capability ---------------------------------------
    const messageTypeCap = capabilityForMessageType(req.message_type);
    if (messageTypeCap && !hasCapability(req.role, messageTypeCap)) {
      return {
        allowed: false,
        reason: `Role '${req.role}' cannot perform '${messageTypeCap}'`,
        code: 'role_insufficient',
        classification: actualClassification,
      };
    }

    const classificationCap = capabilityForClassification(actualClassification);
    if (classificationCap && !hasCapability(req.role, classificationCap)) {
      return {
        allowed: false,
        reason: `Role '${req.role}' cannot run '${actualClassification.type}' statements (${actualClassification.kind})`,
        code: 'role_insufficient',
        classification: actualClassification,
      };
    }

    // ---- Step 4: permission level ---------------------------------------
    const provableRead = isProvableRead(actualClassification);

    switch (req.permission_level) {
      case 'full':
        return {
          allowed: true,
          reason: 'Full permission',
          code: 'allowed',
          classification: actualClassification,
        };

      case 'read_only': {
        if (!provableRead) {
          return {
            allowed: false,
            reason:
              `Read-only mode: ${explainWhyNotAProvableRead(actualClassification)}. ` +
              'PostgreSQL will not refuse it for you: default_transaction_read_only = on ' +
              'constrains writes to relations, not reads, notifications or function bodies.',
            code: 'permission_denied',
            classification: actualClassification,
          };
        }
        return {
          allowed: true,
          reason: 'Read allowed in read_only mode',
          code: 'allowed',
          classification: actualClassification,
        };
      }

      case 'auto_upgrade': {
        if (provableRead) {
          return {
            allowed: true,
            reason: 'Read allowed',
            code: 'allowed',
            classification: actualClassification,
          };
        }

        const upgrade = await this.opts.autoUpgradeChecker.check(req, statements);
        if (upgrade.granted) {
          return {
            allowed: true,
            reason: upgrade.reason,
            code: 'auto_upgrade_granted',
            classification: actualClassification,
          };
        }
        return {
          allowed: false,
          reason: `Auto-upgrade not granted: ${upgrade.reason}`,
          code: 'plan_not_registered',
          classification: actualClassification,
        };
      }

      case 'manual': {
        if (provableRead) {
          return {
            allowed: true,
            reason: 'Read allowed',
            code: 'allowed',
            classification: actualClassification,
          };
        }

        // Everything else needs approval from the user who requested it.
        // `ManualApprovalHandler` binds the pending approval to this user id
        // and to a nonce it minted itself, so nobody else on the relay can
        // approve it. Only a redacted preview is transmitted: the full SQL can
        // carry PII literals and this event crosses the cloud boundary.
        const approvalRequest = {
          request_id: req.request_id,
          sql_preview: previewStatement(req.sql),
          intent: actualClassification.type === 'write' ? ('write' as const) : ('ddl' as const),
          db_alias: req.db_alias,
        };

        const approval = await this.opts.manualApprovalHandler.requestApproval({
          ...approvalRequest,
          project: req.project,
          user: req.user,
        });

        if (approval.approved) {
          return {
            allowed: true,
            reason: 'Approved by user',
            code: 'allowed',
            classification: actualClassification,
          };
        }
        return {
          allowed: false,
          reason: approval.reason || 'Approval denied',
          code: 'permission_denied',
          classification: actualClassification,
          approval_request: approvalRequest,
        };
      }

      default:
        return {
          allowed: false,
          reason: `Invalid permission level '${req.permission_level}'`,
          code: 'permission_denied',
          classification: actualClassification,
        };
    }
  }
}

/**
 * Combine per-statement classifications for a multi-statement request.
 *
 * The aggregate is the MOST restrictive classification present, and it carries
 * the union of every read violation, function-effect record and side effect.
 * This is what stops `['SELECT 1', 'DROP TABLE users']` from being treated as a
 * read because its first statement is one.
 */
function aggregateClassification(parts: StatementClassification[]): StatementClassification {
  if (parts.length === 0) {
    return {
      type: 'unknown',
      kind: 'EMPTY',
      transactional: true,
      verb: '',
      statement_count: 0,
      parse_ok: false,
      read_violations: ['parse_error'],
      function_effects: [],
      side_effects: [],
    };
  }
  if (parts.length === 1) return parts[0];

  const rank: Record<StatementClassification['type'], number> = {
    read: 0,
    utility: 1,
    write: 2,
    ddl: 3,
    unknown: 4,
  };

  let worst = parts[0];
  for (const p of parts) {
    if (rank[p.type] > rank[worst.type]) worst = p;
  }

  const violations = [...new Set(parts.flatMap((p) => p.read_violations))];
  const functionEffects = dedupeRecords(parts.flatMap((p) => p.function_effects ?? []));
  const sideEffects = [...new Set(parts.flatMap((p) => p.side_effects ?? []))];

  return {
    type: worst.type,
    kind: parts.length > 1 ? `${parts.length} statements` : worst.kind,
    // A plan is only transactional if every statement is.
    transactional: parts.every((p) => p.transactional),
    verb: worst.verb,
    statement_count: parts.reduce((n, p) => n + p.statement_count, 0),
    parse_ok: parts.every((p) => p.parse_ok),
    read_violations: violations,
    function_effects: functionEffects,
    side_effects: sideEffects,
  };
}

/** One record per distinct function name; the first verdict for a name wins. */
function dedupeRecords(
  records: readonly NonNullable<StatementClassification['function_effects']>[number][],
): NonNullable<StatementClassification['function_effects']> {
  const byName = new Map<string, NonNullable<StatementClassification['function_effects']>[number]>();
  for (const record of records) {
    const key = record.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, record);
  }
  return [...byName.values()];
}
