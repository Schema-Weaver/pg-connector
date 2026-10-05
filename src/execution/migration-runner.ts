import * as crypto from 'crypto';
import { PoolManager } from './pool';
import { DbEntry } from '../config/db-config';
import { MigrationRunPayload, MigrationResultPayload } from '../protocol/messages';
import { InFlightRequest, StatementResult } from './types';
import { detectNonTransactional } from './non-tx-detector';
import { classifyStatement } from './statement-classifier';
import { LIMITS } from '../protocol/constants';
import { AgentMessage, Role } from '../protocol/envelope';

export class MigrationInProgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MigrationInProgressError';
  }
}

export interface MigrationRunnerOptions {
  poolManager: PoolManager;
}

export interface MigrationContext {
  dbEntry: DbEntry;
  request_id: string;
  project: string;
  user: { id: string; role: Role };
  db_alias: string;
  /** Called for each statement status change. */
  onProgress?: (event: AgentMessage) => void | Promise<void>;
  abortSignal?: AbortSignal;
  registerInFlight?: (req: InFlightRequest) => void;
  unregisterInFlight?: (request_id: string) => void;
}

/** Advisory lock key for SW migrations. Derived from project name. */
function advisoryLockKey(projectName: string): { key1: number; key2: number } {
  const hash = crypto.createHash('md5').update(projectName).digest();
  const key1 = hash.readInt32LE(0);
  const key2 = hash.readInt32LE(4);
  return { key1, key2 };
}

export class MigrationRunner {
  private readonly poolManager: PoolManager;

  constructor(opts: MigrationRunnerOptions) {
    this.poolManager = opts.poolManager;
  }

  async run(payload: MigrationRunPayload, ctx: MigrationContext): Promise<MigrationResultPayload> {
    const startTime = Date.now();

    // Step 1: Validate
    if (payload.statements.length === 0) {
      if (payload.dry_run) {
        return {
          plan_id: payload.plan_id,
          status: 'dry_run_ok',
          statements: [],
          total_ms: Date.now() - startTime,
          rolled_back_indices: [],
        };
      }
      throw new Error('Migration run payload contains no statements');
    }

    if (payload.statements.length > LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION) {
      throw new Error(`Migration statement count exceeds maximum limit (${LIMITS.MAX_STATEMENT_COUNT_PER_MIGRATION})`);
    }

    for (const stmt of payload.statements) {
      if (!stmt.trim()) {
        throw new Error('Migration payload contains an empty statement');
      }
      if (Buffer.byteLength(stmt, 'utf8') > LIMITS.MAX_STATEMENT_LENGTH) {
        throw new Error(`Statement length exceeds maximum allowed limit (${LIMITS.MAX_STATEMENT_LENGTH})`);
      }
    }

    // Step 2: Dry run (if dry_run)
    if (payload.dry_run) {
      const { client, release } = await this.poolManager.acquire(ctx.dbEntry);
      const statementResults: StatementResult[] = [];
      let allPassed = true;

      try {
        for (let i = 0; i < payload.statements.length; i++) {
          const stmt = payload.statements[i];
          const classification = classifyStatement(stmt);
          const verb = classification.verb;
          const isDdl = ['CREATE', 'DROP', 'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE'].includes(verb);
          
          const stmtStart = Date.now();
          let inTx = false;
          try {
            if (isDdl && classification.transactional) {
              await client.query('BEGIN');
              inTx = true;
              await client.query(stmt);
              await client.query('ROLLBACK');
              inTx = false;
            } else {
              await client.query(`EXPLAIN ${stmt}`);
            }
            statementResults.push({
              index: i,
              status: 'success',
              ms: Date.now() - stmtStart,
              rows_affected: 0,
            });
          } catch (err: unknown) {
            if (inTx) {
              try {
                await client.query('ROLLBACK');
              } catch {
                // ignore
              }
            }
            allPassed = false;
            statementResults.push({
              index: i,
              status: 'failed',
              ms: Date.now() - stmtStart,
              rows_affected: 0,
              error: err instanceof Error ? err.message : String(err),
              pg_error_code: err && typeof err === 'object' && 'code' in err ? String((err as Record<string, unknown>).code) : undefined,
            });
          }
        }
      } finally {
        release();
      }

      return {
        plan_id: payload.plan_id,
        status: allPassed ? 'dry_run_ok' : 'dry_run_failed',
        statements: statementResults,
        total_ms: Date.now() - startTime,
        rolled_back_indices: [],
      };
    }

    // Step 3: Acquire advisory lock & execute migration
    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      message: null as unknown as AgentMessage,
      abort: abortController,
      is_streaming: false,
    };

    if (ctx.registerInFlight) {
      ctx.registerInFlight(inFlightReq);
    }

    let isAborted = false;
    const onAbort = () => {
      isAborted = true;
      abortController.abort();
    };

    if (ctx.abortSignal) {
      ctx.abortSignal.addEventListener('abort', onAbort);
    }

    const { key1, key2 } = advisoryLockKey(ctx.project);

    try {
      // Try lock
      const lockRes = await client.query('SELECT pg_try_advisory_lock($1, $2) AS locked', [key1, key2]);
      const locked = lockRes.rows[0].locked;
      if (!locked) {
        throw new MigrationInProgressError('Database migration is currently in progress for this project.');
      }

      // Step 4: Strategy selection & auto-switch
      const nonTxCheck = detectNonTransactional(payload.statements);
      let strategy = payload.strategy;
      let strategyChangedFrom: 'single_tx' | undefined;

      if (nonTxCheck.has_non_transactional && strategy === 'single_tx') {
        strategy = 'per_statement';
        strategyChangedFrom = 'single_tx';

        if (ctx.onProgress) {
          ctx.onProgress({
            v: 1,
            id: crypto.randomUUID(),
            type: 'event',
            project: ctx.project,
            user: ctx.user,
            db_alias: ctx.db_alias,
            ts: Date.now(),
            payload: {
              kind: 'warning',
              data: {
                code: 'strategy_changed',
                message: `Migration contains non-transactional statements (${nonTxCheck.summary}). Auto-switched to per_statement strategy.`,
              },
            },
          });
        }
      }

      const statementResults: StatementResult[] = [];
      let migrationStatus: 'committed' | 'rolled_back' | 'partial' = 'committed';
      const rolledBackIndices: number[] = [];

      // Step 5: Execute loop
      if (strategy === 'single_tx') {
        await client.query('BEGIN');
        
        for (let i = 0; i < payload.statements.length; i++) {
          if (isAborted) {
            migrationStatus = 'rolled_back';
            await client.query('ROLLBACK');
            for (let j = 0; j < i; j++) {
              rolledBackIndices.push(j);
            }
            break;
          }

          const stmt = payload.statements[i];
          const stmtStart = Date.now();

          if (ctx.onProgress) {
            ctx.onProgress({
              v: 1,
              id: crypto.randomUUID(),
              type: 'event',
              project: ctx.project,
              user: ctx.user,
              db_alias: ctx.db_alias,
              ts: Date.now(),
              payload: {
                kind: 'migration_progress',
                data: {
                  plan_id: payload.plan_id,
                  statement_index: i,
                  statement_sql_preview: stmt.substring(0, 100),
                  status: 'running',
                },
              },
            });
          }

          try {
            const runRes = await client.query(stmt);
            const duration = Date.now() - stmtStart;
            const rowsAffected = runRes.rowCount || 0;

            statementResults.push({
              index: i,
              status: 'success',
              ms: duration,
              rows_affected: rowsAffected,
            });

            if (ctx.onProgress) {
              ctx.onProgress({
                v: 1,
                id: crypto.randomUUID(),
                type: 'event',
                project: ctx.project,
                user: ctx.user,
                db_alias: ctx.db_alias,
                ts: Date.now(),
                payload: {
                  kind: 'migration_progress',
                  data: {
                    plan_id: payload.plan_id,
                    statement_index: i,
                    statement_sql_preview: stmt.substring(0, 100),
                    status: 'success',
                    ms: duration,
                  },
                },
              });
            }
          } catch (err: unknown) {
            migrationStatus = 'rolled_back';
            const duration = Date.now() - stmtStart;

            statementResults.push({
              index: i,
              status: 'failed',
              ms: duration,
              rows_affected: 0,
              error: err instanceof Error ? err.message : String(err),
              pg_error_code: err && typeof err === 'object' && 'code' in err ? String((err as Record<string, unknown>).code) : undefined,
            });

            if (ctx.onProgress) {
              ctx.onProgress({
                v: 1,
                id: crypto.randomUUID(),
                type: 'event',
                project: ctx.project,
                user: ctx.user,
                db_alias: ctx.db_alias,
                ts: Date.now(),
                payload: {
                  kind: 'migration_progress',
                  data: {
                    plan_id: payload.plan_id,
                    statement_index: i,
                    statement_sql_preview: stmt.substring(0, 100),
                    status: 'failed',
                    ms: duration,
                    error: err instanceof Error ? err.message : String(err),
                  },
                },
              });
            }

            await client.query('ROLLBACK');
            for (let j = 0; j < i; j++) {
              rolledBackIndices.push(j);
            }
            break;
          }
        }

        if (migrationStatus === 'committed') {
          await client.query('COMMIT');
        }
      } else {
        // per_statement strategy
        for (let i = 0; i < payload.statements.length; i++) {
          if (isAborted) {
            migrationStatus = 'partial';
            break;
          }

          const stmt = payload.statements[i];
          const stmtStart = Date.now();

          if (ctx.onProgress) {
            ctx.onProgress({
              v: 1,
              id: crypto.randomUUID(),
              type: 'event',
              project: ctx.project,
              user: ctx.user,
              db_alias: ctx.db_alias,
              ts: Date.now(),
              payload: {
                kind: 'migration_progress',
                data: {
                  plan_id: payload.plan_id,
                  statement_index: i,
                  statement_sql_preview: stmt.substring(0, 100),
                  status: 'running',
                },
              },
            });
          }

          try {
            const runRes = await client.query(stmt);
            const duration = Date.now() - stmtStart;
            const rowsAffected = runRes.rowCount || 0;

            statementResults.push({
              index: i,
              status: 'success',
              ms: duration,
              rows_affected: rowsAffected,
            });

            if (ctx.onProgress) {
              ctx.onProgress({
                v: 1,
                id: crypto.randomUUID(),
                type: 'event',
                project: ctx.project,
                user: ctx.user,
                db_alias: ctx.db_alias,
                ts: Date.now(),
                payload: {
                  kind: 'migration_progress',
                  data: {
                    plan_id: payload.plan_id,
                    statement_index: i,
                    statement_sql_preview: stmt.substring(0, 100),
                    status: 'success',
                    ms: duration,
                  },
                },
              });
            }
          } catch (err: unknown) {
            migrationStatus = 'partial';
            const duration = Date.now() - stmtStart;

            statementResults.push({
              index: i,
              status: 'failed',
              ms: duration,
              rows_affected: 0,
              error: err instanceof Error ? err.message : String(err),
              pg_error_code: err && typeof err === 'object' && 'code' in err ? String((err as Record<string, unknown>).code) : undefined,
            });

            if (ctx.onProgress) {
              ctx.onProgress({
                v: 1,
                id: crypto.randomUUID(),
                type: 'event',
                project: ctx.project,
                user: ctx.user,
                db_alias: ctx.db_alias,
                ts: Date.now(),
                payload: {
                  kind: 'migration_progress',
                  data: {
                    plan_id: payload.plan_id,
                    statement_index: i,
                    statement_sql_preview: stmt.substring(0, 100),
                    status: 'failed',
                    ms: duration,
                    error: err instanceof Error ? err.message : String(err),
                  },
                },
              });
            }
          }
        }
      }

      // Unlock advisory lock
      await client.query('SELECT pg_advisory_unlock($1, $2)', [key1, key2]);

      return {
        plan_id: payload.plan_id,
        status: migrationStatus,
        statements: statementResults,
        total_ms: Date.now() - startTime,
        rolled_back_indices: rolledBackIndices,
        strategy_changed_from: strategyChangedFrom,
      };
    } finally {
      if (ctx.abortSignal) {
        ctx.abortSignal.removeEventListener('abort', onAbort);
      }
      if (ctx.unregisterInFlight) {
        ctx.unregisterInFlight(ctx.request_id);
      }
      release();
    }
  }
}
