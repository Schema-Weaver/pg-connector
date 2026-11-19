/**
 * MySQL driver.
 *
 * SECURITY POSTURE
 * ----------------
 * The classifier (`mysql-classifier.ts`) decides whether a statement is a read.
 * This file is the second gate, and it is deliberately independent of it:
 *
 *   - Every request starts from a known session posture. `RESET`-equivalent
 *     cleanup is handled by the pool (`resetOnRelease`), and `harden()` re-applies
 *     the read-only posture and the execution timeout on the connection it is
 *     about to use.
 *   - Every statement classified as a read runs inside
 *     `START TRANSACTION READ ONLY`. That is MySQL's own enforcement: a write
 *     the classifier missed is refused by the server. The transaction is always
 *     rolled back, because a read has nothing to commit.
 *   - Writes run outside that transaction. At `read_only` permission the
 *     session itself is `SET SESSION TRANSACTION READ ONLY`, so a write cannot
 *     silently succeed after a classifier miss either.
 *   - Stored functions are refused by the classifier, not by this layer: a
 *     stored function body is not visible to the agent, so there is no safe way
 *     to prove it read-only.
 *
 * The pool is per alias and per connection identity, so editing an entry to
 * point elsewhere never reuses a session that authenticated to the old target.
 */
import * as fs from 'fs';
import {
  createPool,
  type FieldPacket,
  type Pool,
  type PoolConnection,
  type PoolOptions,
  type SslOptions,
} from 'mysql2';
import type { DbEntry } from '../config/db-config';
import { DEFAULTS } from '../protocol/constants';
import type {
  QueryPayload,
  QueryResultPayload,
  StreamChunkPayload,
  StreamQueryPayload,
} from '../protocol/messages';
import type { StatementClassification } from '../execution/types';
import { QueryTooLargeError, StreamTooLargeError } from '../execution/query-runner';
import type {
  DatabaseDriver,
  DriverCapabilities,
  DriverClassifyOptions,
  DriverConnectionInfo,
  DriverQueryContext,
} from './types';
import { classifyMysqlStatement } from './mysql-classifier';
import { resolveEntryPassword } from './credentials';
import { estimateRowBytes, processRow, type TruncationState } from './row-limits';
import { redactDbEntry } from '../config/db-config';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_TIMEOUT_MS = DEFAULTS.QUERY_TIMEOUT_MS;
const MAX_TIMEOUT_MS = 300_000;
const MAX_QUERY_ROWS = DEFAULTS.MAX_QUERY_ROWS;
const MAX_STREAM_ROWS = DEFAULTS.MAX_STREAM_ROWS;

function mysqlTimeout(payloadMs: number | undefined): number {
  if (typeof payloadMs !== 'number' || !Number.isFinite(payloadMs) || payloadMs <= 0) {
    return DEFAULT_TIMEOUT_MS;
  }
  return Math.min(Math.floor(payloadMs), MAX_TIMEOUT_MS);
}

function buildSsl(entry: DbEntry): SslOptions | undefined {
  if (entry.ssl_mode === 'disable') return undefined;
  const ssl: SslOptions = {
    // `require` encrypts without verifying the chain, matching the PostgreSQL
    // driver's mapping. `verify-*` requires a trusted chain.
    rejectUnauthorized: entry.ssl_mode === 'verify-ca' || entry.ssl_mode === 'verify-full',
  };
  if (entry.ssl_mode === 'verify-ca') {
    // `verify-ca` checks the chain but not that the certificate names the host,
    // the same distinction PostgreSQL's `checkServerIdentity: () => undefined`
    // makes. The option is a standard `tls.connect` setting that mysql2 passes
    // through; its typings omit it.
    (ssl as SslOptions & { checkServerIdentity?: () => undefined }).checkServerIdentity = () =>
      undefined;
  }
  if (entry.ssl_root_cert) {
    ssl.ca = fs.readFileSync(entry.ssl_root_cert);
  }
  return ssl;
}

function getConnection(pool: Pool): Promise<PoolConnection> {
  return new Promise((resolve, reject) => {
    pool.getConnection((err, connection) => {
      if (err) reject(err);
      else resolve(connection);
    });
  });
}

function endPool(pool: Pool): Promise<void> {
  return new Promise((resolve, reject) => {
    pool.end((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function execRaw(connection: PoolConnection, sql: string, values?: unknown[]): Promise<any> {
  return new Promise((resolve, reject) => {
    connection.query(sql, values as any, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

interface BufferedResult {
  rows: unknown[][];
  fields: FieldPacket[];
  affectedRows: number;
}

function queryBuffered(
  connection: PoolConnection,
  sql: string,
  values: unknown[] | undefined,
  timeoutMs: number,
): Promise<BufferedResult> {
  return new Promise((resolve, reject) => {
    connection.query(
      { sql, values: values as any, rowsAsArray: true, timeout: timeoutMs },
      (err, result: any, fields: FieldPacket[] | undefined) => {
        if (err) {
          reject(err);
          return;
        }
        if (Array.isArray(result)) {
          resolve({
            rows: result as unknown[][],
            fields: fields ?? [],
            affectedRows: result.length,
          });
          return;
        }
        resolve({
          rows: [],
          fields: fields ?? [],
          affectedRows:
            result && typeof result.affectedRows === 'number' ? Number(result.affectedRows) : 0,
        });
      },
    );
  });
}

function columnsFromFields(fields: FieldPacket[]): QueryResultPayload['columns'] {
  return fields.map((field) => ({
    name: field.name,
    type_oid: field.columnType ?? field.type ?? 0,
    type_name: field.typeName ?? 'mysql',
  }));
}

export class MysqlDriver implements DatabaseDriver {
  readonly type = 'mysql' as const;
  readonly display_name = 'MySQL';
  readonly default_port = 3306;
  readonly capabilities: DriverCapabilities = {
    query: true,
    stream: true,
    introspect: false,
    migration: false,
    server_cancel: false,
  };

  private readonly pools = new Map<string, Pool>();

  async classify(sql: string, _options: DriverClassifyOptions = {}) {
    // MySQL stored functions are denied by name/shape inside the classifier;
    // there is no `pg_proc`-style catalogue verdict to resolve here.
    void _options;
    return classifyMysqlStatement(sql);
  }

  async testConnection(entry: DbEntry): Promise<DriverConnectionInfo> {
    const pool = createPool(this.poolOptions(entry, 1));
    try {
      const connection = await getConnection(pool);
      try {
        const result = await queryBuffered(
          connection,
          'SELECT VERSION() AS version, DATABASE() AS `database`, CURRENT_USER() AS `user`',
          undefined,
          DEFAULT_TIMEOUT_MS,
        );
        const first = (result.rows[0] ?? []) as unknown[];
        return {
          version: typeof first[0] === 'string' ? first[0] : 'MySQL',
          database: typeof first[1] === 'string' ? first[1] : entry.database,
          user: typeof first[2] === 'string' ? first[2] : entry.user,
        };
      } finally {
        connection.release();
      }
    } finally {
      await endPool(pool).catch(() => undefined);
    }
  }

  async runOneShot(payload: QueryPayload, ctx: DriverQueryContext): Promise<QueryResultPayload> {
    const classification = requireClassification(ctx.classification);
    const pool = this.poolFor(ctx.dbEntry);
    const connection = await getConnection(pool);
    const timeoutMs = mysqlTimeout(payload.timeout_ms);
    const startedAt = Date.now();
    const read = classification.type === 'read';

    try {
      await this.harden(connection, ctx, timeoutMs);
      if (read) await execRaw(connection, 'START TRANSACTION READ ONLY');

      if (read) {
        const { rows, fields } = await this.collectRead(
          connection,
          payload.sql,
          payload.params,
          timeoutMs,
          MAX_QUERY_ROWS,
        );
        return {
          columns: columnsFromFields(fields),
          rows,
          rows_affected: rows.length,
          ms: Date.now() - startedAt,
          truncated: false,
        };
      }

      const result = await queryBuffered(connection, payload.sql, payload.params, timeoutMs);
      if (result.rows.length > MAX_QUERY_ROWS) {
        throw new QueryTooLargeError(
          `Query result size exceeds maximum allowed rows (${MAX_QUERY_ROWS})`,
        );
      }
      const state: TruncationState = { hasTruncated: false };
      return {
        columns: columnsFromFields(result.fields),
        rows: result.rows.map((row) => processRow(row, state)),
        rows_affected: result.affectedRows,
        ms: Date.now() - startedAt,
        truncated: false,
      };
    } finally {
      if (read) await execRaw(connection, 'ROLLBACK').catch(() => undefined);
      // A connection destroyed by the per-query timeout must not be released
      // into the idle queue; mysql2 removes it from the pool itself.
      if (!(connection.state as { destroyed?: boolean } | undefined)?.destroyed) {
        connection.release();
      }
    }
  }

  async runStreaming(payload: StreamQueryPayload, ctx: DriverQueryContext): Promise<void> {
    const classification = requireClassification(ctx.classification);
    const pool = this.poolFor(ctx.dbEntry);
    const connection = await getConnection(pool);
    const timeoutMs = mysqlTimeout(payload.timeout_ms);
    const startedAt = Date.now();
    const read = classification.type === 'read';

    let chunkIndex = 0;
    let totalRows = 0;
    let columnsSent = false;
    let accumulated: unknown[][] = [];
    let accumulatedBytes = 0;
    let lastChunkAt = Date.now();
    let columns: QueryResultPayload['columns'] = [];

    const flush = async (): Promise<void> => {
      if (!ctx.onChunk || accumulated.length === 0) return;
      const state: TruncationState = { hasTruncated: false };
      const rows = accumulated.map((row) => processRow(row, state));
      const chunk: StreamChunkPayload = {
        request_id: ctx.request_id,
        columns: columnsSent ? null : columns,
        rows,
        chunk_index: chunkIndex++,
        has_truncated_cells: state.hasTruncated,
      };
      columnsSent = true;
      await ctx.onChunk(chunk);
      accumulated = [];
      accumulatedBytes = 0;
      lastChunkAt = Date.now();
    };

    try {
      await this.harden(connection, ctx, timeoutMs);
      if (read) await execRaw(connection, 'START TRANSACTION READ ONLY');

      if (!read) {
        // A write is not streamed row by row. Execute it once and report the
        // affected-row count through a normal terminal frame rather than
        // pretending its result is a cursor.
        const result = await queryBuffered(connection, payload.sql, payload.params, timeoutMs);
        const state: TruncationState = { hasTruncated: false };
        if (result.rows.length > 0) {
          accumulated = result.rows.map((row) => processRow(row, state));
          columns = columnsFromFields(result.fields);
          totalRows = accumulated.length;
          await flush();
        }
        if (ctx.onEnd) {
          await ctx.onEnd({
            request_id: ctx.request_id,
            total_rows: totalRows,
            ms: Date.now() - startedAt,
            chunk_count: chunkIndex,
            truncated: false,
          });
        }
        return;
      }

      const query = connection.query({
        sql: payload.sql,
        values: payload.params as any,
        rowsAsArray: true,
        timeout: timeoutMs,
      });
      const stream = query.stream({ highWaterMark: DEFAULTS.STREAM_CHUNK_ROWS });
      query.on('fields', (fields: FieldPacket[]) => {
        if (fields.length > 0) columns = columnsFromFields(fields);
      });

      const abort = () => {
        stream.destroy();
        connection.destroy();
      };
      if (ctx.abortSignal) {
        if (ctx.abortSignal.aborted) abort();
        else ctx.abortSignal.addEventListener('abort', abort, { once: true });
      }

      try {
        for await (const raw of stream) {
          if (ctx.abortSignal?.aborted) throw new Error('Query was cancelled');
          const row = Array.isArray(raw) ? (raw as unknown[]) : [raw];
          totalRows++;
          if (totalRows > MAX_STREAM_ROWS) {
            await flush();
            stream.destroy();
            throw new StreamTooLargeError(`Stream exceeded maximum rows (${MAX_STREAM_ROWS}).`);
          }
          accumulated.push(row);
          accumulatedBytes += estimateRowBytes(row);

          if (
            accumulated.length >= DEFAULTS.STREAM_CHUNK_ROWS ||
            accumulatedBytes >= DEFAULTS.STREAM_CHUNK_BYTES ||
            Date.now() - lastChunkAt >= DEFAULTS.STREAM_CHUNK_MS
          ) {
            if (ctx.waitForDrain) await ctx.waitForDrain();
            await flush();
          }
        }
        await flush();
      } finally {
        if (ctx.abortSignal) ctx.abortSignal.removeEventListener('abort', abort);
      }

      if (ctx.onEnd) {
        await ctx.onEnd({
          request_id: ctx.request_id,
          total_rows: totalRows,
          ms: Date.now() - startedAt,
          chunk_count: chunkIndex,
          truncated: false,
        });
      }
    } finally {
      if (read) await execRaw(connection, 'ROLLBACK').catch(() => undefined);
      // A destroyed connection must not be released into the idle queue.
      if (!(connection.state as { destroyed?: boolean } | undefined)?.destroyed) {
        connection.release();
      }
    }
  }

  async close(alias: string): Promise<void> {
    const prefix = `${alias}\u0000`;
    const closing: Array<Promise<void>> = [];
    for (const [key, pool] of this.pools) {
      if (key.startsWith(prefix)) {
        this.pools.delete(key);
        closing.push(endPool(pool));
      }
    }
    await Promise.allSettled(closing);
  }

  async closeAll(): Promise<void> {
    const pools = [...this.pools.values()];
    this.pools.clear();
    await Promise.allSettled(pools.map((pool) => endPool(pool)));
  }

  redactConfig(entry: DbEntry): Record<string, unknown> {
    return redactDbEntry(entry);
  }

  /* ---------------------------------------------------------------- */

  private poolOptions(entry: DbEntry, connectionLimit: number): PoolOptions {
    return {
      host: entry.host,
      port: entry.port,
      user: entry.user,
      password: resolveEntryPassword(entry),
      database: entry.database,
      ssl: buildSsl(entry),
      connectionLimit,
      maxIdle: connectionLimit,
      waitForConnections: true,
      queueLimit: 0,
      connectTimeout: 5_000,
      enableKeepAlive: true,
      // MySQL 5.7.3+: reset session state when a connection is returned. It is
      // a second line of defence behind `harden()`, which runs on acquire.
      resetOnRelease: true,
      // The connector never sends multiple statements. A payload that contains
      // one must fail at the parser, not be executed by the driver.
      multipleStatements: false,
      // Exact integers: a BIGINT above 2^53 must not silently round.
      supportBigNumbers: true,
      bigNumberStrings: true,
    };
  }

  private poolFor(entry: DbEntry): Pool {
    const key = [
      entry.db_alias,
      entry.host,
      entry.port,
      entry.database,
      entry.user,
      entry.ssl_mode,
      entry.ssl_root_cert ?? '',
    ].join('\u0000');
    let pool = this.pools.get(key);
    if (!pool) {
      pool = createPool(this.poolOptions(entry, 5));
      this.pools.set(key, pool);
    }
    return pool;
  }

  /**
   * Apply the per-request session posture.
   *
   * `SET SESSION TRANSACTION READ ONLY` is the database-level backstop for a
   * read-only permission level. The explicit `START TRANSACTION READ ONLY`
   * around read statements is narrower and is applied even at `full`.
   */
  /**
   * Remove sql_mode flags that change how quotes and backslashes are lexed.
   *
   * The classifier and `node-sql-parser` assume MySQL's default lexical rules.
   * A server running `NO_BACKSLASH_ESCAPES` would treat `\'` as a literal
   * backslash followed by a closing quote, so a statement that parses as a
   * `SELECT` could reach `INTO OUTFILE` outside the string the parser saw.
   * `ANSI_QUOTES` creates the mirror ambiguity for `"`. The session is
   * normalised on every acquire so the grammar and the server agree.
   *
   * Only the lexing flags are removed; strictness, timezone and every other
   * mode the deployment chose are left intact. A failure to read or set
   * `sql_mode` aborts the statement rather than running under assumptions the
   * classifier cannot verify.
   */
  private async normaliseLexing(connection: PoolConnection): Promise<void> {
    const result = await execRaw(connection, 'SELECT @@SESSION.sql_mode AS mode');
    const row = Array.isArray(result) ? result[0] : undefined;
    const raw = row && typeof row.mode === 'string' ? row.mode : undefined;
    if (typeof raw !== 'string') {
      throw new Error('Could not read the MySQL session sql_mode; refusing to execute unverified SQL.');
    }

    const lexingModes = new Set(['NO_BACKSLASH_ESCAPES', 'ANSI_QUOTES', 'ANSI']);
    const modes = raw
      .split(',')
      .map((mode) => mode.trim())
      .filter((mode) => mode.length > 0);
    const kept = modes.filter((mode) => !lexingModes.has(mode.toUpperCase()));

    if (kept.length !== modes.length) {
      await execRaw(connection, 'SET SESSION sql_mode = ?', [kept.join(',')]);
    }
  }

  private async harden(
    connection: PoolConnection,
    ctx: DriverQueryContext,
    timeoutMs: number,
  ): Promise<void> {
    await execRaw(connection, 'ROLLBACK').catch(() => undefined);
    // Writes are autocommitted like PostgreSQL's non-transactional path. A
    // server with global autocommit=0 would otherwise leave them pending and
    // then roll them back on release.
    await execRaw(connection, 'SET SESSION autocommit = 1');
    await this.normaliseLexing(connection);
    await execRaw(
      connection,
      ctx.readOnlySession
        ? 'SET SESSION TRANSACTION READ ONLY'
        : 'SET SESSION TRANSACTION READ WRITE',
    );
    // SELECT-only timeout. MySQL ignores it for writes, which are bounded by
    // the query-level `timeout` option instead.
    await execRaw(connection, `SET SESSION max_execution_time = ${timeoutMs}`).catch(
      () => undefined,
    );
    await execRaw(connection, `SET SESSION lock_wait_timeout = 10`).catch(() => undefined);
  }

  /**
   * Read rows through a cursor-like stream so the row ceiling binds while rows
   * are produced, not after the whole result has been buffered.
   */
  private async collectRead(
    connection: PoolConnection,
    sql: string,
    params: unknown[] | undefined,
    timeoutMs: number,
    maxRows: number,
  ): Promise<{ rows: unknown[][]; fields: FieldPacket[] }> {
    const query = connection.query({
      sql,
      values: params as any,
      rowsAsArray: true,
      timeout: timeoutMs,
    });
    const stream = query.stream({ highWaterMark: 100 });
    let fields: FieldPacket[] = [];
    query.on('fields', (next: FieldPacket[]) => {
      fields = next;
    });

    const rows: unknown[][] = [];
    const state: TruncationState = { hasTruncated: false };
    try {
      for await (const raw of stream) {
        if (rows.length >= maxRows) {
          stream.destroy();
          throw new QueryTooLargeError(
            `Query result exceeds the maximum of ${maxRows} rows. ` +
              'Use stream_query for large result sets.',
          );
        }
        const row = Array.isArray(raw) ? (raw as unknown[]) : [raw];
        rows.push(processRow(row, state));
      }
    } catch (err) {
      stream.destroy();
      throw err;
    }
    return { rows, fields };
  }
}

function requireClassification(
  classification: StatementClassification | undefined,
): StatementClassification {
  if (!classification) {
    throw new Error(
      'Refusing to execute an unclassified MySQL statement. Classification must happen before execution.',
    );
  }
  return classification;
}
