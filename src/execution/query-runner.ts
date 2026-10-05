import { PoolClient } from 'pg';
import { PoolManager } from './pool';
import { DbEntry } from '../config/db-config';
import { QueryPayload, QueryResultPayload, StreamQueryPayload, StreamChunkPayload, StreamEndPayload } from '../protocol/messages';
import { DEFAULTS } from '../protocol/constants';
import { InFlightRequest } from './types';
import { AgentMessage } from '../protocol/envelope';

export class QueryTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'QueryTooLargeError';
  }
}

export class StreamTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StreamTooLargeError';
  }
}

export class CellSizeLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CellSizeLimitError';
  }
}

export class QueryCancelledError extends Error {
  constructor(message: string = 'Query was cancelled') {
    super(message);
    this.name = 'QueryCancelledError';
  }
}

export interface QueryRunnerOptions {
  poolManager: PoolManager;
}

export interface QueryRunContext {
  dbEntry: DbEntry;
  request_id: string;
  /** Called for each stream chunk. */
  onChunk?: (chunk: StreamChunkPayload) => void;
  /** Called when stream ends. */
  onEnd?: (end: StreamEndPayload) => void;
  /** Abort signal for cancellation. */
  abortSignal?: AbortSignal;
  /** Track this request (for cancellation). */
  registerInFlight?: (req: InFlightRequest) => void;
  unregisterInFlight?: (request_id: string) => void;
}

const OID_TO_NAME = new Map<number, string>();

async function ensureOidMap(client: PoolClient) {
  if (OID_TO_NAME.size > 0) return;
  try {
    const res = await client.query('SELECT oid, typname FROM pg_catalog.pg_type');
    for (const r of res.rows) {
      OID_TO_NAME.set(r.oid, r.typname);
    }
  } catch {
    // Ignore, fallback to oid format
  }
}

function getTypeName(oid: number): string {
  return OID_TO_NAME.get(oid) || `unknown(${oid})`;
}

function estimateRowSize(row: unknown[]): number {
  let size = 0;
  for (const cell of row) {
    if (cell === null || cell === undefined) {
      size += 4;
    } else if (typeof cell === 'string') {
      size += Buffer.byteLength(cell, 'utf8');
    } else if (typeof cell === 'number') {
      size += 8;
    } else if (typeof cell === 'boolean') {
      size += 1;
    } else if (cell instanceof Date) {
      size += 24;
    } else if (Buffer.isBuffer(cell)) {
      size += cell.length;
    } else {
      size += Buffer.byteLength(JSON.stringify(cell), 'utf8');
    }
  }
  return size;
}

function processRowTruncation(row: unknown[], stats: { hasTruncated: boolean }): unknown[] {
  return row.map(cell => {
    if (cell === null || cell === undefined) return cell;

    let contentString: string | null = null;
    let originalSize = 0;

    if (typeof cell === 'string') {
      originalSize = Buffer.byteLength(cell, 'utf8');
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) {
        contentString = cell;
      }
    } else if (Buffer.isBuffer(cell)) {
      originalSize = cell.length;
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) {
        contentString = cell.toString('base64');
      }
    } else if (typeof cell === 'object') {
      const jsonStr = JSON.stringify(cell);
      originalSize = Buffer.byteLength(jsonStr, 'utf8');
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) {
        contentString = jsonStr;
      }
    }

    if (contentString !== null) {
      stats.hasTruncated = true;
      const preview = contentString.substring(0, 100);
      return {
        __truncated: true,
        original_size: originalSize,
        preview,
      };
    }

    return cell;
  });
}

export class QueryRunner {
  private readonly poolManager: PoolManager;

  constructor(opts: QueryRunnerOptions) {
    this.poolManager = opts.poolManager;
  }

  /**
   * Run a one-shot query. Returns the full result.
   * Throws if result exceeds MAX_QUERY_ROWS (caller should send error message).
   */
  async runOneShot(payload: QueryPayload, ctx: QueryRunContext): Promise<QueryResultPayload> {
    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);
    await ensureOidMap(client);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      message: null as unknown as AgentMessage, // Will be wired if dispatcher supplies it
      abort: abortController,
      is_streaming: false,
    };

    if (ctx.registerInFlight) {
      ctx.registerInFlight(inFlightReq);
    }

    const onAbort = () => {
      abortController.abort();
    };

    if (ctx.abortSignal) {
      ctx.abortSignal.addEventListener('abort', onAbort);
    }

    try {
      const timeoutMs = payload.timeout_ms ?? DEFAULTS.QUERY_TIMEOUT_MS;
      if (timeoutMs > 0) {
        await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
      }

      const queryStart = Date.now();
      const res = await client.query({
        text: payload.sql,
        values: payload.params,
        rowMode: 'array',
      });

      if (res.rows.length > DEFAULTS.MAX_QUERY_ROWS) {
        throw new QueryTooLargeError(`Query result size exceeds maximum allowed rows (${DEFAULTS.MAX_QUERY_ROWS})`);
      }

      const columns = (res.fields || []).map(f => ({
        name: f.name,
        type_oid: f.dataTypeID,
        type_name: getTypeName(f.dataTypeID),
      }));

      const truncationStats = { hasTruncated: false };
      const rows = res.rows.map(r => processRowTruncation(r, truncationStats));

      return {
        columns,
        rows,
        rows_affected: res.rowCount !== null && res.rowCount !== undefined ? res.rowCount : -1,
        ms: Date.now() - queryStart,
        truncated: false,
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

  /**
   * Run a streaming query. Calls ctx.onChunk for each chunk, ctx.onEnd when done.
   * Chunks: 100 rows OR 64KB OR 100ms, whichever first.
   * Hard cap: MAX_STREAM_ROWS (1M). After that, sends final chunk with truncated=true.
   */
  async runStreaming(payload: StreamQueryPayload, ctx: QueryRunContext): Promise<void> {
    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);
    await ensureOidMap(client);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      message: null as unknown as AgentMessage,
      abort: abortController,
      is_streaming: true,
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

    const startTime = Date.now();
    let totalRows = 0;
    let chunkIndex = 0;
    let cursorDeclared = false;

    try {
      const timeoutMs = payload.timeout_ms ?? DEFAULTS.QUERY_TIMEOUT_MS;
      if (timeoutMs > 0) {
        await client.query(`SET LOCAL statement_timeout = ${timeoutMs}`);
      }

      // Start transaction to declare cursor
      await client.query('BEGIN');
      
      // Declare cursor name uniquely
      const cursorName = `sw_cursor_${ctx.request_id.replace(/[^a-zA-Z0-9]/g, '_')}`;
      
      // Declare cursor with statement parameter values
      // Note: parameters need to be passed inside query if pg driver supports it, 
      // but parameterized DECLARE is fully supported by node-postgres.
      await client.query({
        text: `DECLARE ${cursorName} CURSOR FOR ${payload.sql}`,
        values: payload.params,
      });
      cursorDeclared = true;

      let accumulatedRows: unknown[][] = [];
      let accumulatedBytes = 0;
      let lastChunkTime = Date.now();
      let columnsMetadataSent = false;
      let columns: Array<{ name: string; type_oid: number; type_name: string }> = [];

      const sendChunk = () => {
        if (!ctx.onChunk) return;

        const hasTruncated = { hasTruncated: false };
        const processedRows = accumulatedRows.map(r => processRowTruncation(r, hasTruncated));

        ctx.onChunk({
          request_id: ctx.request_id,
          columns: columnsMetadataSent ? null : columns,
          rows: processedRows,
          chunk_index: chunkIndex++,
          has_truncated_cells: hasTruncated.hasTruncated,
        });

        columnsMetadataSent = true;
      };

      for (;;) {
        if (isAborted) {
          throw new QueryCancelledError();
        }

        // Fetch small batch
        const fetchRes = await client.query({
          text: `FETCH 50 FROM ${cursorName}`,
          rowMode: 'array',
        });

        const batchRows = fetchRes.rows;
        if (batchRows.length === 0) {
          break;
        }

        if (!columnsMetadataSent && columns.length === 0) {
          columns = (fetchRes.fields || []).map(f => ({
            name: f.name,
            type_oid: f.dataTypeID,
            type_name: getTypeName(f.dataTypeID),
          }));
        }

        for (const row of batchRows) {
          for (const cell of row) {
            if (cell !== null && cell !== undefined) {
              let originalSize = 0;
              if (typeof cell === 'string') {
                originalSize = Buffer.byteLength(cell, 'utf8');
              } else if (Buffer.isBuffer(cell)) {
                originalSize = cell.length;
              } else if (typeof cell === 'object') {
                originalSize = Buffer.byteLength(JSON.stringify(cell), 'utf8');
              }
              if (originalSize > DEFAULTS.MAX_CELL_BYTES) {
                throw new CellSizeLimitError(`Cell size exceeds maximum allowed (${DEFAULTS.MAX_CELL_BYTES} bytes)`);
              }
            }
          }
          accumulatedRows.push(row);
          accumulatedBytes += estimateRowSize(row);
          totalRows++;

          const maxStreamRows = process.env.SW_AGENT_MAX_STREAM_ROWS ? parseInt(process.env.SW_AGENT_MAX_STREAM_ROWS, 10) : DEFAULTS.MAX_STREAM_ROWS;
          if (totalRows > maxStreamRows) {
            throw new StreamTooLargeError(`Stream exceeded maximum rows (${maxStreamRows}).`);
          }

          const rowsFull = accumulatedRows.length >= DEFAULTS.STREAM_CHUNK_ROWS;
          const bytesFull = accumulatedBytes >= DEFAULTS.STREAM_CHUNK_BYTES;
          const timeFull = Date.now() - lastChunkTime >= DEFAULTS.STREAM_CHUNK_MS;

          if (rowsFull || bytesFull || timeFull) {
            sendChunk();
            accumulatedRows = [];
            accumulatedBytes = 0;
            lastChunkTime = Date.now();
          }
        }
      }

      if (accumulatedRows.length > 0) {
        sendChunk();
      }

      if (cursorDeclared) {
        await client.query(`CLOSE ${cursorName}`);
        await client.query('COMMIT');
        cursorDeclared = false;
      }

      if (ctx.onEnd) {
        ctx.onEnd({
          request_id: ctx.request_id,
          total_rows: totalRows,
          ms: Date.now() - startTime,
          chunk_count: chunkIndex,
          truncated: false,
        });
      }
    } catch (err: unknown) {
      if (cursorDeclared) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // ignore
        }
      }
      throw err;
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
