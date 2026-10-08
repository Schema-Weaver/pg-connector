import { PoolClient } from 'pg';
import { PoolManager, clampStatementTimeout, markSessionDirty } from './pool';
import { DbEntry } from '../config/db-config';
import {
  QueryPayload,
  QueryResultPayload,
  StreamQueryPayload,
  StreamChunkPayload,
  StreamEndPayload,
} from '../protocol/messages';
import type { StreamCursor } from '../protocol/messages';
import { DEFAULTS } from '../protocol/constants';
import { extendedArrayQuery, extendedQuery } from './types';
import type { InFlightRequest, StatementClassification } from './types';

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
  /**
   * Called for each stream chunk. The runner AWAITS the returned promise, which
   * is what makes backpressure real: `DataChannel.send` settles on the
   * WebSocket send callback, so the fetch loop stops while the socket drains.
   *
   * The contract returns a Promise because it used to return void while the
   * only implementation returned one: the discarded promise turned a rejected
   * send into an unhandled rejection, which either killed the daemon (Node's
   * `--unhandled-rejections=throw` default) or was swallowed by the global
   * handler, truncating the stream with no `stream_end`.
   */
  onChunk?: (chunk: StreamChunkPayload) => Promise<void>;
  /** Called when stream ends. Awaited, and only ever called once, on success. */
  onEnd?: (end: StreamEndPayload) => void | Promise<void>;
  /**
   * Optional transport drain signal. When supplied, it is awaited before every
   * fetch: the producer pauses while the socket is above the transport's
   * buffered-amount watermark and resumes once it drains. Without it the
   * runner still stops on every awaited send, which throttles the producer to
   * the socket but cannot observe the buffer directly.
   */
  waitForDrain?: () => Promise<void>;
  /** Abort signal for cancellation. */
  abortSignal?: AbortSignal;
  /**
   * Parsed classification of `payload.sql`. Decides whether the one-shot read
   * may be fetched through a cursor. Omitting it is treated as "not provably a
   * read", which is the fail-closed default.
   */
  classification?: StatementClassification;
  registerInFlight?: (req: InFlightRequest) => void;
  unregisterInFlight?: (request_id: string) => void;
}

/* ------------------------------------------------------------------ */
/* Type metadata                                                       */
/* ------------------------------------------------------------------ */

/**
 * A type catalogue: OID to `typname` for ONE database.
 *
 * OIDs are only unique WITHIN a database. The same OID is a different type in
 * a different catalogue, and PostgreSQL reassigns built-in OIDs between major
 * versions and between 32- and 64-bit builds, so type names must never be
 * resolved against a map filled from somebody else's connection. The previous
 * implementation kept a single module-global map plus the name of the database
 * that filled it and cleared it in place on every switch, which is correct only
 * while one request runs at a time: with a query on DB-A and a query on DB-B in
 * flight, B's refill could land between A's `pg_type` read and A's column
 * resolution and type A's rows from B's catalogue.
 *
 * The map here is keyed by database, so the two cannot contaminate each other
 * by construction rather than by timing, and each caller gets the snapshot it
 * started with.
 */
interface OidCatalog {
  /**
   * Snapshot handed out to callers. It is REPLACED, never mutated, so a
   * statement that captured it keeps a consistent view even if the entry is
   * refilled or evicted while that statement is still running.
   */
  types: ReadonlyMap<number, string>;
  /** True once `types` holds a catalogue that was actually read. */
  loaded: boolean;
  /** LRU stamp; higher is more recently used. */
  lastUsed: number;
  /**
   * In-flight fill, shared by every query that misses on this database at the
   * same time, so two concurrent statements on ONE database issue one
   * `pg_type` read instead of racing to overwrite each other's map.
   */
  fill?: Promise<ReadonlyMap<number, string>>;
}

/**
 * Catalogues keyed by `host:port/database`. That triple is the catalogue's
 * identity: two aliases with the same database name on different hosts are two
 * unrelated `pg_type` tables, and an alias whose entry is edited to point
 * elsewhere must not inherit the previous target's names.
 */
const OID_CATALOGS = new Map<string, OidCatalog>();

/**
 * Ceiling on cached catalogues, so a long-running daemon that cycles through
 * many aliases cannot grow the cache without bound. One catalogue is a few
 * thousand short strings, so sixteen is a few megabytes at worst; past the
 * ceiling the least recently used entries are dropped and re-read on demand.
 */
const MAX_OID_CATALOGS = 16;

/** Handed back when a catalogue cannot be read, so `type_name` stays `unknown(N)`. */
const NO_TYPE_NAMES: ReadonlyMap<number, string> = new Map();

let oidCatalogClock = 0;

function oidCatalogKey(dbEntry: DbEntry): string {
  return `${dbEntry.host}:${dbEntry.port}/${dbEntry.database}`;
}

/**
 * Drop the least recently used catalogues once the cache is over its ceiling.
 *
 * An entry whose fill is still running is never dropped: the caller awaiting it
 * holds the snapshot directly, so evicting is safe, but there is no point
 * throwing away a read that is about to complete.
 */
function evictIdleCatalogs(): void {
  if (OID_CATALOGS.size <= MAX_OID_CATALOGS) return;
  const byIdle = [...OID_CATALOGS.entries()].sort((a, b) => a[1].lastUsed - b[1].lastUsed);
  for (const [key, catalog] of byIdle) {
    if (OID_CATALOGS.size <= MAX_OID_CATALOGS) break;
    if (catalog.fill) continue;
    OID_CATALOGS.delete(key);
  }
}

async function readOidCatalog(
  client: PoolClient,
  key: string,
  catalog: OidCatalog,
): Promise<ReadonlyMap<number, string>> {
  try {
    const res = await client.query(
      extendedArrayQuery('SELECT oid, typname FROM pg_catalog.pg_type'),
    );
    const next = new Map<number, string>();
    for (const r of res.rows) next.set(Number((r as unknown[])[0]), String((r as unknown[])[1]));
    catalog.types = next;
    catalog.loaded = true;
    return next;
  } catch {
    // Fall back to numeric OIDs in the response. The failure is deliberately
    // NOT cached: the entry is dropped so the next statement re-reads the
    // catalogue, and a transient error (a database still starting up, a
    // statement_timeout on the lookup) does not leave the process naming every
    // column `unknown(N)` for the life of the daemon.
    if (OID_CATALOGS.get(key) === catalog) OID_CATALOGS.delete(key);
    return NO_TYPE_NAMES;
  }
}

/**
 * The type catalogue for the database this connection is attached to, read on
 * first use and reused afterwards.
 *
 * The result is the snapshot to resolve this statement's columns against, not
 * a reference to the cache entry, so a concurrent statement on another database
 * — or an eviction — cannot change the names underneath a running query.
 */
async function oidCatalogFor(
  client: PoolClient,
  dbEntry: DbEntry,
): Promise<ReadonlyMap<number, string>> {
  const key = oidCatalogKey(dbEntry);
  let catalog = OID_CATALOGS.get(key);
  if (catalog) {
    catalog.lastUsed = ++oidCatalogClock;
  } else {
    catalog = { types: NO_TYPE_NAMES, loaded: false, lastUsed: ++oidCatalogClock };
    OID_CATALOGS.set(key, catalog);
  }
  const entry = catalog;

  // Cache hit: one `pg_type` read per database, not per statement.
  if (entry.loaded) return entry.types;

  if (!entry.fill) {
    entry.fill = readOidCatalog(client, key, entry).finally(() => {
      entry.fill = undefined;
    });
  }
  const types = await entry.fill;
  evictIdleCatalogs();
  return types;
}

function getTypeName(oid: number, types: ReadonlyMap<number, string>): string {
  return types.get(oid) || `unknown(${oid})`;
}

type ColumnMeta = Array<{ name: string; type_oid: number; type_name: string }>;

/** Rows pulled per cursor round trip. Batches bound peak memory per fetch. */
const CURSOR_BATCH_ROWS = 100;

/**
 * Column metadata for a result, with every OID resolved against the catalogue
 * of the database that produced it.
 */
function columnsFromFields(
  fields: Array<{ name: string; dataTypeID: number }> | undefined,
  types: ReadonlyMap<number, string>,
): ColumnMeta {
  return (fields || []).map((f) => ({
    name: f.name,
    type_oid: f.dataTypeID,
    type_name: getTypeName(f.dataTypeID, types),
  }));
}

function estimateRowSize(row: unknown[]): number {
  let size = 0;
  for (const cell of row) {
    if (cell === null || cell === undefined) size += 4;
    else if (typeof cell === 'string') size += Buffer.byteLength(cell, 'utf8');
    else if (typeof cell === 'number') size += 8;
    else if (typeof cell === 'boolean') size += 1;
    else if (cell instanceof Date) size += 24;
    else if (Buffer.isBuffer(cell)) size += cell.length;
    else size += Buffer.byteLength(JSON.stringify(cell), 'utf8');
  }
  return size;
}

/** Byte size of a single cell, used for the per-cell ceiling. */
function cellSize(cell: unknown): number {
  if (cell === null || cell === undefined) return 0;
  if (typeof cell === 'string') return Buffer.byteLength(cell, 'utf8');
  if (Buffer.isBuffer(cell)) return cell.length;
  if (typeof cell === 'object') {
    try {
      return Buffer.byteLength(JSON.stringify(cell), 'utf8');
    } catch {
      return 0;
    }
  }
  return 8;
}

function assertCellWithinLimit(cell: unknown): void {
  if (cellSize(cell) > DEFAULTS.MAX_CELL_BYTES) {
    throw new CellSizeLimitError(
      `Cell size exceeds maximum allowed (${DEFAULTS.MAX_CELL_BYTES} bytes)`,
    );
  }
}

/**
 * Replace any cell over `DEFAULTS.MAX_CELL_BYTES` with a bounded
 * descriptor — the original byte size plus a short sample — so the UI can show
 * what was cut without shipping a megabyte of row data per cell. The full value
 * never leaves the process; this ceiling is the control that bounds the path.
 *
 * `preview` is deliberately NOT routed through `previewStatement()` (audit
 * H-04), because it is a row VALUE and not SQL. That function is a SQL lexer,
 * and applied to row data it fails in both directions: it redacts nothing in the
 * case that matters (`'alice smith, alice@corp.com'` comes back unchanged) while
 * corrupting content that is perfectly safe to display (`"it's fine"` collapses
 * to the unredactable marker, `'42 Main St'` loses its digits, a JSON cell comes
 * back as `{"?":"?"}`). A display sample that misreports its own contents is
 * worse than an honest truncated one, so redaction of oversized-cell samples —
 * if it is ever wanted — needs a row-value redactor, not the SQL one.
 */
function processRowTruncation(row: unknown[], stats: { hasTruncated: boolean }): unknown[] {
  return row.map((cell) => {
    if (cell === null || cell === undefined) return cell;

    let contentString: string | null = null;
    let originalSize = 0;

    if (typeof cell === 'string') {
      originalSize = Buffer.byteLength(cell, 'utf8');
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) contentString = cell;
    } else if (Buffer.isBuffer(cell)) {
      originalSize = cell.length;
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) contentString = cell.toString('base64');
    } else if (typeof cell === 'object') {
      const jsonStr = JSON.stringify(cell);
      originalSize = Buffer.byteLength(jsonStr, 'utf8');
      if (originalSize > DEFAULTS.MAX_CELL_BYTES) contentString = jsonStr;
    }

    if (contentString !== null) {
      stats.hasTruncated = true;
      return {
        __truncated: true,
        original_size: originalSize,
        preview: contentString.substring(0, 100),
      };
    }
    return cell;
  });
}

let cursorSequence = 0;

/**
 * A unique, injection-proof cursor name. The request id is sanitised to
 * identifier characters and truncated so the whole name stays inside
 * PostgreSQL's 63-byte identifier limit.
 */
function cursorNameFor(requestId: string): string {
  cursorSequence = (cursorSequence + 1) % 1_000_000;
  const safe = requestId.replace(/[^A-Za-z0-9]/g, '_').slice(0, 32);
  return `sw_cursor_${cursorSequence}_${safe}`;
}

/**
 * Default page size when a caller sends a cursor without one. Matches the
 * Data Explorer mode the protocol documents.
 */
const DEFAULT_PAGE_SIZE = 50;

/**
 * Hard ceiling on `page_size`. The inbound validator already refuses anything
 * above this; it is repeated here so the runner cannot be driven past it by a
 * caller that skipped validation, and so the value can never exceed the
 * existing 1M row ceiling.
 */
const MAX_PAGE_SIZE = 1_000;

/** Identifier the caller may not control beyond these bounds. */
const MAX_CURSOR_COLUMN_LENGTH = 63;

const ROW_RETURNING_START = /^(?:select|with|table|values)\b/i;

interface ResolvedStreamPage {
  /** Statement to run, keyset-wrapped when a cursor was supplied. */
  sql: string;
  params: unknown[] | undefined;
  /** Rows this request may emit, or null for the whole-stream ceiling. */
  row_limit: number | null;
  cursor: StreamCursor | null;
}

function quoteSqlIdentifier(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function stripTrailingSemicolon(sql: string): string {
  return sql.replace(/;\s*$/, '');
}

function invalidPagination(detail: string): Error {
  return new Error(`invalid_message:${detail}`);
}

/**
 * Resolve `cursor` and `page_size` into an executable statement and a row
 * ceiling.
 *
 * The cursor is applied as an exclusive keyset bound on the caller's own
 * statement — `WHERE page."col" > $n ORDER BY page."col"` for `forward`, `<`
 * for `backward` — with `LIMIT page_size + 1` so the agent can tell a
 * complete page from a truncated one without ever fetching past it. The extra
 * row is what makes `has_more` truthful, and it is also what keeps the
 * statement bounded server-side: the cursor never walks the whole result.
 *
 * A one-row look-ahead is not enough on its own to keep the server from
 * materialising a large intermediate, but PostgreSQL pushes a simple
 * subquery's predicate into the subquery, so the common case streams.
 */
function resolveStreamPage(payload: StreamQueryPayload): ResolvedStreamPage {
  const cursor = payload.cursor;
  const requestedPageSize = payload.page_size;

  let pageSize: number | null = null;
  if (requestedPageSize !== undefined) {
    if (typeof requestedPageSize !== 'number' || !Number.isFinite(requestedPageSize)) {
      throw invalidPagination('page_size must be a finite number.');
    }
    pageSize = Math.min(
      Math.max(Math.floor(requestedPageSize), 1),
      MAX_PAGE_SIZE,
      DEFAULTS.MAX_STREAM_ROWS,
    );
  }

  if (!cursor) {
    return {
      sql: payload.sql,
      params: payload.params,
      row_limit: pageSize,
      cursor: null,
    };
  }

  const column = cursor.column;
  if (
    typeof column !== 'string' ||
    column.length === 0 ||
    column.length > MAX_CURSOR_COLUMN_LENGTH
  ) {
    throw invalidPagination(
      `cursor.column must be a single identifier of 1-${MAX_CURSOR_COLUMN_LENGTH} characters.`,
    );
  }
  if (column.includes('\u0000')) {
    throw invalidPagination('cursor.column must not contain a null byte.');
  }
  if (cursor.last_value === undefined) {
    throw invalidPagination('cursor.last_value must be defined.');
  }
  const direction = cursor.direction === 'backward' ? 'backward' : 'forward';
  if (cursor.direction !== 'forward' && cursor.direction !== 'backward') {
    throw invalidPagination('cursor.direction must be forward or backward.');
  }
  const inner = stripTrailingSemicolon(payload.sql.trim());
  if (!ROW_RETURNING_START.test(inner)) {
    throw invalidPagination('cursor pagination requires a row-returning statement.');
  }

  const effectivePageSize = pageSize ?? DEFAULT_PAGE_SIZE;
  const quoted = quoteSqlIdentifier(column);
  const comparator = direction === 'backward' ? '<' : '>';
  const order = direction === 'backward' ? 'DESC' : 'ASC';
  // The caller's own placeholders keep their numbering; the keyset bound is
  // appended, so it must be the next index rather than `$1`.
  const keysetIndex = (payload.params?.length ?? 0) + 1;

  return {
    sql:
      `SELECT * FROM (${inner}) AS sw_page ` +
      `WHERE sw_page.${quoted} ${comparator} $${keysetIndex} ` +
      `ORDER BY sw_page.${quoted} ${order} ` +
      `LIMIT ${effectivePageSize + 1}`,
    params: [...(payload.params ?? []), cursor.last_value],
    row_limit: effectivePageSize,
    cursor: { column, last_value: cursor.last_value, direction },
  };
}

/**
 * Cursor for the row after the last one delivered. `undefined` when the page
 * ended exactly on its ceiling with nothing left, or when the cursor column is
 * not in the projection (which the keyset predicate would have rejected
 * server-side anyway).
 */
function nextCursorFor(
  cursor: StreamCursor,
  columns: ColumnMeta,
  lastRow: unknown[] | null,
): StreamCursor | undefined {
  if (!lastRow) return undefined;
  const index = columns.findIndex((c) => c.name === cursor.column);
  if (index < 0) return undefined;
  return {
    column: cursor.column,
    last_value: lastRow[index],
    direction: cursor.direction,
  };
}

/**
 * A server-side cursor over one statement, held open in a transaction.
 *
 * This is the single mechanism through which cloud-originated SQL is consumed,
 * for both one-shot and streaming requests. It buys two properties at once:
 *
 *   - the row ceiling binds *while rows are produced*, so a result that would
 *     exhaust memory is abandoned mid-fetch instead of after being buffered;
 *   - the statement is parsed through `DECLARE ... CURSOR FOR`, which is sent
 *     over the extended query protocol, and PostgreSQL therefore rejects a
 *     second command smuggled after a `SELECT`.
 *
 * `close()` commits, `abort()` rolls back. Both are idempotent and neither
 * throws, so every exit path — success, ceiling, cancellation, transport
 * failure — can tear the cursor down.
 */
class IncrementalCursor {
  private inTransaction = false;
  private finished = false;

  private constructor(
    private readonly client: PoolClient,
    readonly name: string,
  ) {}

  /**
   * Open the cursor. Rolls back if the transaction or the declaration fails,
   * so a failed open never leaves a transaction behind on the pooled
   * connection.
   */
  static async open(
    client: PoolClient,
    sql: string,
    params: readonly unknown[] | undefined,
    name: string,
  ): Promise<IncrementalCursor> {
    const cursor = new IncrementalCursor(client, name);
    // Anything that opens a transaction may fail to close it again; the
    // connection is destroyed on release rather than recycled.
    markSessionDirty(client);
    try {
      await client.query(extendedQuery('BEGIN'));
      cursor.inTransaction = true;
      await client.query(extendedQuery(`DECLARE ${name} NO SCROLL CURSOR FOR ${sql}`, params));
    } catch (err) {
      await cursor.abort();
      throw err;
    }
    return cursor;
  }

  /** Fetch the next batch. An empty row array means the cursor is drained. */
  async fetch(batchSize: number): Promise<{
    rows: unknown[][];
    fields: Array<{ name: string; dataTypeID: number }>;
  }> {
    const res = await this.client.query(extendedArrayQuery(`FETCH ${batchSize} FROM ${this.name}`));
    return {
      rows: res.rows as unknown[][],
      fields: (res.fields || []) as Array<{ name: string; dataTypeID: number }>,
    };
  }

  /** Commit and drop the cursor. */
  async close(): Promise<void> {
    await this.finish('COMMIT');
  }

  /** Drop the cursor and roll the transaction back. */
  async abort(): Promise<void> {
    await this.finish('ROLLBACK');
  }

  private async finish(terminator: 'COMMIT' | 'ROLLBACK'): Promise<void> {
    if (this.finished) return;
    this.finished = true;
    if (!this.inTransaction) return;
    this.inTransaction = false;
    try {
      await this.client.query(extendedQuery(`CLOSE ${this.name}`));
    } catch {
      /* still try to terminate the transaction */
    }
    try {
      await this.client.query(extendedQuery(terminator));
    } catch {
      // The connection is unusable. It is marked dirty, so `release()`
      // destroys it instead of recycling it.
    }
  }
}

/* ------------------------------------------------------------------ */

export class QueryRunner {
  private readonly poolManager: PoolManager;

  constructor(opts: QueryRunnerOptions) {
    this.poolManager = opts.poolManager;
  }

  /**
   * Run a one-shot query and return the whole result.
   *
   * Reads are fetched through the shared cursor so the row ceiling is enforced
   * WHILE rows are produced. The previous implementation called `client.query`
   * and only then compared `res.rows.length` against MAX_QUERY_ROWS, which meant
   * a single `SELECT repeat('x', 1048576) FROM generate_series(1,5000000)` could
   * exhaust memory before the check ever ran.
   *
   * Statements that are not provably reads are executed directly, because a
   * cursor would force them into a transaction and change their semantics. They
   * still travel over the extended query protocol, and they are still subject to
   * the `read_only` connection posture.
   */
  async runOneShot(payload: QueryPayload, ctx: QueryRunContext): Promise<QueryResultPayload> {
    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);
    // Snapshot, taken once: every column of this result is resolved against
    // this database's own catalogue, whatever else runs concurrently.
    const typeNames = await oidCatalogFor(client, ctx.dbEntry);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      abort: abortController,
      is_streaming: false,
    };
    if (ctx.registerInFlight) ctx.registerInFlight(inFlightReq);

    // Cooperative cancellation: the canceller aborts this controller, and the
    // fetch loop below actually listens. Previously `inFlightReq.abort` had no
    // listener at all, so local cancellation was a no-op.
    const onAbort = () => abortController.abort();
    if (ctx.abortSignal) {
      if (ctx.abortSignal.aborted) onAbort();
      else ctx.abortSignal.addEventListener('abort', onAbort);
    }

    // Fail closed: without a classification the statement is not provably a
    // read, so it goes through the cursor anyway. A non-transactional statement
    // arriving without one is refused by PostgreSQL rather than executed
    // outside the ceiling.
    const useCursor = ctx.classification?.type === 'read' || ctx.classification === undefined;
    const queryStart = Date.now();

    try {
      // A cancel that arrived between registering the request and executing it
      // stops it here. Without this the statement ran to completion and only
      // the result was discarded, which for a write is a side effect nobody
      // asked for.
      if (abortController.signal.aborted) throw new QueryCancelledError();

      // Session level, and applied per request. `SET LOCAL` outside a
      // transaction block is a silent no-op in PostgreSQL, which is why this
      // used to be decorative. `clampStatementTimeout` caps a client-supplied
      // `timeout_ms` at the server-configured maximum.
      const timeoutMs = clampStatementTimeout(
        payload.timeout_ms,
        this.poolManager.maxStatementTimeoutMs,
      );
      await client.query(extendedQuery(`SET statement_timeout = ${timeoutMs}`));

      if (!useCursor) {
        const res = await client.query(extendedArrayQuery(payload.sql, payload.params));
        const rows = res.rows as unknown[][];
        if (rows.length > DEFAULTS.MAX_QUERY_ROWS) {
          throw new QueryTooLargeError(
            `Query result size exceeds maximum allowed rows (${DEFAULTS.MAX_QUERY_ROWS})`,
          );
        }
        return {
          columns: columnsFromFields(res.fields, typeNames),
          rows: rows.map((r) => processRowTruncation(r, { hasTruncated: false })),
          rows_affected: res.rowCount ?? -1,
          ms: Date.now() - queryStart,
          truncated: false,
        };
      }

      // ---- read path: cursor so the ceiling binds during production ----
      const cursor = await IncrementalCursor.open(
        client,
        payload.sql,
        payload.params,
        cursorNameFor(ctx.request_id),
      );

      const columns: ColumnMeta = [];
      let columnsResolved = false;
      const rows: unknown[][] = [];
      const truncationStats = { hasTruncated: false };
      let total = 0;
      let capped = false;

      try {
        for (;;) {
          if (abortController.signal.aborted) throw new QueryCancelledError();

          const batch = await cursor.fetch(CURSOR_BATCH_ROWS);

          if (!columnsResolved && batch.fields.length > 0) {
            columns.push(...columnsFromFields(batch.fields, typeNames));
            columnsResolved = true;
          }

          if (batch.rows.length === 0) break;

          for (const row of batch.rows) {
            if (total >= DEFAULTS.MAX_QUERY_ROWS) {
              capped = true;
              break;
            }
            total++;
            // Truncate oversized cells as each row is consumed so the raw body
            // is not retained for the life of the result. MAX_CELL_BYTES is a
            // presentation limit for a one-shot read, not a hard failure.
            rows.push(processRowTruncation(row, truncationStats));
          }

          // Stop fetching the moment the ceiling is reached. The remainder of
          // the result is never requested, let alone buffered.
          if (capped) break;
        }

        if (capped) {
          await cursor.abort();
          throw new QueryTooLargeError(
            `Query result exceeds the maximum of ${DEFAULTS.MAX_QUERY_ROWS} rows. ` +
              'Use stream_query for large result sets.',
          );
        }

        await cursor.close();
      } catch (err) {
        await cursor.abort();
        throw err;
      }

      return {
        columns,
        rows,
        rows_affected: total,
        ms: Date.now() - queryStart,
        truncated: false,
      };
    } finally {
      if (ctx.abortSignal) ctx.abortSignal.removeEventListener('abort', onAbort);
      if (ctx.unregisterInFlight) ctx.unregisterInFlight(ctx.request_id);
      release();
    }
  }

  /**
   * Run a streaming query, emitting chunks as rows are fetched.
   *
   * Chunks flush on 100 rows, 64 KB, or 100 ms, whichever comes first. The
   * cursor is the same shared mechanism `runOneShot` uses, and `ctx.onChunk` is
   * awaited, so a slow relay stops the fetch loop instead of buffering the
   * entire result in the WebSocket send buffer.
   *
   * Exactly one terminal outcome is emitted: either `onEnd` on success, or a
   * thrown error that the caller turns into a single `error` frame. A chunk
   * send that rejects therefore ends the stream instead of leaving it open.
   */
  async runStreaming(payload: StreamQueryPayload, ctx: QueryRunContext): Promise<void> {
    // Resolved before the connection is taken: an unusable cursor is a payload
    // problem and must not hold a pool slot.
    const page = resolveStreamPage(payload);

    const { client, release, pid } = await this.poolManager.acquire(ctx.dbEntry);
    // Same snapshot rule as the one-shot path: a stream's column metadata must
    // name types from the database the stream is reading.
    const typeNames = await oidCatalogFor(client, ctx.dbEntry);

    const abortController = new AbortController();
    const inFlightReq: InFlightRequest = {
      request_id: ctx.request_id,
      db_alias: ctx.dbEntry.db_alias,
      pid,
      started_at: Date.now(),
      abort: abortController,
      is_streaming: true,
    };
    if (ctx.registerInFlight) ctx.registerInFlight(inFlightReq);

    const onAbort = () => abortController.abort();
    if (ctx.abortSignal) {
      if (ctx.abortSignal.aborted) onAbort();
      else ctx.abortSignal.addEventListener('abort', onAbort);
    }

    const startTime = Date.now();
    let totalRows = 0;
    let chunkIndex = 0;

    const maxStreamRows = readBoundedEnvInt(
      'SW_AGENT_MAX_STREAM_ROWS',
      DEFAULTS.MAX_STREAM_ROWS,
      1,
    );

    try {
      const timeoutMs = clampStatementTimeout(
        payload.timeout_ms,
        this.poolManager.maxStatementTimeoutMs,
      );
      await client.query(extendedQuery(`SET statement_timeout = ${timeoutMs}`));

      const cursor = await IncrementalCursor.open(
        client,
        page.sql,
        page.params,
        cursorNameFor(ctx.request_id),
      );

      let accumulatedRows: unknown[][] = [];
      let accumulatedBytes = 0;
      let lastChunkTime = Date.now();
      let columnsSent = false;
      let columns: ColumnMeta = [];

      const flush = async (): Promise<void> => {
        if (!ctx.onChunk || accumulatedRows.length === 0) return;
        const hasTruncated = { hasTruncated: false };
        const processed = accumulatedRows.map((r) => processRowTruncation(r, hasTruncated));
        const payloadChunk: StreamChunkPayload = {
          request_id: ctx.request_id,
          columns: columnsSent ? null : columns,
          rows: processed,
          chunk_index: chunkIndex++,
          has_truncated_cells: hasTruncated.hasTruncated,
        };
        columnsSent = true;
        // AWAITED. This is the backpressure: a rejected send surfaces here
        // instead of becoming an unhandled rejection, and the loop stops.
        await ctx.onChunk(payloadChunk);
        // A send can block for as long as the transport is congested, which is
        // the widest window this loop has. A cancel that arrived meanwhile is
        // honoured here rather than after the next round trip.
        if (abortController.signal.aborted) throw new QueryCancelledError();
        accumulatedRows = [];
        accumulatedBytes = 0;
        lastChunkTime = Date.now();
      };

      let pageEndedEarly = false;
      let lastRow: unknown[] | null = null;

      try {
        for (;;) {
          if (abortController.signal.aborted) throw new QueryCancelledError();

          // Pause the producer while the transport is above its watermark.
          if (ctx.waitForDrain) await ctx.waitForDrain();

          // Never ask for more than the page can deliver.
          const remaining =
            page.row_limit === null ? CURSOR_BATCH_ROWS : page.row_limit - totalRows + 1;
          if (remaining <= 0) {
            pageEndedEarly = true;
            break;
          }

          const fetchRes = await cursor.fetch(Math.min(CURSOR_BATCH_ROWS, remaining));

          if (!columnsSent && columns.length === 0 && fetchRes.fields.length > 0) {
            columns = columnsFromFields(fetchRes.fields, typeNames);
          }

          if (fetchRes.rows.length === 0) break;

          for (const row of fetchRes.rows) {
            // A row past the page ceiling is the one-row look-ahead: it is
            // proof that the server still had rows, and it is never sent.
            if (page.row_limit !== null && totalRows >= page.row_limit) {
              pageEndedEarly = true;
              break;
            }
            for (const cell of row) assertCellWithinLimit(cell);
            accumulatedRows.push(row);
            accumulatedBytes += estimateRowSize(row);
            totalRows++;
            lastRow = row;

            if (totalRows > maxStreamRows) {
              await flush();
              await cursor.abort();
              throw new StreamTooLargeError(`Stream exceeded maximum rows (${maxStreamRows}).`);
            }

            if (
              accumulatedRows.length >= DEFAULTS.STREAM_CHUNK_ROWS ||
              accumulatedBytes >= DEFAULTS.STREAM_CHUNK_BYTES ||
              Date.now() - lastChunkTime >= DEFAULTS.STREAM_CHUNK_MS
            ) {
              await flush();
            }
          }

          if (pageEndedEarly) break;
        }

        await flush();
        await cursor.close();
      } catch (err) {
        await cursor.abort();
        throw err;
      }

      if (ctx.onEnd) {
        const nextCursor = page.cursor ? nextCursorFor(page.cursor, columns, lastRow) : undefined;
        await ctx.onEnd({
          request_id: ctx.request_id,
          total_rows: totalRows,
          ms: Date.now() - startTime,
          chunk_count: chunkIndex,
          // A page that ends at its ceiling stopped short of the whole result.
          // For a cursor page that is not truncation, it is `has_more`.
          truncated: pageEndedEarly && nextCursor === undefined,
          ...(pageEndedEarly && nextCursor ? { has_more: true, next_cursor: nextCursor } : {}),
        });
      }
    } finally {
      if (ctx.abortSignal) ctx.abortSignal.removeEventListener('abort', onAbort);
      if (ctx.unregisterInFlight) ctx.unregisterInFlight(ctx.request_id);
      release();
    }
  }
}

/**
 * Read an integer environment override, rejecting NaN, zero, negatives and
 * absurd values. Previously `SW_AGENT_MAX_STREAM_ROWS=abc` produced NaN and
 * disabled the row ceiling entirely.
 */
function readBoundedEnvInt(name: string, fallback: number, min: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return Math.min(parsed, 100_000_000);
}
