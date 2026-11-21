/**
 * MongoDB driver.
 *
 * The execution layer implements exactly five read methods — `find`,
 * `aggregate`, `count`, `distinct` and the database-scoped `listCollections` —
 * and nothing else. `listCollections` returns `{ name, type }` metadata with
 * `nameOnly: true`; there is deliberately no `db.command()` passthrough and no
 * generic collection method dispatch, since a passthrough would make every
 * server-side operator reachable and turn the classifier into decoration.
 *
 * The read-only posture is enforced in three places:
 *
 *   1. The classifier refuses every method outside the allow-list, and blocks
 *      `$out`/`$merge` (plus server-side JavaScript) anywhere in a pipeline.
 *   2. The client is built with `retryWrites=false`, a configured
 *      `readPreference`, and a configured `readConcern`. Those options are not
 *      caller-overridable — the command validator rejects them in `options`.
 *   3. The deployment is expected to use a read-only MongoDB role. That is the
 *      boundary the agent cannot bypass, exactly as the read-only PostgreSQL
 *      role is. `README.md` documents the role.
 */
import {
  MongoClient,
  ReadPreference,
  type Collection,
  type Document,
  type MongoClientOptions,
} from 'mongodb';
import type { DbEntry } from '../config/db-config';
import { redactDbEntry } from '../config/db-config';
import { DEFAULTS } from '../protocol/constants';
import type {
  QueryPayload,
  QueryResultPayload,
  StreamChunkPayload,
  StreamQueryPayload,
} from '../protocol/messages';
import { QueryTooLargeError, StreamTooLargeError } from '../execution/query-runner';
import type {
  DatabaseDriver,
  DriverCapabilities,
  DriverClassifyOptions,
  DriverConnectionInfo,
  DriverQueryContext,
} from './types';
import { classifyMongoStatement } from './mongodb-classifier';
import { parseMongoQuery, type MongoQuery } from './mongodb-query';
import { resolveEntryPassword } from './credentials';

/* eslint-disable @typescript-eslint/no-explicit-any */

const DEFAULT_TIMEOUT_MS = DEFAULTS.QUERY_TIMEOUT_MS;
const MAX_TIMEOUT_MS = 300_000;
const MAX_QUERY_ROWS = DEFAULTS.MAX_QUERY_ROWS;
const MAX_STREAM_ROWS = DEFAULTS.MAX_STREAM_ROWS;

function mongoTimeout(payloadMs: number | undefined): number {
  if (typeof payloadMs !== 'number' || !Number.isFinite(payloadMs) || payloadMs <= 0) {
    return DEFAULT_TIMEOUT_MS;
  }
  return Math.min(Math.floor(payloadMs), MAX_TIMEOUT_MS);
}

function hostForUri(host: string): string {
  // An IPv6 literal has to be bracketed in a URI authority. A hostname must
  // not be, so only bracket when a colon is present and brackets are absent.
  if (host.includes(':') && !host.startsWith('[')) return `[${host}]`;
  return host;
}

export function buildMongoUri(entry: DbEntry, password: string): string {
  const scheme = entry.srv ? 'mongodb+srv' : 'mongodb';
  const authority = entry.srv
    ? hostForUri(entry.host)
    : `${hostForUri(entry.host)}:${String(entry.port)}`;
  const user = encodeURIComponent(entry.user);
  const pass = encodeURIComponent(password);
  const params = new URLSearchParams();

  params.set('authSource', entry.auth_source || entry.database);
  params.set('appName', 'schema-weaver-db-connector');
  // Writes are never retried. A read-only deployment should also refuse them,
  // but this removes one path by which the driver could replay a write.
  params.set('retryWrites', 'false');
  params.set('readPreference', entry.read_preference || 'primary');
  params.set('readConcernLevel', entry.read_concern || 'local');

  if (entry.ssl_mode === 'disable') {
    params.set('tls', 'false');
  } else {
    params.set('tls', 'true');
    params.set(
      'tlsAllowInvalidCertificates',
      entry.ssl_mode === 'require' ? 'true' : 'false',
    );
    params.set(
      'tlsAllowInvalidHostnames',
      entry.ssl_mode === 'require' || entry.ssl_mode === 'verify-ca' ? 'true' : 'false',
    );
    if (entry.ssl_root_cert) {
      params.set('tlsCAFile', entry.ssl_root_cert);
    }
  }

  return `${scheme}://${user}:${pass}@${authority}/${encodeURIComponent(
    entry.database,
  )}?${params.toString()}`;
}

function clientOptions(entry: DbEntry): MongoClientOptions {
  return {
    appName: 'schema-weaver-db-connector',
    serverSelectionTimeoutMS: 5_000,
    connectTimeoutMS: 5_000,
    maxPoolSize: 5,
    minPoolSize: 0,
    retryWrites: false,
    readPreference: (entry.read_preference || 'primary') as unknown as ReadPreference,
    readConcern: { level: entry.read_concern || 'local' } as any,
  };
}

function jsonReplacer(_key: string, value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString();
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (value && typeof value === 'object') {
    const candidate = value as any;
    if (typeof candidate.toHexString === 'function') {
      return String(candidate.toHexString());
    }
    if (typeof candidate._bsontype === 'string') {
      if (candidate._bsontype === 'Binary' && candidate.buffer) {
        return Buffer.from(candidate.buffer).toString('base64');
      }
      if (typeof candidate.toString === 'function') return String(candidate.toString());
    }
    if (value instanceof RegExp) return value.toString();
  }
  return value;
}

function toJsonCell(value: unknown): string {
  try {
    return JSON.stringify(value, jsonReplacer);
  } catch {
    return '"[unserialisable document]"';
  }
}

function toJsonValue(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  return toJsonCell(value);
}

function documentRow(document: Document): unknown[] {
  return [toJsonCell(document)];
}

function cursorOptions(query: MongoQuery, maxTimeMS: number): Record<string, unknown> {
  const options: Record<string, unknown> = { maxTimeMS };
  for (const key of ['sort', 'projection', 'skip', 'hint', 'collation', 'comment', 'batchSize']) {
    if (query.options[key] !== undefined) options[key] = query.options[key];
  }
  return options;
}

function limitOption(query: MongoQuery, cap: number): number | undefined {
  const requested = query.options.limit;
  if (typeof requested !== 'number') return cap;
  return Math.min(requested, cap);
}

function requireCollection(query: MongoQuery): string {
  if (query.collection === undefined) {
    throw new Error(`Method "${query.method}" requires a collection`);
  }
  return query.collection;
}

export class MongoDriver implements DatabaseDriver {
  readonly type = 'mongodb' as const;
  readonly display_name = 'MongoDB';
  readonly default_port = 27017;
  readonly capabilities: DriverCapabilities = {
    query: true,
    stream: true,
    introspect: false,
    migration: false,
    server_cancel: false,
  };

  private readonly clients = new Map<string, MongoClient>();

  async classify(sql: string, _options: DriverClassifyOptions = {}) {
    void _options;
    return classifyMongoStatement(sql);
  }

  async testConnection(entry: DbEntry): Promise<DriverConnectionInfo> {
    const client = new MongoClient(buildMongoUri(entry, resolveEntryPassword(entry)), {
      ...clientOptions(entry),
      maxPoolSize: 1,
    });
    try {
      await client.connect();
      const db = client.db(entry.database);
      await db.command({ ping: 1 });
      let version = 'MongoDB';
      try {
        const info = (await db.command({ buildInfo: 1 })) as { version?: unknown };
        if (typeof info.version === 'string') version = `MongoDB ${info.version}`;
      } catch {
        // `ping` already proved connectivity and authentication. buildInfo can
        // be withheld by a restricted role, which is not a connection failure.
      }
      return { version, database: entry.database, user: entry.user };
    } finally {
      await client.close().catch(() => undefined);
    }
  }

  async runOneShot(payload: QueryPayload, ctx: DriverQueryContext): Promise<QueryResultPayload> {
    requireClassification(ctx.classification);
    requireNoBindParameters(payload.params);
    const query = parseMongoQuery(payload.sql);
    const maxTimeMS = mongoTimeout(payload.timeout_ms);
    const startedAt = Date.now();

    if (query.method === 'listCollections') {
      const cursor = this.clientFor(ctx.dbEntry)
        .db(ctx.dbEntry.database)
        .listCollections(
          {},
          {
            nameOnly: true,
            maxTimeMS,
            ...(query.options.batchSize !== undefined
              ? { batchSize: query.options.batchSize as number }
              : {}),
          },
        );
      const rows: unknown[][] = [];
      try {
        for await (const info of cursor) {
          if (rows.length >= MAX_QUERY_ROWS) {
            throw new QueryTooLargeError(
              `Query result exceeds the maximum of ${MAX_QUERY_ROWS} rows. ` +
                'Use stream_query for large result sets.',
            );
          }
          rows.push(documentRow(info));
        }
      } finally {
        await cursor.close().catch(() => undefined);
      }

      return {
        columns: [{ name: 'document', type_oid: 0, type_name: 'json' }],
        rows,
        rows_affected: rows.length,
        ms: Date.now() - startedAt,
        truncated: false,
      };
    }

    const collection = this.collectionFor(ctx.dbEntry, requireCollection(query));

    if (query.method === 'count') {
      // countDocuments returns a number, so there is nothing to buffer. A
      // caller-supplied `limit` is honoured as Mongo's own count limit.
      const options = cursorOptions(query, maxTimeMS) as Record<string, unknown>;
      if (typeof query.options.limit === 'number') options.limit = query.options.limit;
      const count = await collection.countDocuments(query.filter ?? {}, options as any);
      return {
        columns: [{ name: 'count', type_oid: 0, type_name: 'number' }],
        rows: [[String(count)]],
        rows_affected: Number(count),
        ms: Date.now() - startedAt,
        truncated: false,
      };
    }

    if (query.method === 'distinct') {
      const values = await collection.distinct(query.field!, query.filter ?? {}, {
        maxTimeMS,
        ...(query.options.collation !== undefined
          ? { collation: query.options.collation as any }
          : {}),
        ...(query.options.comment !== undefined
          ? { comment: query.options.comment as string }
          : {}),
      });
      if (values.length > MAX_QUERY_ROWS) {
        throw new QueryTooLargeError(
          `Query result exceeds the maximum of ${MAX_QUERY_ROWS} rows. ` +
            'Use stream_query for large result sets.',
        );
      }
      return {
        columns: [{ name: query.field!, type_oid: 0, type_name: 'mixed' }],
        rows: values.map((value) => [toJsonValue(value)]),
        rows_affected: values.length,
        ms: Date.now() - startedAt,
        truncated: false,
      };
    }

    const cursor =
      query.method === 'find'
        ? collection.find(query.filter ?? {}, cursorOptions(query, maxTimeMS) as any)
        : collection.aggregate(cappedPipeline(query, MAX_QUERY_ROWS), {
            ...(cursorOptions(query, maxTimeMS) as any),
            allowDiskUse: false,
          });

    if (query.method === 'find') {
      (cursor as any).limit(limitOption(query, MAX_QUERY_ROWS + 1)!);
    }

    const rows: unknown[][] = [];
    try {
      for await (const document of cursor) {
        if (rows.length >= MAX_QUERY_ROWS) {
          throw new QueryTooLargeError(
            `Query result exceeds the maximum of ${MAX_QUERY_ROWS} rows. ` +
              'Use stream_query for large result sets.',
          );
        }
        rows.push(documentRow(document));
      }
    } finally {
      await cursor.close().catch(() => undefined);
    }

    return {
      columns: [{ name: 'document', type_oid: 0, type_name: 'json' }],
      rows,
      rows_affected: rows.length,
      ms: Date.now() - startedAt,
      truncated: false,
    };
  }

  async runStreaming(payload: StreamQueryPayload, ctx: DriverQueryContext): Promise<void> {
    requireClassification(ctx.classification);
    requireNoBindParameters(payload.params);
    const query = parseMongoQuery(payload.sql);
    if (query.method === 'listCollections') {
      throw new Error(
        'listCollections is only supported on query; use query to list collections.',
      );
    }
    const maxTimeMS = mongoTimeout(payload.timeout_ms);
    const startedAt = Date.now();
    const collection = this.collectionFor(ctx.dbEntry, requireCollection(query));

    let chunkIndex = 0;
    let totalRows = 0;
    let accumulated: unknown[][] = [];
    let lastChunkAt = Date.now();
    let columnsSent = false;

    const columns: QueryResultPayload['columns'] =
      query.method === 'count'
        ? [{ name: 'count', type_oid: 0, type_name: 'number' }]
        : query.method === 'distinct'
          ? [{ name: query.field!, type_oid: 0, type_name: 'mixed' }]
          : [{ name: 'document', type_oid: 0, type_name: 'json' }];

    const flush = async (): Promise<void> => {
      if (!ctx.onChunk || accumulated.length === 0) return;
      const chunk: StreamChunkPayload = {
        request_id: ctx.request_id,
        columns: columnsSent ? null : columns,
        rows: accumulated,
        chunk_index: chunkIndex++,
        has_truncated_cells: false,
      };
      columnsSent = true;
      await ctx.onChunk(chunk);
      accumulated = [];
      lastChunkAt = Date.now();
    };

    const push = async (row: unknown[]): Promise<void> => {
      totalRows++;
      if (totalRows > MAX_STREAM_ROWS) {
        await flush();
        throw new StreamTooLargeError(`Stream exceeded maximum rows (${MAX_STREAM_ROWS}).`);
      }
      accumulated.push(row);
      if (
        accumulated.length >= DEFAULTS.STREAM_CHUNK_ROWS ||
        Date.now() - lastChunkAt >= DEFAULTS.STREAM_CHUNK_MS
      ) {
        if (ctx.waitForDrain) await ctx.waitForDrain();
        await flush();
      }
    };

    if (query.method === 'count') {
      const options = cursorOptions(query, maxTimeMS) as Record<string, unknown>;
      if (typeof query.options.limit === 'number') options.limit = query.options.limit;
      const count = await collection.countDocuments(query.filter ?? {}, options as any);
      await push([String(count)]);
    } else if (query.method === 'distinct') {
      const values = await collection.distinct(query.field!, query.filter ?? {}, {
        maxTimeMS,
      });
      for (const value of values) {
        if (ctx.abortSignal?.aborted) throw new Error('Query was cancelled');
        await push([toJsonValue(value)]);
      }
    } else {
      const cursor =
        query.method === 'find'
          ? collection.find(query.filter ?? {}, cursorOptions(query, maxTimeMS) as any)
          : collection.aggregate(cappedPipeline(query, MAX_STREAM_ROWS), {
              ...(cursorOptions(query, maxTimeMS) as any),
              allowDiskUse: false,
            });

      if (query.method === 'find') {
        (cursor as any).limit(limitOption(query, MAX_STREAM_ROWS + 1)!);
      }

      try {
        for await (const document of cursor) {
          if (ctx.abortSignal?.aborted) throw new Error('Query was cancelled');
          await push(documentRow(document));
        }
      } finally {
        await cursor.close().catch(() => undefined);
      }
    }

    await flush();
    if (ctx.onEnd) {
      await ctx.onEnd({
        request_id: ctx.request_id,
        total_rows: totalRows,
        ms: Date.now() - startedAt,
        chunk_count: chunkIndex,
        truncated: false,
      });
    }
  }

  async close(alias: string): Promise<void> {
    const prefix = `${alias}\u0000`;
    const closing: Array<Promise<void>> = [];
    for (const [key, client] of this.clients) {
      if (key.startsWith(prefix)) {
        this.clients.delete(key);
        closing.push(client.close());
      }
    }
    await Promise.allSettled(closing);
  }

  async closeAll(): Promise<void> {
    const clients = [...this.clients.values()];
    this.clients.clear();
    await Promise.allSettled(clients.map((client) => client.close()));
  }

  redactConfig(entry: DbEntry): Record<string, unknown> {
    return redactDbEntry(entry);
  }

  /* ---------------------------------------------------------------- */

  private clientFor(entry: DbEntry): MongoClient {
    const key = [
      entry.db_alias,
      entry.host,
      entry.port,
      entry.database,
      entry.user,
      entry.srv ? 'srv' : 'tcp',
      entry.auth_source ?? '',
      entry.read_preference ?? '',
      entry.read_concern ?? '',
      entry.ssl_mode,
      entry.ssl_root_cert ?? '',
    ].join('\u0000');
    let client = this.clients.get(key);
    if (!client) {
      client = new MongoClient(buildMongoUri(entry, resolveEntryPassword(entry)), clientOptions(entry));
      this.clients.set(key, client);
    }
    return client;
  }

  private collectionFor(entry: DbEntry, collection: string): Collection<Document> {
    return this.clientFor(entry).db(entry.database).collection(collection);
  }
}

/** A user limit must not let one command fetch the whole collection in memory. */
function cappedPipeline(query: MongoQuery, cap: number): Document[] {
  const pipeline = [...(query.pipeline ?? [])];
  pipeline.push({ $limit: cap + 1 });
  return pipeline;
}

function requireClassification(classification: unknown): void {
  if (!classification) {
    throw new Error(
      'Refusing to execute an unclassified MongoDB command. Classification must happen before execution.',
    );
  }
}

function requireNoBindParameters(params: unknown[] | undefined): void {
  if (Array.isArray(params) && params.length > 0) {
    throw new Error('Bind parameters are not supported for MongoDB commands.');
  }
}
