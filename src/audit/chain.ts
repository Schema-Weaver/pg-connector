import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { getAgentHome } from '../config/paths';
import { AuditEvent, AuditHead } from './types';

/** The hash the first record of a chain chains from. */
export const GENESIS_HASH = '0'.repeat(64);

/** HMAC-SHA256 key length. 32 bytes = 256 bits. */
export const AUDIT_KEY_BYTES = 32;

/** Operator-supplied key (hex or base64). Used by tests and managed deployments. */
export const AUDIT_KEY_ENV = 'SW_AGENT_AUDIT_KEY';

/** Machine-local key file, relative to the agent home (`~/.sw-agent/audit.key`). */
export const AUDIT_KEY_FILENAME = 'audit.key';

/** Anchored chain head, relative to the audit directory. */
export const AUDIT_HEAD_FILENAME = 'head.json';

/**
 * Suffix of the monotonic floor anchor. It is appended to the audit directory's
 * own name, so `<home>/audit` is anchored by `<home>/audit.floor.json`.
 *
 * The file holds the highest sequence number any writer has ever anchored. It is
 * the second, independent claim about the same chain: `head.json` lives with the
 * log, so anyone able to rewrite the log can rewrite the head too, and a matching
 * pair of rolled-back files verifies as a self-consistent chain. This file is
 * what makes that rollback visible (finding C-05, recommended fixes 2a and 3).
 */
export const AUDIT_FLOOR_SUFFIX = '.floor.json';

const KEY_FILE_MODE = 0o600;
const KEY_DIR_MODE = 0o700;
const HEAD_FILE_MODE = 0o600;
const FLOOR_FILE_MODE = 0o600;
const CHAIN_ID_BYTES = 16;

const HASH_HEX = /^[0-9a-f]{64}$/;
const HEX_KEY = /^[0-9a-fA-F]{64}$/;
const BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/;

export type AuditKeySource = 'env' | 'keyfile';

/** An established chain identity: the signing key plus the id it stamps records with. */
export interface AuditKey {
  /** 32 raw bytes. */
  key: Buffer;
  /** Random id generated when the key was created; 32 hex characters. */
  chain_id: string;
  source: AuditKeySource;
  /** Where the key came from — the env var name, or the key file path. */
  origin: string;
}

export class AuditKeyError extends Error {
  readonly code: 'no_key' | 'bad_key' | 'key_io';

  constructor(code: 'no_key' | 'bad_key' | 'key_io', message: string) {
    super(message);
    this.name = 'AuditKeyError';
    this.code = code;
  }
}

export function isHash64(value: unknown): value is string {
  return typeof value === 'string' && HASH_HEX.test(value);
}

/** True when `value` is a whole, non-negative, safe integer. */
function isSeq(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    Number.isSafeInteger(value)
  );
}

/* ------------------------------------------------------------------ */
/* Key establishment                                                    */
/* ------------------------------------------------------------------ */

/**
 * Decodes operator-supplied key material: 64 hex characters, or 44 characters
 * of standard base64. Anything else is rejected rather than coerced — a
 * mistyped key must not silently produce a different key than intended.
 */
export function decodeKeyMaterial(raw: string): Buffer {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new AuditKeyError('bad_key', `${AUDIT_KEY_ENV} is set but empty`);
  }
  if (HEX_KEY.test(trimmed)) {
    const buf = Buffer.from(trimmed, 'hex');
    if (buf.length !== AUDIT_KEY_BYTES) {
      throw new AuditKeyError(
        'bad_key',
        `${AUDIT_KEY_ENV} must decode to ${AUDIT_KEY_BYTES} bytes`,
      );
    }
    return buf;
  }
  if (BASE64_KEY.test(trimmed)) {
    const buf = Buffer.from(trimmed, 'base64');
    if (buf.length !== AUDIT_KEY_BYTES) {
      throw new AuditKeyError(
        'bad_key',
        `${AUDIT_KEY_ENV} must decode to ${AUDIT_KEY_BYTES} bytes`,
      );
    }
    return buf;
  }
  throw new AuditKeyError(
    'bad_key',
    `${AUDIT_KEY_ENV} must be ${AUDIT_KEY_BYTES} bytes as hex (${AUDIT_KEY_BYTES * 2} chars) or base64`,
  );
}

/**
 * Deterministic chain id for a key supplied out of band (no key file to carry
 * one). Derived with the key itself, so it is stable across restarts and reveals
 * nothing without the key.
 */
export function deriveChainId(key: Buffer): string {
  return crypto
    .createHmac('sha256', key)
    .update('sw-agent/audit-chain-id/v1', 'utf8')
    .digest('hex')
    .slice(0, 32);
}

export function newChainId(): string {
  return crypto.randomBytes(CHAIN_ID_BYTES).toString('hex');
}

export interface KeyFileContents {
  v: 1;
  chain_id: string;
  /** base64, 32 bytes */
  key: string;
  created_at: string;
}

function defaultKeyPath(dir?: string): string {
  const base = dir ?? safeAgentHome();
  return path.join(base, AUDIT_KEY_FILENAME);
}

function safeAgentHome(): string {
  try {
    return getAgentHome();
  } catch {
    return path.join(os.homedir(), '.sw-agent');
  }
}

function readKeyFile(keyPath: string): AuditKey | null {
  let raw: string;
  try {
    raw = fs.readFileSync(keyPath, 'utf8');
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return null;
    throw new AuditKeyError('key_io', `cannot read audit key file ${keyPath}: ${String(err)}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new AuditKeyError(
      'bad_key',
      `audit key file ${keyPath} is not valid JSON — refusing to fall back to an unkeyed chain`,
    );
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new AuditKeyError('bad_key', `audit key file ${keyPath} is malformed`);
  }
  const rec = parsed as Partial<KeyFileContents>;
  if (typeof rec.key !== 'string' || typeof rec.chain_id !== 'string') {
    throw new AuditKeyError('bad_key', `audit key file ${keyPath} is missing key/chain_id`);
  }
  let key: Buffer;
  try {
    key = Buffer.from(rec.key, 'base64');
  } catch {
    throw new AuditKeyError('bad_key', `audit key file ${keyPath} has undecodable key material`);
  }
  if (key.length !== AUDIT_KEY_BYTES) {
    throw new AuditKeyError(
      'bad_key',
      `audit key file ${keyPath} does not hold a ${AUDIT_KEY_BYTES}-byte key`,
    );
  }
  return { key, chain_id: rec.chain_id, source: 'keyfile', origin: keyPath };
}

function createKeyFile(keyPath: string): AuditKey {
  const key = crypto.randomBytes(AUDIT_KEY_BYTES);
  const chain_id = newChainId();
  const contents: KeyFileContents = {
    v: 1,
    chain_id,
    key: key.toString('base64'),
    created_at: new Date().toISOString(),
  };

  const dir = path.dirname(keyPath);
  fs.mkdirSync(dir, { recursive: true, mode: KEY_DIR_MODE });
  const tmp = `${keyPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  try {
    // Create with restrictive mode from the start; never briefly world-readable.
    const fd = fs.openSync(tmp, 'wx', KEY_FILE_MODE);
    try {
      fs.writeFileSync(fd, JSON.stringify(contents, null, 2) + '\n', 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(tmp, KEY_FILE_MODE);
    fs.renameSync(tmp, keyPath);
    fsyncDir(dir);
  } catch (err: unknown) {
    // eslint-disable-next-line no-empty
    try {
      fs.unlinkSync(tmp);
    } catch {}
    throw new AuditKeyError('key_io', `cannot create audit key file ${keyPath}: ${String(err)}`);
  }

  return { key, chain_id, source: 'keyfile', origin: keyPath };
}

export interface LoadAuditKeyOptions {
  /** Directory holding `audit.key`. Defaults to the agent home. */
  dir?: string;
  /** Explicit key file path, overriding `dir`. */
  keyPath?: string;
  /** Environment to read `SW_AGENT_AUDIT_KEY` from. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Create the key file when absent. Default true. `false` still reads an existing one. */
  create?: boolean;
  /**
   * Chain id to adopt when the key comes from the environment: keeps a chain
   * continuous across a switch between an operator-supplied key and a key file.
   */
  chainId?: string | null;
}

/**
 * Establishes the chain signing key, or throws.
 *
 * There is deliberately no unkeyed fallback. An audit chain that verifies
 * against a public algorithm proves only internal consistency, which an
 * attacker with write access can reproduce (audit finding C-05); silently
 * degrading to that construction is worse than refusing to run.
 *
 * Precedence: `SW_AGENT_AUDIT_KEY` (operator override) → `audit.key`.
 *
 * `create: false` is read-only: an existing key file is still loaded. It only
 * refuses to mint one, so verification paths can resolve the key without being
 * able to establish a new chain.
 */
export function loadAuditKey(opts: LoadAuditKeyOptions = {}): AuditKey {
  const env = opts.env ?? process.env;
  const keyPath = opts.keyPath ?? defaultKeyPath(opts.dir);
  // Always *read* the file when present; `create` governs minting, not reading.
  const fromFile = readKeyFile(keyPath);

  const raw = env[AUDIT_KEY_ENV];
  if (typeof raw === 'string' && raw.trim().length > 0) {
    const key = decodeKeyMaterial(raw);
    const chain_id = opts.chainId ?? fromFile?.chain_id ?? deriveChainId(key);
    return { key, chain_id, source: 'env', origin: AUDIT_KEY_ENV };
  }

  if (fromFile) return fromFile;

  if (opts.create === false) {
    throw new AuditKeyError(
      'no_key',
      `no audit key: set ${AUDIT_KEY_ENV} or create ${keyPath}. Refusing to verify an unkeyed audit chain.`,
    );
  }
  return createKeyFile(keyPath);
}

/** Non-throwing variant for read-only verification paths. */
export function tryLoadAuditKey(opts: LoadAuditKeyOptions = {}): AuditKey | null {
  try {
    return loadAuditKey(opts);
  } catch {
    return null;
  }
}

/** Normalises key material supplied directly by a caller. */
export function requireKeyBytes(key: Buffer | string | null | undefined): Buffer {
  if (Buffer.isBuffer(key) && key.length === AUDIT_KEY_BYTES) return key;
  if (typeof key === 'string' && key.length > 0) return decodeKeyMaterial(key);
  throw new AuditKeyError(
    'no_key',
    `a ${AUDIT_KEY_BYTES}-byte audit key is required; an unkeyed chain is not offered`,
  );
}

/* ------------------------------------------------------------------ */
/* Head anchor                                                          */
/* ------------------------------------------------------------------ */

export function headPathFor(dir: string): string {
  return path.join(dir, AUDIT_HEAD_FILENAME);
}

/**
 * Reads the anchored head. A missing or malformed head is reported as `null`
 * (not as a pass): without an anchor, a log cannot be shown to be complete.
 */
export function readHead(dir: string): AuditHead | null {
  return readHeadFile(headPathFor(dir));
}

/** Reads and validates one anchor file. Never throws. */
function readHeadFile(target: string): AuditHead | null {
  let raw: string;
  try {
    raw = fs.readFileSync(target, 'utf8');
  } catch {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    return normalizeHead(parsed);
  } catch {
    return null;
  }
}

/**
 * Absolute path of the monotonic floor anchor for an audit directory.
 *
 * It is a sibling of the audit directory, named after it, rather than a file
 * inside it: anyone who can rewrite the log can rewrite an anchor that lives
 * beside it, so the second claim has to sit outside the directory it vouches for.
 * Deriving the name from the audit directory also keeps two audit directories that
 * share a parent (two installations under one home) from sharing a floor.
 *
 * Because the name follows the directory, moving or renaming an audit directory
 * orphans its floor: the moved log then has no second anchor and a rollback of it
 * plus `head.json` is only caught if the operator still holds a copy of the head.
 */
export function floorPathFor(auditDir: string): string {
  const resolved = path.resolve(auditDir);
  return path.join(path.dirname(resolved), `${path.basename(resolved)}${AUDIT_FLOOR_SUFFIX}`);
}

/**
 * Reads the monotonic floor anchor, or `null` when there is none. It is a lower
 * bound on the end of the log, not a second head: it may legitimately lag the log
 * after a crash, but it must never be ahead of it.
 */
export function readHeadFloor(auditDir: string): AuditHead | null {
  return readHeadFile(floorPathFor(auditDir));
}

export function normalizeHead(value: unknown): AuditHead | null {
  if (typeof value !== 'object' || value === null) return null;
  const rec = value as Record<string, unknown>;
  if (typeof rec.chain_id !== 'string' || rec.chain_id.length === 0) return null;
  if (!isSeq(rec.seq)) return null;
  if (!isHash64(rec.last_hash)) return null;
  if (typeof rec.written_at !== 'string') return null;
  const head: AuditHead = {
    v: 1,
    chain_id: rec.chain_id,
    seq: rec.seq,
    last_hash: rec.last_hash,
    written_at: rec.written_at,
  };
  // Absent means "the whole log is retained" — the pre-rotation case.
  if (rec.retained_from_seq === undefined || rec.retained_from_seq === null) return head;
  if (!isSeq(rec.retained_from_seq) || rec.retained_from_seq < 1) return null;
  return { ...head, retained_from_seq: rec.retained_from_seq };
}

export function makeHead(
  seq: number,
  lastHash: string,
  chainId: string,
  retainedFromSeq?: number | null,
): AuditHead {
  const head: AuditHead = {
    v: 1,
    chain_id: chainId,
    seq,
    last_hash: lastHash,
    written_at: new Date().toISOString(),
  };
  if (
    typeof retainedFromSeq === 'number' &&
    Number.isInteger(retainedFromSeq) &&
    retainedFromSeq >= 1
  ) {
    head.retained_from_seq = retainedFromSeq;
  }
  return head;
}

export interface WriteHeadOptions {
  /** fsync the head before returning. Default true. */
  sync?: boolean;
}

/**
 * Persists the head atomically: write a private temp file, rename over the old
 * head. A reader therefore never observes a half-written head.
 *
 * The head is written *after* the record it describes. A crash in between
 * leaves the head behind the log, which recovery detects and repairs; the
 * reverse order would look exactly like a truncation.
 */
export function writeHead(dir: string, head: AuditHead, opts: WriteHeadOptions = {}): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeJsonAtomic(headPathFor(dir), head, HEAD_FILE_MODE, opts.sync !== false, true);
}

/**
 * Advances the floor anchor, and only ever upwards.
 *
 * A floor that went backwards would withdraw a claim the log has already made,
 * which is precisely the truncation this exists to detect. The write happens
 * after `writeHead`, so a crash can only leave the floor *behind* the log — which
 * costs detection of nothing — never ahead of it.
 *
 * Refuses to write over another chain's floor: that is a key rotation or a
 * re-initialisation, and silently discarding the old chain's claim would make
 * the audit trail of the previous chain unverifiable.
 *
 * @returns true when the floor moved.
 */
export function writeHeadFloor(
  auditDir: string,
  head: AuditHead,
  opts: WriteHeadOptions = {},
): boolean {
  if (!isSeq(head.seq) || head.seq < 1) return false;
  const target = floorPathFor(auditDir);
  const current = readHeadFile(target);
  if (current) {
    if (current.chain_id !== head.chain_id) {
      throw new Error(
        `${target} anchors chain ${current.chain_id} at seq ${current.seq}, but this installation signs ` +
          `chain ${head.chain_id}. Refusing to discard another chain's anchor: restore that chain, or ` +
          `delete ${target} if the key was rotated deliberately and the old log is being abandoned.`,
      );
    }
    if (current.seq >= head.seq) return false;
  }
  writeJsonAtomic(target, head, FLOOR_FILE_MODE, opts.sync !== false, false);
  return true;
}

/**
 * Writes one anchor file atomically: a private temp file, then a rename over the
 * old one, so a reader never observes a half-written anchor.
 */
function writeJsonAtomic(
  target: string,
  value: unknown,
  mode: number,
  sync: boolean,
  fsyncParent: boolean,
): void {
  const dir = path.dirname(target);
  const tmp = `${target}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  let fd: number | null = null;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    fs.writeFileSync(fd, JSON.stringify(value) + '\n', 'utf8');
    if (sync) fs.fsyncSync(fd);
  } catch (err: unknown) {
    if (fd !== null) {
      // eslint-disable-next-line no-empty
      try {
        fs.closeSync(fd);
      } catch {}
    }
    // eslint-disable-next-line no-empty
    try {
      fs.unlinkSync(tmp);
    } catch {}
    throw err;
  }
  if (fd !== null) fs.closeSync(fd);
  fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, target);
  if (sync && fsyncParent) fsyncDir(dir);
}

/** fsync a directory so a rename is durable. Best effort: not supported everywhere. */
export function fsyncDir(dir: string): void {
  let dfd: number | null = null;
  try {
    dfd = fs.openSync(dir, 'r');
    fs.fsyncSync(dfd);
  } catch {
    // Directory fsync is unsupported on some platforms; the rename is still atomic.
  } finally {
    if (dfd !== null) {
      // eslint-disable-next-line no-empty
      try {
        fs.closeSync(dfd);
      } catch {}
    }
  }
}

/* ------------------------------------------------------------------ */
/* Anchor arbitration                                                  */
/* ------------------------------------------------------------------ */

/** One claim about where the chain ends, and where it came from. */
export interface AnchorClaim {
  head: AuditHead | null;
  /** Human-readable origin, used in the conflict message. */
  source: string;
}

export interface ResolvedAnchor {
  /**
   * The strongest claim available, or `null` when there is none. Every anchor is
   * a statement of the form "the log reached at least seq N, and the record at N
   * hashes to H", so the highest `seq` is the claim that subsumes the others.
   */
  anchor: AuditHead | null;
  /** Where `anchor` came from. */
  anchorSource: string | null;
  /** Set when two claims at the same sequence number disagree: a contradiction. */
  conflict: string | null;
  /** Origins that contributed a claim. */
  sources: string[];
}

/**
 * Combines every available claim about the end of the chain.
 *
 * Two claims at the same `seq` that disagree on `chain_id` or `last_hash` are a
 * contradiction, not a tie to break: the caller must fail closed rather than pick
 * one. Different sequence numbers are not a contradiction — an older anchor is
 * simply a weaker claim — but the retention floor is carried over from whichever
 * claim has one, because it says where the log starts, not where it ends.
 */
export function resolveAnchor(claims: AnchorClaim[]): ResolvedAnchor {
  let anchor: AuditHead | null = null;
  let anchorSource: string | null = null;
  let conflict: string | null = null;
  const sources: string[] = [];

  for (const { head, source } of claims) {
    if (!head) continue;
    sources.push(source);
    const current = anchor;
    const floor = retentionFloorOf(current);

    if (
      current !== null &&
      head.seq === current.seq &&
      (head.chain_id !== current.chain_id || head.last_hash !== current.last_hash)
    ) {
      conflict =
        conflict ??
        `anchors disagree at seq ${head.seq}: ${source} holds ${head.last_hash} but the chain was already ` +
          `anchored at ${current.last_hash}`;
      continue;
    }

    if (current === null || head.seq > current.seq) {
      anchor = withRetentionFloor(head, floor);
      anchorSource = source;
    } else if (floor === undefined && head.retained_from_seq !== undefined) {
      anchor = withRetentionFloor(current, head.retained_from_seq);
    }
  }

  return { anchor, anchorSource, conflict, sources };
}

function retentionFloorOf(head: AuditHead | null): number | undefined {
  return head === null ? undefined : head.retained_from_seq;
}

function withRetentionFloor(head: AuditHead, floor: number | undefined): AuditHead {
  return floor === undefined ? { ...head } : { ...head, retained_from_seq: floor };
}

/* ------------------------------------------------------------------ */
/* Record MAC                                                           */
/* ------------------------------------------------------------------ */

/**
 * Marker for a value `JSON.stringify` has no representation for at all. It is
 * not an encoded value: a property holding it is dropped, an array element
 * holding it becomes `null`, exactly as the transport does.
 */
const OMITTED = Symbol('audit.canonical.omitted');

/** Applies `toJSON` once, as `JSON.stringify` does, before any other test. */
function jsonViewOf(value: object, key: string): unknown {
  const toJSON = (value as { toJSON?: unknown }).toJSON;
  return typeof toJSON === 'function' ? (toJSON as (k: string) => unknown).call(value, key) : value;
}

/**
 * One level of the canonical encoding, keyed by the property name (or the
 * decimal array index) so a `toJSON` that reads its key behaves as it will on
 * disk. Returns {@link OMITTED} for a value the transport cannot carry.
 */
function canonicalEncode(value: unknown, key: string): string | typeof OMITTED {
  const json = value !== null && typeof value === 'object' ? jsonViewOf(value, key) : value;
  if (json === undefined || typeof json === 'function' || typeof json === 'symbol') return OMITTED;
  if (json === null) return 'null';
  if (typeof json !== 'object') return JSON.stringify(json);
  if (Array.isArray(json)) {
    const items: string[] = [];
    for (let i = 0; i < json.length; i++) {
      const encoded = canonicalEncode(json[i], String(i));
      items.push(encoded === OMITTED ? 'null' : encoded);
    }
    return '[' + items.join(',') + ']';
  }
  const record = json as Record<string, unknown>;
  const pairs: string[] = [];
  for (const k of Object.keys(record).sort()) {
    const encoded = canonicalEncode(record[k], k);
    if (encoded === OMITTED) continue;
    pairs.push(JSON.stringify(k) + ':' + encoded);
  }
  return '{' + pairs.join(',') + '}';
}

/**
 * Deterministic canonical JSON encoding used as MAC input.
 *
 * Determinism is required — writer and verifier must agree byte for byte — and
 * it is also why naive recomputation of a chain is trivial: the algorithm is
 * public and the input is public. That is precisely why the *key*, not this
 * encoding, is the control. This function makes a record reproducible by a key
 * holder and unforgeable for anyone else.
 *
 * The invariant this encoding exists to hold:
 *
 * > the bytes MACed are exactly the bytes that will be read back
 *
 * The log file is the transport, so wherever the canonical form and
 * `JSON.stringify` disagreed the disagreement was resolved in favour of
 * `JSON.stringify`:
 *   - a property whose value is `undefined` (or a function or a symbol) is
 *     **omitted**, not encoded as `''` — the key never reaches the file, so
 *     re-canonicalising the parsed record must not invent one
 *   - `undefined` in an array becomes `null`, holes included
 *   - an explicit `null` is kept, because it is a meaningful audit value and
 *     stays distinguishable from the field being absent
 *   - `toJSON` is honoured, so a `Date` encodes as the ISO string the file
 *     will hold
 *
 * The first two are not cosmetic. Encoding `undefined` as `''` MACs a record
 * the JSON round trip cannot reproduce, so a correctly chained log is reported
 * as `mac_mismatch` — a genuine artifact called tampered, which destroys the
 * evidentiary value of the only control that says the agent did what it claims.
 *
 * Normalising here rather than stripping `undefined` at the call sites is what
 * makes the invariant structural rather than a convention: {@link computeMac}
 * is the sole producer of MAC input and it calls this function, so the writer
 * and every verifier — including one reading an existing file — run the same
 * code and cannot drift. A value JSON cannot represent even in principle (a
 * `BigInt`) throws here exactly as it throws on the write path.
 */
export function canonicalStringify(value: unknown): string {
  const encoded = canonicalEncode(value, '');
  // Only reachable when called at the top level; inside a container the value
  // is omitted from its parent rather than encoded on its own.
  return encoded === OMITTED ? '' : encoded;
}

/** The fields covered by the MAC: everything except the MAC itself. */
export type MacInput = Omit<AuditEvent, 'mac' | 'hash'>;

/**
 * Strips the MAC fields so the remaining record can be canonicalised.
 *
 * `mac` and `hash` are the only fields removed here, and they are top-level by
 * construction, so this copy is enough. Fields whose value is `undefined` are
 * deliberately **left in place**: {@link canonicalStringify} omits them, which is
 * the same rule `JSON.stringify` applies to the bytes on disk, so keeping them
 * here cannot make the MAC disagree with what a verifier reads back.
 */
export function macInputOf(event: AuditEvent | MacInput): MacInput {
  const rest = { ...(event as Record<string, unknown>) };
  delete rest.mac;
  delete rest.hash;
  return rest as unknown as MacInput;
}

/**
 * `HMAC-SHA256(key, canonical(record) || prev_hash)`.
 *
 * Requires the installation key; there is no unkeyed variant.
 */
export function computeMac(event: MacInput, key: Buffer | string): string {
  const k = requireKeyBytes(key);
  const input = canonicalStringify(macInputOf(event as MacInput)) + event.prev_hash;
  return crypto.createHmac('sha256', k).update(input, 'utf8').digest('hex');
}

/**
 * Backwards-compatible alias of {@link computeMac}. Retained because it is part
 * of the published package API. The key argument is required: there is no
 * unkeyed fallback.
 */
export function computeHash(event: MacInput, key: Buffer | string): string {
  return computeMac(event, key);
}

/** Verifies one record in place. Returns null when it verifies, else the reason. */
export function verifyEventMac(event: AuditEvent, key: Buffer | string): string | null {
  if (!isHash64(event.mac) && typeof event.mac !== 'string') return 'record has no mac';
  if (event.hash !== event.mac) return 'hash/mac alias mismatch';
  if (!isSeq(event.seq)) return 'record has no usable seq';
  if (typeof event.chain_id !== 'string' || event.chain_id.length === 0)
    return 'record has no chain_id';
  if (!isHash64(event.prev_hash)) return 'record has no prev_hash';
  const expected = computeMac(macInputOf(event), key);
  return expected === event.mac ? null : 'mac does not match';
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

export type ChainFailureReason =
  | 'empty'
  | 'log_missing'
  | 'malformed'
  | 'parse_error'
  | 'key_unavailable'
  | 'chain_id_mismatch'
  | 'seq_gap'
  | 'seq_regression'
  | 'seq_duplicate'
  | 'prev_hash_mismatch'
  | 'mac_mismatch'
  | 'head_mismatch'
  | 'head_missing'
  | 'unreadable';

export interface ChainVerifyResult {
  intact: boolean;
  /** Machine-readable failure reason. */
  reason?: ChainFailureReason;
  detail?: string;
  /** Index within the verified window of the first bad record. */
  brokenAt?: number;
  /** Records examined. */
  events: number;
  /** The head actually observed at the end of the window. */
  observed?: AuditHead;
  /**
   * Sequence number of the oldest record examined.
   *
   * Greater than 1 when rotation has evicted the oldest archives, in which case
   * the linkage to the evicted prefix cannot be re-checked and is not claimed.
   */
  verified_from_seq?: number;
}

export interface ChainVerifyOptions {
  /** Signing key. Defaults to the operator key / key file; absence fails closed. */
  key?: Buffer | string;
  /** Expected head from `head.json`. Enables truncation/rollback detection. */
  head?: AuditHead | null;
  /** Directory to resolve the key from when `key` is omitted. */
  dir?: string;
  /**
   * Sequence number the first record must carry.
   *
   * Default: `head.retained_from_seq` when a head is supplied, else 1. The log
   * is kept in a bounded number of rotated files, so once the oldest archive has
   * been evicted the log legitimately starts above 1; the anchored retention
   * floor is what distinguishes that from a truncation.
   */
  expectedSeq?: number;
  /**
   * Hash the first record must chain from.
   *
   * Defaults to {@link GENESIS_HASH} when the window starts at seq 1. When the
   * window starts later (retention) and this is omitted, the first record's own
   * `prev_hash` is adopted instead — the evicted prefix cannot be re-checked.
   */
  expectedPrevHash?: string;
  /** Chain id every record must carry. Default: pinned from the first record. */
  chainId?: string;
}

function fail(
  reason: ChainFailureReason,
  events: number,
  extra: {
    detail?: string;
    brokenAt?: number;
    observed?: AuditHead;
    verifiedFromSeq?: number;
  } = {},
): ChainVerifyResult {
  return {
    intact: false,
    reason,
    events,
    detail: extra.detail,
    brokenAt: extra.brokenAt,
    observed: extra.observed,
    verified_from_seq: extra.verifiedFromSeq,
  };
}

function resolveKey(opts: ChainVerifyOptions): Buffer | null {
  if (opts.key !== undefined && opts.key !== null) {
    return requireKeyBytes(opts.key);
  }
  const found = tryLoadAuditKey({ dir: opts.dir, create: false });
  return found ? found.key : null;
}

/**
 * Incremental, early-exit chain verifier. Holds only the previous record's
 * mac/seq, so memory is O(1) regardless of log size (audit finding M-06).
 */
export class ChainVerifier {
  private readonly key: Buffer;
  private prev: string;
  private expectedSeq: number;
  private count = 0;
  private failure: ChainVerifyResult | null = null;
  private chainId: string | null;
  private lastSeq = 0;
  private lastMac: string = GENESIS_HASH;
  /** Sequence number of the first record in the window; 1 means from genesis. */
  private readonly windowStartSeq: number;
  /**
   * True when the window starts after seq 1 and no explicit `expectedPrevHash`
   * was supplied, so the first record's own `prev_hash` has to be adopted. The
   * evicted prefix is gone, so its linkage cannot be re-checked — but the first
   * record's MAC covers its own `prev_hash`, so nothing inside the window is
   * left unverified.
   */
  private readonly adoptFirstPrevHash: boolean;

  constructor(
    key: Buffer | string,
    opts: { chainId?: string; expectedSeq?: number; expectedPrevHash?: string } = {},
  ) {
    this.key = requireKeyBytes(key);
    this.prev = opts.expectedPrevHash ?? GENESIS_HASH;
    this.expectedSeq = opts.expectedSeq ?? 1;
    this.windowStartSeq = this.expectedSeq;
    this.adoptFirstPrevHash = opts.expectedPrevHash === undefined && this.expectedSeq > 1;
    this.chainId = opts.chainId ?? null;
  }

  /** Records pushed so far. */
  get events(): number {
    return this.count;
  }

  /** True once any record has failed verification. */
  get failed(): boolean {
    return this.failure !== null;
  }

  /** Adds a record. Records after the first failure are ignored. */
  push(event: unknown): void {
    if (this.failure) return;
    const at = this.count;
    this.count++;

    if (typeof event !== 'object' || event === null || Array.isArray(event)) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: 'record is not an object',
      });
      return;
    }
    const ev = event as AuditEvent;

    if (!isHash64(ev.prev_hash)) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: 'record has no prev_hash',
      });
      return;
    }
    if (typeof ev.seq !== 'number' || !isSeq(ev.seq) || ev.seq < 1) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: 'record has no usable seq',
      });
      return;
    }
    if (typeof ev.chain_id !== 'string' || ev.chain_id.length === 0) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: 'record has no chain_id',
      });
      return;
    }
    if (this.chainId === null) {
      this.chainId = ev.chain_id;
    } else if (ev.chain_id !== this.chainId) {
      this.failure = fail('chain_id_mismatch', this.count, {
        brokenAt: at,
        detail: `record ${at} belongs to chain ${ev.chain_id}, expected ${this.chainId}`,
      });
      return;
    }
    if (ev.seq !== this.expectedSeq) {
      const belowWindow = ev.seq < this.windowStartSeq;
      const regressed = belowWindow || ev.seq < this.lastSeq;
      const reason: ChainFailureReason = regressed
        ? ev.seq === this.lastSeq
          ? 'seq_duplicate'
          : 'seq_regression'
        : ev.seq < this.lastSeq
          ? 'seq_regression'
          : 'seq_gap';
      this.failure = fail(reason, this.count, {
        brokenAt: at,
        detail: `record ${at} carries seq ${ev.seq}, expected ${this.expectedSeq}`,
        verifiedFromSeq: this.windowStartSeq,
      });
      return;
    }
    if (this.adoptFirstPrevHash && at === 0) {
      // Retention window: the record before this one has been evicted on purpose.
      this.prev = ev.prev_hash;
    } else if (ev.prev_hash !== this.prev) {
      this.failure = fail('prev_hash_mismatch', this.count, {
        brokenAt: at,
        detail: `record ${at} does not chain from the previous record`,
        verifiedFromSeq: this.windowStartSeq,
      });
      return;
    }
    if (typeof ev.mac !== 'string' || !isHash64(ev.mac)) {
      this.failure = fail('malformed', this.count, { brokenAt: at, detail: 'record has no mac' });
      return;
    }
    if (ev.hash !== ev.mac) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: 'legacy hash alias disagrees with mac',
      });
      return;
    }

    let expected: string;
    try {
      expected = computeMac(macInputOf(ev), this.key);
    } catch (err: unknown) {
      this.failure = fail('malformed', this.count, {
        brokenAt: at,
        detail: `record ${at} could not be verified: ${String(err)}`,
      });
      return;
    }
    if (expected !== ev.mac) {
      this.failure = fail('mac_mismatch', this.count, {
        brokenAt: at,
        detail: `record ${at} does not match its mac`,
      });
      return;
    }

    this.prev = ev.mac;
    this.lastSeq = ev.seq;
    this.lastMac = ev.mac;
    this.expectedSeq = ev.seq + 1;
  }

  /** The head observed so far, or `null` when nothing has been verified. */
  observedHead(): AuditHead | null {
    if (this.failure || this.chainId === null || this.lastSeq === 0) return null;
    return {
      v: 1,
      chain_id: this.chainId,
      seq: this.lastSeq,
      last_hash: this.lastMac,
      written_at: '',
    };
  }

  /**
   * Final result. When `expectedHead` is supplied the observed head must match
   * it exactly, which is what makes truncation, deletion and rollback visible.
   */
  result(expectedHead?: AuditHead | null): ChainVerifyResult {
    if (this.failure) return this.failure;
    if (this.count === 0) {
      return fail('empty', 0, { detail: 'no records to verify' });
    }
    const observed = this.observedHead()!;
    const from = this.windowStartSeq > 1 ? this.windowStartSeq : undefined;
    if (!expectedHead) {
      return { intact: true, events: this.count, observed, verified_from_seq: from };
    }
    if (expectedHead.chain_id !== observed.chain_id) {
      return fail('head_mismatch', this.count, {
        detail: `head belongs to chain ${expectedHead.chain_id}, log holds ${observed.chain_id}`,
        observed,
        verifiedFromSeq: from,
      });
    }
    if (expectedHead.seq > observed.seq) {
      return fail('seq_regression', this.count, {
        detail: `head expects at least seq ${expectedHead.seq} but the log ends at seq ${observed.seq}`,
        observed,
        verifiedFromSeq: from,
      });
    }
    if (expectedHead.seq < observed.seq) {
      return fail('head_mismatch', this.count, {
        detail: `log ends at seq ${observed.seq}, ahead of the anchored head at ${expectedHead.seq}`,
        observed,
        verifiedFromSeq: from,
      });
    }
    if (expectedHead.last_hash !== observed.last_hash) {
      return fail('head_mismatch', this.count, {
        detail: `record at seq ${observed.seq} does not match the anchored head`,
        observed,
        verifiedFromSeq: from,
      });
    }
    return { intact: true, events: this.count, observed, verified_from_seq: from };
  }
}

/**
 * Verifies an ordered window of records across the whole log, in chronological
 * order — never per rotated file with a fresh genesis, which is what made
 * routine rotation look like tampering (audit finding H-13).
 *
 * What an intact result proves, and only this:
 *   - no record in the window was modified, inserted, removed or reordered
 *     without the installation key
 *   - the sequence numbers are contiguous, so nothing was dropped in the middle
 *   - the tail matches the supplied head, so the log was not truncated, deleted
 *     or rolled back past the anchor
 *
 * What it does **not** prove:
 *   - that this agent wrote the records: there is a MAC, not a signature, so any
 *     process holding the key can produce a verifying chain
 *   - legal attribution — there is no signing identity and no third-party time
 *     source, so a record cannot be tied to a person in a dispute
 *   - anything against an attacker who can write the log *and* both anchors (and
 *     who does not hold the key). Keep a copy of the head you cannot rewrite, and
 *     keep the key out of reach of the log.
 *
 * An empty window is **never** intact: "nothing to check" is not "verified".
 */
export function verifyChain(
  events: AuditEvent[],
  opts: ChainVerifyOptions = {},
): ChainVerifyResult {
  if (!Array.isArray(events) || events.length === 0) {
    return fail('empty', 0, { detail: 'no records to verify' });
  }

  let key: Buffer | null;
  try {
    key = resolveKey(opts);
  } catch (err: unknown) {
    return fail('key_unavailable', events.length, { detail: String(err) });
  }
  if (!key) {
    return fail('key_unavailable', events.length, {
      detail: `no audit key available (${AUDIT_KEY_ENV} or ${AUDIT_KEY_FILENAME}); cannot verify`,
    });
  }

  const verifier = new ChainVerifier(key, {
    chainId: opts.chainId,
    expectedSeq: opts.expectedSeq ?? opts.head?.retained_from_seq ?? 1,
    expectedPrevHash: opts.expectedPrevHash,
  });
  for (const event of events) {
    verifier.push(event);
    if (verifier.failed) break;
  }
  return verifier.result(opts.head ?? null);
}

/**
 * Verifies the log against the head the operator expects (from `head.json`).
 * Thin wrapper over {@link verifyChain} that makes the anchor mandatory in the
 * type signature, so a caller cannot accidentally verify a log against itself.
 */
export function verifyChainAgainstHead(
  events: AuditEvent[],
  head: AuditHead | null,
  opts: ChainVerifyOptions = {},
): ChainVerifyResult {
  if (!head) {
    return fail('head_missing', Array.isArray(events) ? events.length : 0, {
      detail: `no head anchor available (${AUDIT_HEAD_FILENAME}); truncation and rollback cannot be detected`,
    });
  }
  return verifyChain(events, { ...opts, head });
}

export {
  verifyChain as verifyHashChain,
  computeMac as computeEventMac,
  computeMac as computeEventHash,
};
