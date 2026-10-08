import { MachineConfig } from '../../config/machine-config';
import { DatabasesConfig } from '../../config/db-config';
import { isProcessAlive } from '../daemon/pid-file';
import { Pool, PoolConfig } from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import { AUDIT_DIR_MODE, ensureAuditDir, probeAuditDir } from '../../audit/files';
import { verifyAuditDirCached, type CachedVerifyResult } from '../../audit/verify-cache';
import { buildSslConfig } from '../../execution/pool';
import { RECOMMENDED_PG_ROLE } from '../../permissions/role-policy';

export interface DoctorCheck {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  detail?: string;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export interface DoctorContext {
  swAgentDir: string;
  machineConfig: MachineConfig | null;
  databasesConfig: DatabasesConfig | null;
  nodeVersion: string;
  platform: string;
}

export async function checkSwAgentDirExists(ctx: DoctorContext): Promise<DoctorCheck> {
  try {
    const fs_ = await import('fs/promises');
    const stat = await fs_.stat(ctx.swAgentDir);
    if (stat.isDirectory()) {
      return { name: 'SW Agent directory exists', status: 'pass' };
    }
    return { name: 'SW Agent directory exists', status: 'fail', detail: 'Not a directory' };
  } catch {
    return {
      name: 'SW Agent directory exists',
      status: 'fail',
      detail: 'Directory does not exist',
    };
  }
}

export async function checkMachineConfigValid(ctx: DoctorContext): Promise<DoctorCheck> {
  if (!ctx.machineConfig) {
    return {
      name: 'Machine config valid',
      status: 'fail',
      detail: 'Config file missing or invalid',
    };
  }
  if (!ctx.machineConfig.agent_token) {
    return { name: 'Machine config valid', status: 'fail', detail: 'Missing agent_token' };
  }
  return {
    name: 'Machine config valid',
    status: 'pass',
    detail: `Agent ID: ${ctx.machineConfig.agent_id}`,
  };
}

export async function checkTokenFormat(ctx: DoctorContext): Promise<DoctorCheck> {
  if (!ctx.machineConfig?.agent_token) {
    return { name: 'Token format', status: 'fail', detail: 'No token to check' };
  }
  const token = ctx.machineConfig.agent_token;
  const pattern = /^swagt_[A-Za-z0-9]{32}$/;
  if (pattern.test(token)) {
    return { name: 'Token format', status: 'pass' };
  }
  if (!token.startsWith('swagt_')) {
    return { name: 'Token format', status: 'fail', detail: 'Token must start with "swagt_"' };
  }
  const body = token.slice(6);
  if (body.length < 32) {
    return {
      name: 'Token format',
      status: 'fail',
      detail: `Token body too short (${body.length} chars, expected 32)`,
    };
  }
  if (body.length > 32) {
    return {
      name: 'Token format',
      status: 'fail',
      detail: `Token body too long (${body.length} chars, expected 32)`,
    };
  }
  if (!/^[A-Za-z0-9]+$/.test(body)) {
    return {
      name: 'Token format',
      status: 'fail',
      detail: 'Token body contains invalid characters (must be base62)',
    };
  }
  return { name: 'Token format', status: 'pass' };
}

export async function checkDatabasesConfigValid(ctx: DoctorContext): Promise<DoctorCheck> {
  if (!ctx.databasesConfig) {
    return {
      name: 'Databases config valid',
      status: 'fail',
      detail: 'Config file missing or invalid',
    };
  }
  if (ctx.databasesConfig.databases.length === 0) {
    return { name: 'Databases config valid', status: 'warn', detail: 'No databases configured' };
  }
  return {
    name: 'Databases config valid',
    status: 'pass',
    detail: `${ctx.databasesConfig.databases.length} database(s) configured`,
  };
}

export async function checkDatabasesReachable(ctx: DoctorContext): Promise<DoctorCheck> {
  if (!ctx.databasesConfig || ctx.databasesConfig.databases.length === 0) {
    return {
      name: 'Databases reachable',
      status: 'warn',
      detail: 'No databases configured to test',
    };
  }

  const results: { alias: string; ok: boolean; detail: string }[] = [];
  for (const db of ctx.databasesConfig.databases) {
    try {
      const password =
        db.password_stored || (db.password_env ? process.env[db.password_env] : undefined);
      if (!password) {
        results.push({ alias: db.db_alias, ok: false, detail: 'No password configured' });
        continue;
      }

      const poolConfig: PoolConfig = {
        host: db.host,
        port: db.port,
        database: db.database,
        user: db.user,
        password,
        connectionTimeoutMillis: 5000,
      };
      // Same negotiator the pool uses, so doctor cannot report a healthy
      // private-CA database as unreachable. An inlined copy of this logic was
      // the bug: it dropped the CA, and used the system trust store instead.
      poolConfig.ssl = buildSslConfig(db.ssl_mode, db.ssl_root_cert, db.host);

      const pool = new Pool(poolConfig);
      try {
        await Promise.race([
          pool.query('SELECT 1'),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000)),
        ]);
        results.push({ alias: db.db_alias, ok: true, detail: 'Connected' });
      } catch (err: unknown) {
        results.push({ alias: db.db_alias, ok: false, detail: errorText(err) });
      } finally {
        await pool.end();
      }
    } catch (err: unknown) {
      results.push({ alias: db.db_alias, ok: false, detail: errorText(err) });
    }
  }

  const allOk = results.every((r) => r.ok);
  if (allOk) {
    return {
      name: 'Databases reachable',
      status: 'pass',
      detail: `${results.length} database(s) connected`,
    };
  }
  const failed = results.filter((r) => !r.ok);
  return {
    name: 'Databases reachable',
    status: 'fail',
    detail: `${failed.length} database(s) failed: ${failed.map((f) => f.alias).join(', ')}`,
  };
}

/**
 * Files whose contents are credential material and which must therefore be
 * readable only by their owner.
 */
export const SECURE_CONFIG_FILES = ['sw-agent.config.json', 'databases.config.json'] as const;

/** Mode every config file must have: read/write for the owner, nothing else. */
export const SECURE_CONFIG_MODE = 0o600;

export interface ConfigFileMode {
  name: string;
  path: string;
  mode: number | null;
  /** True when the path exists but is not a regular file (symlink, socket, …). */
  irregular: boolean;
  exists: boolean;
}

/**
 * Resolve the real config file paths and read their modes. Does not follow
 * symlinks for the permission read: a symlinked config is reported as
 * irregular rather than silently checking whatever it points at.
 */
export function inspectConfigFileModes(swAgentDir: string): ConfigFileMode[] {
  return SECURE_CONFIG_FILES.map((name) => {
    const p = path.join(swAgentDir, name);
    const base = { name, path: p };
    let st: fs.Stats;
    try {
      st = fs.lstatSync(p);
    } catch {
      return { ...base, mode: null, irregular: false, exists: false };
    }
    if (st.isSymbolicLink() || !st.isFile()) {
      return { ...base, mode: st.mode & 0o777, irregular: true, exists: true };
    }
    return { ...base, mode: st.mode & 0o777, irregular: false, exists: true };
  });
}

export function formatMode(mode: number): string {
  return '0o' + mode.toString(8);
}

/**
 * Check that the config files are owner-only (0o600).
 *
 * `databases.config.json` holds encrypted database passwords and
 * `sw-agent.config.json` holds the agent token that authenticates this agent to
 * the cloud. A group- or world-readable copy of either is a credential
 * disclosure to every other local user, so a 0o644 config FAILS here rather
 * than producing a warning. Missing files are reported as a warning: their
 * absence is covered by the config-validity checks.
 */
export async function checkConfigFilePermissions(ctx: DoctorContext): Promise<DoctorCheck> {
  const name = 'Config file permissions';
  if (ctx.platform === 'win32') {
    return { name, status: 'warn', detail: 'Skipped (POSIX modes do not apply on Windows)' };
  }

  const inspected = inspectConfigFileModes(ctx.swAgentDir);
  const present = inspected.filter((f) => f.exists);
  if (present.length === 0) {
    return { name, status: 'warn', detail: 'No config files found to check' };
  }

  const irregular = present.filter((f) => f.irregular);
  const loose = present.filter((f) => !f.irregular && f.mode !== SECURE_CONFIG_MODE);

  if (irregular.length > 0 || loose.length > 0) {
    const problems: string[] = [];
    for (const f of irregular) {
      problems.push(`${f.name} is not a regular file (symlink or special file)`);
    }
    for (const f of loose) {
      problems.push(
        `${f.name} is ${formatMode(f.mode as number)}, expected ${formatMode(SECURE_CONFIG_MODE)}`,
      );
    }
    return {
      name,
      status: 'fail',
      detail: `${problems.join('; ')}. Other local users can read credential material. Run 'sw-agent doctor --fix'.`,
    };
  }

  const modes = present.map((f) => `${f.name} ${formatMode(f.mode as number)}`).join(', ');
  return { name, status: 'pass', detail: modes };
}

export async function checkAuditDirWritable(ctx: DoctorContext): Promise<DoctorCheck> {
  const auditDir = path.join(ctx.swAgentDir, 'audit');
  const probe = await probeAuditDir(auditDir);
  const mode = formatMode(probe.dirMode);
  if (!probe.ok) {
    return {
      name: `Audit directory writable (mode ${mode})`,
      status: 'fail',
      detail: probe.reason,
    };
  }
  return {
    name: `Audit directory writable (mode ${mode})`,
    status: 'pass',
    detail: probe.repaired ? 'repaired mode (was untraversable)' : 'append + fsync verified',
  };
}

/**
 * Verifies the existing audit log against its anchor. A log that does not
 * verify is reported as a failure, not a warning: an operator running `doctor`
 * is exactly the person who needs to be told.
 *
 * This is the one caller that reuses {@link verifyAuditDirCached}: an operator
 * running `doctor` repeatedly in the same shell re-verifies an unchanged log
 * over and over, and the archives are the bulk of it. A reused file is only
 * skipped when it is byte-identical to what was verified (dev/inode/size/mtime
 * *and* ctime, at nanosecond precision), when the entry was verified from the
 * chain state the walk is resuming into, when it was verified with the same
 * signing key, and — for the end of the log — when the tail record on disk is
 * still the record that was verified. The anchors are re-read from disk on
 * every call. The result always says how much it did *not* read, so a pass
 * backed by the cache can never look like a full re-read.
 */
export async function checkAuditChain(ctx: DoctorContext): Promise<DoctorCheck> {
  const auditDir = path.join(ctx.swAgentDir, 'audit');
  let hasLog = false;
  try {
    hasLog = fs
      .readdirSync(auditDir)
      .some((e) => e === 'audit.jsonl' || /^audit-\d+\.jsonl$/.test(e));
  } catch {
    hasLog = false;
  }
  if (!hasLog) {
    return {
      name: 'Audit log integrity',
      status: 'pass',
      detail: 'no log yet (nothing to verify)',
    };
  }

  try {
    const verification = await verifyAuditDirCached(auditDir, { keyDir: ctx.swAgentDir });
    if (verification.intact) {
      return {
        name: 'Audit log integrity',
        status: 'pass',
        detail:
          `${verification.events} record(s) verified against ` +
          `${verification.head_present ? 'head.json' : 'no anchor'}` +
          cacheNote(verification),
      };
    }
    return {
      name: 'Audit log integrity',
      status: 'fail',
      detail: `${verification.reason ?? 'failed'}: ${verification.detail ?? 'no detail'}`,
    };
  } catch (err: unknown) {
    return {
      name: 'Audit log integrity',
      status: 'fail',
      detail: err instanceof Error ? err.message : String(err),
    };
  }
}

/** Names the files a pass did not re-read. A cache hit is never silent. */
function cacheNote(verification: CachedVerifyResult): string {
  const reused = verification.cached_files.length;
  if (reused === 0) return '';
  const total = verification.files.length;
  const when = verification.cached_since ? ` since ${verification.cached_since}` : '';
  const reread = verification.verified_files.length;
  return ` (${reused}/${total} file(s) unchanged${when}, ${reread} re-read)`;
}

/**
 * Repairs an audit directory that exists with a mode that cannot be traversed.
 * `mkdir({ recursive: true })` is a no-op on an existing directory, so without
 * this the wrong mode is permanent and the audit log silently records nothing.
 */
export async function ensureAuditDirForDoctor(ctx: DoctorContext): Promise<DoctorCheck> {
  const auditDir = path.join(ctx.swAgentDir, 'audit');
  const before = await statMode(auditDir);
  await ensureAuditDir(auditDir);
  const after = await statMode(auditDir);
  const fixed = before !== null && after !== null && before !== after;
  return {
    name: 'Audit directory permissions',
    status: 'pass',
    detail: fixed
      ? `Repaired mode ${formatMode(before)} -> ${formatMode(after)}`
      : `Mode ${formatMode(after ?? AUDIT_DIR_MODE)}`,
  };
}

async function statMode(p: string): Promise<number | null> {
  try {
    const st = await fs.promises.stat(p);
    return st.mode & 0o777;
  } catch {
    return null;
  }
}

export async function checkDiskSpace(_ctx: DoctorContext): Promise<DoctorCheck> {
  return { name: 'Disk space', status: 'pass', detail: 'Skipped (platform check)' };
}

/* ------------------------------------------------------------------ */
/* C-02: the PostgreSQL login role                                     */
/* ------------------------------------------------------------------ */

/**
 * One `rolX = false` expectation, parsed out of
 * {@link RECOMMENDED_PG_ROLE}.required_attributes.
 *
 * The role policy is the single source of truth: the SQL and the expectations
 * are both derived from it, so a new required attribute is enforced the moment
 * it is documented rather than needing a second edit here.
 */
export interface PgRoleAttributeRule {
  attribute: string;
  expect: boolean;
}

const ATTRIBUTE_RULE_RE = /^(\w+)\s*=\s*(true|false)$/;

/** Attribute rules taken from the role policy, or the rules that could not be parsed. */
function pgRoleAttributeRules(): {
  rules: PgRoleAttributeRule[];
  unparsed: string[];
} {
  const rules: PgRoleAttributeRule[] = [];
  const unparsed: string[] = [];
  for (const entry of RECOMMENDED_PG_ROLE.required_attributes) {
    const m = ATTRIBUTE_RULE_RE.exec(entry.trim());
    if (!m) {
      unparsed.push(entry);
      continue;
    }
    rules.push({ attribute: m[1] as string, expect: m[2] === 'true' });
  }
  return { rules, unparsed };
}

/** The documented probe for `privilege`, e.g. TEMP on the database. */
function privilegeProbeSql(fragment: string): string | null {
  const query = RECOMMENDED_PG_ROLE.verification_queries.find((q) => q.sql.includes(fragment));
  return query ? query.sql.trim() : null;
}

/** The value the policy documents for a probe whose expectation is a bare value. */
function probeExpectedValue(fragment: string): string | null {
  const query = RECOMMENDED_PG_ROLE.verification_queries.find((q) => q.sql.includes(fragment));
  return query ? query.expect.trim().toLowerCase() : null;
}

/**
 * What the connected login role actually holds, as read from the server. Every
 * probe is nullable: an unanswered probe must never read as "acceptable".
 */
export interface PgRoleFacts {
  alias: string;
  role: string;
  /** `pg_roles` attribute name -> value, or null when the probe did not answer. */
  attributes: Record<string, boolean | null>;
  can_create_temp: boolean | null;
  can_create_in_public: boolean | null;
  /** Predefined roles the login role holds, directly or by inheritance. */
  forbidden_memberships: string[];
  default_transaction_read_only: string | null;
}

/**
 * Every way the connected role departs from {@link RECOMMENDED_PG_ROLE}, as
 * human-readable findings. An empty array means the role is acceptable.
 *
 * Pure and fail-closed: an unanswered probe is itself a finding, because a probe
 * that did not answer has not established anything.
 */
export function pgRoleFindings(facts: PgRoleFacts): string[] {
  const findings: string[] = [];
  const { rules, unparsed } = pgRoleAttributeRules();
  for (const entry of unparsed) {
    findings.push(`role policy rule "${entry}" is not verifiable`);
  }
  if (rules.length === 0) {
    findings.push('role policy declares no verifiable pg_roles attributes');
  }

  for (const rule of rules) {
    const value = facts.attributes[rule.attribute];
    if (value === null || value === undefined) {
      findings.push(`${rule.attribute} could not be read`);
    } else if (value !== rule.expect) {
      findings.push(`${rule.attribute}=${value} (expected ${rule.expect})`);
    }
  }

  const mustBeFalse: Array<[string, boolean | null]> = [
    ['TEMP on database', facts.can_create_temp],
    ['CREATE on schema public', facts.can_create_in_public],
  ];
  for (const [label, value] of mustBeFalse) {
    if (value === null) findings.push(`${label} could not be read`);
    else if (value) findings.push(`${label} is granted`);
  }

  if (facts.forbidden_memberships.length > 0) {
    findings.push(`member of ${facts.forbidden_memberships.join(', ')}`);
  }

  const expectedReadOnly = probeExpectedValue('default_transaction_read_only');
  const readOnly = facts.default_transaction_read_only;
  if (readOnly === null) {
    findings.push('default_transaction_read_only could not be read');
  } else if (expectedReadOnly !== null && readOnly !== expectedReadOnly) {
    findings.push(`default_transaction_read_only=${readOnly} (expected ${expectedReadOnly})`);
  }

  return findings;
}

/** The label the role check reports under. */
export const PG_ROLE_CHECK_NAME = `PostgreSQL role is least privilege (${RECOMMENDED_PG_ROLE.role_name})`;

/**
 * Reads the least-privilege facts for one database.
 *
 * Membership uses `pg_has_role(..., 'MEMBER')` rather than the join in the
 * policy's own query, which resolves inherited membership too: a grant through
 * an intermediate group is the same privilege and must not read as clean.
 */
async function readPgRoleFacts(
  pool: Pool,
  alias: string,
  attributeNames: readonly string[],
): Promise<PgRoleFacts> {
  const columnList = attributeNames.length > 0 ? attributeNames.join(', ') : 'true';
  const attrs = await pool.query<Record<string, unknown>>(
    `SELECT current_user AS role, ${columnList} FROM pg_roles WHERE rolname = current_user`,
  );
  const row = attrs.rows[0] as Record<string, unknown> | undefined;

  const attributes: Record<string, boolean | null> = {};
  for (const name of attributeNames) {
    const value = row ? row[name] : undefined;
    attributes[name] = typeof value === 'boolean' ? value : null;
  }

  const tempQuery = privilegeProbeSql('has_database_privilege');
  const temp = tempQuery ? await pool.query<Record<string, unknown>>(tempQuery) : undefined;
  const createQuery = privilegeProbeSql('has_schema_privilege');
  const create = createQuery ? await pool.query<Record<string, unknown>>(createQuery) : undefined;

  const memberships = await pool.query<{ name: string }>(
    `SELECT r.rolname AS name
       FROM unnest($1::text[]) AS wanted(name)
       JOIN pg_roles r ON r.rolname = wanted.name
      WHERE pg_has_role(current_user, r.rolname, 'MEMBER')`,
    [[...RECOMMENDED_PG_ROLE.forbidden_memberships]],
  );

  const readOnly = await pool.query<Record<string, unknown>>('SHOW default_transaction_read_only');

  const firstBoolean = (result?: { rows: Record<string, unknown>[] }): boolean | null => {
    const value = result?.rows[0] ? Object.values(result.rows[0])[0] : undefined;
    return typeof value === 'boolean' ? value : null;
  };
  const firstString = (result?: { rows: Record<string, unknown>[] }): string | null => {
    const value = result?.rows[0] ? Object.values(result.rows[0])[0] : undefined;
    return typeof value === 'string' ? value.trim().toLowerCase() : null;
  };

  const roleValue = row ? row['role'] : undefined;

  return {
    alias,
    role: typeof roleValue === 'string' ? roleValue : 'unknown',
    attributes,
    can_create_temp: firstBoolean(temp),
    can_create_in_public: firstBoolean(create),
    forbidden_memberships: memberships.rows.map((r) => r.name),
    default_transaction_read_only: firstString(readOnly),
  };
}

/**
 * Verifies the connected PostgreSQL login role against
 * {@link RECOMMENDED_PG_ROLE} (C-02).
 *
 * `read_only` constrains what the connector is willing to run; it cannot
 * constrain what the login role is allowed to do. A `rolsuper` or
 * `pg_read_server_files` role defeats every control above it, so the role is
 * the only boundary an operator cannot route around from the wire.
 *
 * A violation is a failure, not a warning: the operator running `doctor` is
 * exactly the person who needs to be told. A database that cannot be reached
 * cannot clear the role, so it is reported as a warning naming what was not
 * checked — never as a pass.
 */
export async function checkPgRoleLeastPrivilege(ctx: DoctorContext): Promise<DoctorCheck> {
  const name = PG_ROLE_CHECK_NAME;
  if (!ctx.databasesConfig || ctx.databasesConfig.databases.length === 0) {
    return {
      name,
      status: 'warn',
      detail: 'Skipped: no databases configured, so there is no role to inspect',
    };
  }

  const { rules, unparsed } = pgRoleAttributeRules();
  if (unparsed.length > 0) {
    return {
      name,
      status: 'fail',
      detail: `Role policy rule(s) not verifiable: ${unparsed.join(', ')}`,
    };
  }
  if (privilegeProbeSql('has_database_privilege') === null) {
    return {
      name,
      status: 'fail',
      detail: 'Role policy no longer documents the TEMP privilege probe',
    };
  }
  if (privilegeProbeSql('has_schema_privilege') === null) {
    return {
      name,
      status: 'fail',
      detail: 'Role policy no longer documents the CREATE-on-public probe',
    };
  }
  const attributeNames = rules.map((r) => r.attribute);

  const findings: string[] = [];
  const unchecked: string[] = [];
  const checkedRoles: string[] = [];

  for (const db of ctx.databasesConfig.databases) {
    const alias = db.db_alias;
    const password =
      db.password_stored || (db.password_env ? process.env[db.password_env] : undefined);
    if (!password) {
      unchecked.push(`${alias} (no password configured)`);
      continue;
    }

    const poolConfig: PoolConfig = {
      host: db.host,
      port: db.port,
      database: db.database,
      user: db.user,
      password,
      connectionTimeoutMillis: 5000,
    };
    try {
      poolConfig.ssl = buildSslConfig(db.ssl_mode, db.ssl_root_cert, db.host);
    } catch (err: unknown) {
      unchecked.push(`${alias} (${errorText(err)})`);
      continue;
    }

    const pool = new Pool(poolConfig);
    try {
      await Promise.race([
        pool.query('SELECT 1'),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000)),
      ]);
      const facts = await readPgRoleFacts(pool, alias, attributeNames);
      checkedRoles.push(`${alias}=${facts.role}`);
      for (const finding of pgRoleFindings(facts)) {
        findings.push(`${alias} (${facts.role}): ${finding}`);
      }
    } catch (err: unknown) {
      unchecked.push(`${alias} (${errorText(err)})`);
    } finally {
      await pool.end();
    }
  }

  if (findings.length > 0) {
    const suffix =
      unchecked.length > 0
        ? ` Not checked: ${unchecked.join(', ')}.`
        : " Apply the role policy's bootstrap, revokes and grants statements once per database.";
    return { name, status: 'fail', detail: findings.join('; ') + suffix };
  }
  if (checkedRoles.length === 0) {
    return {
      name,
      status: 'warn',
      detail: `Skipped: no database could be reached to inspect the role (${unchecked.join(', ') || 'no candidates'})`,
    };
  }
  const suffix = unchecked.length > 0 ? ` Not checked: ${unchecked.join(', ')}.` : '';
  return {
    name,
    status: 'pass',
    detail: `${checkedRoles.join(', ')}: no superuser, no object creation, no server-file role, read-only sessions${suffix}`,
  };
}

export async function checkNodeVersion(ctx: DoctorContext): Promise<DoctorCheck> {
  const versionMatch = ctx.nodeVersion.match(/^v?(\d+)/);
  if (!versionMatch) {
    return { name: 'Node version', status: 'fail', detail: `Unknown version: ${ctx.nodeVersion}` };
  }
  const major = parseInt(versionMatch[1], 10);
  if (major >= 18) {
    return { name: 'Node version', status: 'pass', detail: ctx.nodeVersion };
  }
  return { name: 'Node version', status: 'fail', detail: `${ctx.nodeVersion} (need >= 18.0.0)` };
}

export async function checkPidFile(ctx: DoctorContext): Promise<DoctorCheck> {
  const fs_ = await import('fs/promises');
  const pidPath = `${ctx.swAgentDir}/sw-agent.pid`;
  try {
    const content = await fs_.readFile(pidPath, 'utf8');
    const pidInfo = JSON.parse(content);
    if (isProcessAlive(pidInfo.pid)) {
      return { name: 'PID file', status: 'pass', detail: `Agent running (pid ${pidInfo.pid})` };
    }
    return {
      name: 'PID file',
      status: 'warn',
      detail: `Stale PID file (process ${pidInfo.pid} is dead)`,
    };
  } catch {
    return { name: 'PID file', status: 'pass', detail: 'No PID file (agent not running)' };
  }
}

export async function runAllChecks(ctx: DoctorContext): Promise<DoctorCheck[]> {
  return [
    await checkSwAgentDirExists(ctx),
    await checkMachineConfigValid(ctx),
    await checkTokenFormat(ctx),
    await checkDatabasesConfigValid(ctx),
    await checkConfigFilePermissions(ctx),
    await checkDatabasesReachable(ctx),
    await checkPgRoleLeastPrivilege(ctx),
    await checkAuditDirWritable(ctx),
    await checkAuditChain(ctx),
    await checkDiskSpace(ctx),
    await checkNodeVersion(ctx),
    await checkPidFile(ctx),
  ];
}
