import { Role } from '../protocol/envelope';
import { StatementClassification } from '../execution/types';
import type { FunctionEffectRecord, SideEffectKind } from '../execution/function-effects';
import type { IntrospectionDetail } from '../execution/introspection';
import { PermissionLevel } from './types';

/**
 * What a role can do, regardless of permission level.
 *
 * `approve_ddl` is separate from `ddl` on purpose: being able to run a
 * statement yourself and being able to authorise someone else's statement are
 * different powers, and only the second one is exercised by the manual
 * approval flow.
 */
export type RoleCapability =
  // Reduced schema snapshot: relation names, column names/types and the
  // primary-key/foreign-key shape. Sufficient to populate a data explorer or
  // to write a correct query. It deliberately omits every definition the
  // database holds: index bodies, check-clause expressions, column defaults,
  // trigger function source, owners, comments and partition bounds. Those
  // together are a near-complete dump of the schema and its business rules, and
  // a `viewer` has no need of them.
  | 'introspect'
  // The full snapshot, definitions included.
  //
  // Separate from `introspect` on purpose (audit M-30): granting both to all
  // four roles meant `viewer` and `data_reader` received the entire schema, which
  // is an exfiltration channel rather than a product capability.
  | 'introspect_full'
  | 'query_read' // a provably read-only statement
  | 'query_write' // INSERT, UPDATE, DELETE
  | 'ddl' // CREATE, ALTER, DROP, TRUNCATE, GRANT, and any statement that
  //        escaped the read sandbox (SELECT INTO, FOR UPDATE, a denylisted
  //        function, an executable block)
  | 'migration_run' // execute migration plans
  | 'approve_ddl' // resolve another user's pending write/DDL approval
  | 'cancel' // cancel in-flight requests
  | 'view_history' // see audit history (Part 7)
  | 'manage_team' // add/remove teammates (browser only, not agent concern)
  | 'manage_agent'; // link/unlink agent, rotate token

/**
 * Capability matrix.
 *
 * `viewer` and `data_reader` hold `introspect` but NOT `introspect_full`, so
 * they receive the reduced snapshot (see `IntrospectionDetail` in
 * execution/introspection.ts). Admin and developer hold both. This keeps the
 * data explorer usable for a read-only user while removing the schema dump.
 */
export const ROLE_CAPABILITIES: Record<Role, RoleCapability[]> = {
  admin: [
    'introspect',
    'introspect_full',
    'query_read',
    'query_write',
    'ddl',
    'migration_run',
    'approve_ddl',
    'cancel',
    'view_history',
    'manage_team',
    'manage_agent',
  ],
  developer: [
    'introspect',
    'introspect_full',
    'query_read',
    'query_write',
    'ddl',
    'migration_run',
    'approve_ddl',
    'cancel',
    'view_history',
  ],
  data_reader: ['introspect', 'query_read', 'view_history'],
  viewer: ['introspect', 'query_read', 'view_history'],
};

/** Introspection detail level implied by a role's capabilities. */
export function introspectionDetailFor(role: Role): IntrospectionDetail {
  return hasCapability(role, 'introspect_full') ? 'full' : 'structure';
}

/**
 * Ordering of roles by privilege, lowest first.
 *
 * Used to decide whether one principal may act on another's behalf (e.g. running
 * a migration plan another user registered). It is a *matrix* ordering, not a
 * real security hierarchy: the values come from this table and nothing else, so
 * an unrecognised role can never be treated as privileged.
 */
export const ROLE_PRIVILEGE_RANK: Record<Role, number> = {
  viewer: 0,
  data_reader: 1,
  developer: 2,
  admin: 3,
};

/**
 * Ordering of permission levels by permissiveness, lowest first.
 *
 * `read_only` is the strictest. A plan registered while a database was at a
 * permissive level must not be laundered through a stricter one: a plan that
 * needed no human at `full` may not execute unattended at `auto_upgrade`.
 */
export const PERMISSION_LEVEL_RANK: Record<PermissionLevel, number> = {
  read_only: 0,
  auto_upgrade: 1,
  manual: 2,
  full: 3,
};

/** Check if a role has a specific capability. */
export function hasCapability(role: Role, cap: RoleCapability): boolean {
  return ROLE_CAPABILITIES[role]?.includes(cap) || false;
}

/** True when `role` is at least as privileged as `minimum`. */
export function isAtLeastAsPrivileged(role: Role, minimum: Role): boolean {
  const r = ROLE_PRIVILEGE_RANK[role];
  const m = ROLE_PRIVILEGE_RANK[minimum];
  if (typeof r !== 'number' || typeof m !== 'number') return false;
  return r >= m;
}

/**
 * True when `role` is strictly more privileged than `minimum`.
 *
 * Acting on another principal's behalf requires a *higher* role than they held,
 * never merely an equal one: two developers are peers, and one peer's plan is
 * not the other's to run.
 */
export function isStrictlyMorePrivileged(role: Role, minimum: Role): boolean {
  const r = ROLE_PRIVILEGE_RANK[role];
  const m = ROLE_PRIVILEGE_RANK[minimum];
  if (typeof r !== 'number' || typeof m !== 'number') return false;
  return r > m;
}

/** True when `level` is at least as permissive as `minimum`. */
export function isAtLeastAsPermissive(level: PermissionLevel, minimum: PermissionLevel): boolean {
  const l = PERMISSION_LEVEL_RANK[level];
  const m = PERMISSION_LEVEL_RANK[minimum];
  if (typeof l !== 'number' || typeof m !== 'number') return false;
  return l >= m;
}

/**
 * Side effects that escape the transaction, and therefore escape
 * `default_transaction_read_only` as well.
 *
 * `NOTIFY` is delivered when the statement commits and is not rolled back;
 * advisory locks are released by session end, not by `ROLLBACK`; a sequence
 * advance and an XID allocation both persist (the XID is written to WAL).
 * `read_only` is a restriction on writes to relations, so none of these is
 * covered by it, and none of them is recorded by the audit chain unless the
 * classifier records it here.
 */
export const NON_TRANSACTIONAL_SIDE_EFFECTS: ReadonlySet<SideEffectKind> = new Set<SideEffectKind>(
  [
    'notified',
    'advisory_lock',
    'xid_allocated',
    'sequence',
    'session_mutation',
    'remote_io',
    'unknown_effect',
  ],
);

/**
 * The verdict records a classification must carry for every function it
 * references before that classification can be called a provable read.
 *
 * `IMMUTABLE` and resolved. Not `STABLE`: a STABLE function's result depends on
 * the snapshot and on the clock, and more importantly PostgreSQL makes no
 * promise about it beyond that, whereas IMMUTABLE is a promise the server
 * relies on for constant folding and index use. `VOLATILE`, `SECURITY
 * DEFINER` and unknown all fail, and so does a reference the catalogue could
 * not be asked about.
 */
function areAllFunctionsProvablyImmutable(records: unknown): boolean {
  if (!Array.isArray(records)) {
    // An absent record list means "nothing is known about the functions this
    // statement calls", which is not the same as "it calls none". Refuse.
    return false;
  }
  const list = records as FunctionEffectRecord[];
  return list.every((record) => record.effect === 'immutable' && record.resolved === true);
}

/**
 * True when the statement performs a side effect that a rollback does not undo.
 *
 * Consulted by `isProvableRead()` (any such effect makes the statement not a
 * read) and exported so callers that need to explain WHY a statement was
 * escalated do not have to re-derive the rule.
 */
export function hasNonTransactionalSideEffect(c: StatementClassification): boolean {
  const effects = c.side_effects;
  if (Array.isArray(effects)) {
    for (const kind of effects) {
      if (NON_TRANSACTIONAL_SIDE_EFFECTS.has(kind)) return true;
    }
  }
  const records = c.function_effects;
  if (Array.isArray(records)) {
    for (const record of records) {
      for (const kind of record.side_effects ?? []) {
        if (NON_TRANSACTIONAL_SIDE_EFFECTS.has(kind)) return true;
      }
    }
  }
  return false;
}

/** Read-escape violations, and the plain-English reason each one is refused. */
const STRUCTURAL_ESCAPES: ReadonlyMap<string, string> = new Map<string, string>([
  ['selects_into', 'it is a SELECT … INTO, which creates and populates a table'],
  ['row_locking', 'it takes row locks (FOR UPDATE / FOR SHARE), which block other transactions'],
  ['writable_cte', 'it contains a data-modifying CTE, which writes even inside a SELECT'],
  ['denied_function', 'it calls a function that is refused by name'],
  ['executable_block', 'it contains an executable block'],
  ['multiple_statements', 'it contains more than one statement, and all of them would run'],
  ['parse_error', 'PostgreSQL could not parse it'],
  ['parser_unavailable', 'the PostgreSQL parser was not loaded, so it could not be verified'],
]);

/**
 * Side effects that are real events, not a verdict about one.
 *
 * `unknown_effect` is deliberately absent: it is attached to every reference
 * that `pg_proc` does not prove `IMMUTABLE`, and reporting it as "a side effect
 * outside the transaction" tells the caller the statement notifies or takes an
 * advisory lock when the truth is only "we cannot prove it is harmless". That
 * is what this function exists to prevent.
 */
const CONCRETE_EFFECT_LABELS: Readonly<Partial<Record<SideEffectKind, string>>> = {
  notified: 'it emits a NOTIFY, which is delivered outside the transaction',
  advisory_lock: 'it takes an advisory lock, which survives a rollback',
  xid_allocated: 'it allocates an XID, which is written to WAL',
  sequence: 'it advances a sequence, which persists past a rollback',
  session_mutation: 'it mutates the session, which a rollback does not undo',
  remote_io: 'it performs remote I/O',
};

/** How each `pg_proc` verdict is described to the caller. */
const VERDICT_PHRASES: Readonly<Partial<Record<FunctionEffectRecord['effect'], string>>> = {
  stable: 'STABLE — its result depends on the snapshot or the clock',
  volatile: 'VOLATILE — it may do anything the calling role may do',
  security_definer: 'SECURITY DEFINER — it runs with the owner’s rights',
  unknown: 'no usable verdict',
};

/** `fn(), fn2()` …, capped so one statement cannot produce an unreadable line. */
function listReferences(names: readonly string[], cap = 3): string {
  const unique = [...new Set(names)].map((name) => `${name}()`);
  if (unique.length <= cap) return unique.join(', ');
  return `${unique.slice(0, cap).join(', ')} and ${String(unique.length - cap)} more`;
}

/**
 * The clause that says WHY {@link isProvableRead} returned false, in words a
 * caller can act on.
 *
 * The permission layer refuses first and explains second, and the explanation
 * used to assert that a refused statement "calls a function with a side effect
 * outside the transaction (a notification, an advisory lock, …)" whenever any
 * function was involved. For `SELECT extract(year FROM started_at)` that is
 * simply false: `extract` does not notify, lock or advance anything, it is
 * merely not proved `IMMUTABLE`. An automated caller reading a wrong reason
 * adapts to the wrong thing, so this names the actual `pg_proc` verdict, the
 * actual side-effect family, or the structural reason — whichever is the real
 * cause, in that order of specificity.
 *
 * @returns A lowercase clause with no trailing full stop, suitable for
 *   splicing into `Read-only mode: <clause>.`
 */
export function explainWhyNotAProvableRead(c: StatementClassification): string {
  const violations = c.read_violations ?? [];
  const records = c.function_effects ?? [];

  // A SELECT that was escalated to `write` still carries the reason in
  // `read_violations`; its `type` is the escalation, not the cause, and naming
  // it first produced "it is a 'write' statement (SELECT)" — a contradiction
  // that tells an automated caller nothing. Structural escapes come first
  // because they are unambiguous, then the concrete side-effect families, then
  // the `pg_proc` verdicts behind a `side_effect` violation.
  if (violations.length > 0) {
    // The concrete effect is the better answer when there is one: `pg_notify`
    // is on the deny-list BECAUSE it notifies, and "refused by name" tells a
    // caller nothing it can act on. `denied_function` is dropped in that case;
    // the other escapes are structural and stand on their own.
    const concrete = concreteEffects(c, records);
    const structural = [
      ...new Set(
        violations
          .filter((violation) => violation !== 'denied_function' || concrete.length === 0)
          .map((violation) => STRUCTURAL_ESCAPES.get(violation))
          .filter(isString),
      ),
    ];
    const parts = [...concrete, ...structural];
    if (parts.length > 0) return parts.join('; and ');

    const unresolved = records.filter((record) => !record.resolved);
    if (unresolved.length > 0) {
      return `pg_proc has no verdict for ${listReferences(unresolved.map((r) => r.name))}, so the call cannot be proved harmless`;
    }

    const unproven = records.filter((record) => record.resolved && record.effect !== 'immutable');
    if (unproven.length > 0) return verdictClause(unproven);

    return 'it is not provably free of side effects';
  }

  // No violations, so the statement was never a read: INSERT, UPDATE, DDL …
  if (c.type !== 'read') {
    const what = c.verb || c.kind || c.type;
    return `it is a '${c.type}' statement (${what}), not a read`;
  }

  const concrete = concreteEffects(c, records);
  if (concrete.length > 0) return concrete.join('; and ');
  if (records.length > 0) return verdictClause(records);

  return 'it is not provably free of side effects';
}

function isString(value: string | undefined): value is string {
  return value !== undefined;
}

/** The concrete side-effect families present, as distinct clauses. */
function concreteEffects(
  c: StatementClassification,
  records: readonly FunctionEffectRecord[],
): string[] {
  const clauses = new Set<string>();
  for (const kind of c.side_effects ?? []) {
    const label = CONCRETE_EFFECT_LABELS[kind];
    if (label) clauses.add(label);
  }
  for (const record of records) {
    for (const kind of record.side_effects ?? []) {
      const label = CONCRETE_EFFECT_LABELS[kind];
      if (label) clauses.add(label);
    }
  }
  return [...clauses];
}

/** `it calls a(), which pg_proc reports as STABLE — …`, grouped by verdict. */
function verdictClause(records: readonly FunctionEffectRecord[]): string {
  const byEffect = new Map<FunctionEffectRecord['effect'], string[]>();
  for (const record of records) {
    if (!record.resolved || record.effect === 'immutable') continue;
    const names = byEffect.get(record.effect) ?? [];
    names.push(record.name);
    byEffect.set(record.effect, names);
  }
  const phrases: string[] = [];
  for (const [effect, names] of byEffect) {
    const phrase = VERDICT_PHRASES[effect] ?? 'no usable verdict';
    phrases.push(`it calls ${listReferences(names)}, which pg_proc reports as ${phrase}`);
  }
  if (phrases.length > 0) return phrases.join('; and ');
  return 'it calls a function pg_proc does not prove IMMUTABLE';
}

/**
 * True only for a statement that is provably side-effect free: one statement,
 * parsed by PostgreSQL's own grammar, classified as a read, with no read
 * violations, no recorded side effect, and every function it calls proved
 * `IMMUTABLE` and not `SECURITY DEFINER` by `pg_proc`.
 *
 * This is the single definition of "a read" used by the permission layer. A
 * classification that does not satisfy every clause is treated as a write.
 *
 * The function clause is what closes the transitive hole: an
 * operator-written `SECURITY DEFINER` wrapper around `pg_read_file`, or any
 * VOLATILE function that INSERTs, parses as a `SELECT` and is on no deny-list,
 * but `pg_proc` reports it as unsafe — and a function reference with no
 * catalogue verdict at all is refused too, which is why a caller that cannot
 * reach a database must expect every statement that calls a function to be
 * escalated here.
 */
export function isProvableRead(c: StatementClassification): boolean {
  if (c.type !== 'read') return false;
  if (!c.parse_ok) return false;
  if (c.statement_count !== 1) return false;
  if (c.read_violations.length > 0) return false;
  if (hasNonTransactionalSideEffect(c)) return false;
  return areAllFunctionsProvablyImmutable(c.function_effects);
}

/**
 * Violations that mean "this parsed as a read but it is not one".
 *
 * A statement carrying any of them is gated on `ddl` regardless of the verb it
 * was parsed as: `SELECT * INTO t FROM u` and `SELECT * FROM u FOR UPDATE`
 * change state exactly as a `CREATE TABLE` or a `GRANT` does,
 * `SELECT pg_terminate_backend(1)` is closer to a server-control command than
 * to a read, and `SELECT some_volatile_fn()` is a call the classifier could not
 * prove effect-free.
 */
const READ_ESCAPE_VIOLATIONS: ReadonlySet<string> = new Set([
  'selects_into',
  'row_locking',
  'writable_cte',
  'denied_function',
  'side_effect',
  'executable_block',
]);

/**
 * Map a statement classification to the capability required to run it.
 *
 * `query_read` is granted ONLY for a provable read. Because every role holds
 * `query_read`, this predicate is the entire role-layer defence for `SELECT`,
 * so it must never widen: anything the classifier could not prove is a read is
 * escalated to `ddl` here rather than trusted.
 */
export function capabilityForClassification(c: StatementClassification): RoleCapability | null {
  if (c.read_violations.some((v) => READ_ESCAPE_VIOLATIONS.has(v))) {
    return 'ddl';
  }
  switch (c.type) {
    case 'read':
      return isProvableRead(c) ? 'query_read' : 'ddl';
    case 'write':
      return 'query_write';
    case 'ddl':
      return 'ddl';
    case 'utility':
      return 'ddl'; // VACUUM, ANALYZE, SET, etc. → treat as DDL-level
    case 'unknown':
      return 'ddl'; // safe default: require DDL capability
    default:
      return null;
  }
}

/** Map a message type to the capability required. */
export function capabilityForMessageType(type: string): RoleCapability | null {
  switch (type) {
    case 'ping':
      return null; // no capability needed
    case 'introspect':
      return 'introspect';
    case 'query':
    case 'stream_query':
      return null; // depends on SQL classification, not message type
    case 'migration_run':
      return 'migration_run';
    case 'cancel':
      return 'cancel';
    default:
      return null;
  }
}

/**
 * Map an inbound `event` kind to the capability required to use it.
 *
 * `event` messages bypass the query pipeline, so the capability has to be
 * named here rather than inferred from a SQL statement.
 */
export function capabilityForEventKind(kind: string): RoleCapability | null {
  switch (kind) {
    case 'plan_register':
      return 'migration_run';
    case 'approval_response':
      return 'approve_ddl';
    default:
      return null;
  }
}

/**
 * Shape of the PostgreSQL login role this connector should be given.
 *
 * The agent's own controls are implemented in TypeScript and can have bugs, so
 * the database role is where the boundary that cannot be bypassed from the wire
 * is set. Two things the agent does about function calls are worth naming
 * precisely, because they are frequently described as one control:
 *
 *   - `pg_proc` function-effect analysis (execution/function-effects.ts) is the
 *     primary control: a statement is only a read when every function it calls
 *     is `IMMUTABLE` and not `SECURITY DEFINER`. It does not depend on the
 *     function's name, so it covers operator-written helpers.
 *   - The `DENIED_READ_FUNCTIONS` list in sql-parser.ts is defence in depth. It
 *     is incomplete by construction and is not a boundary.
 *
 * The revokes below are what a miss cannot get past: `read_only` on the
 * connection constrains WRITES only, so a function that reads a server file,
 * notifies a channel, or reaches another host is not covered by it, and only
 * the absence of EXECUTE is.
 *
 * `sw-agent doctor` reports these attributes for the connected role; the
 * statements below are what an operator should run once per deployment. Where a
 * role name is shown as a placeholder, substitute the real one.
 */
export const RECOMMENDED_PG_ROLE = {
  role_name: 'sw_agent',

  /**
   * Required `pg_roles` attributes. A role that satisfies all of these cannot
   * escalate to superuser, cannot create databases or roles, cannot replicate,
   * and cannot bypass row-level security.
   */
  required_attributes: [
    'rolsuper = false',
    'rolcreatedb = false',
    'rolcreaterole = false',
    'rolreplication = false',
    'rolbypassrls = false',
  ],

  /**
   * Predefined roles that must NOT be granted. Several of them exist only in
   * newer PostgreSQL releases; grant the ones the server actually has.
   */
  forbidden_memberships: [
    'pg_read_server_files', // read any file the server can read
    'pg_write_server_files',
    'pg_execute_server_program', // COPY … TO PROGRAM
    'pg_read_all_settings',
    'pg_read_all_stats',
    'pg_stat_scan_tables',
    'pg_monitor',
    'pg_read_all_data',
    'pg_write_all_data',
  ],

  /** Bootstrap. Idempotent; safe to re-run. */
  bootstrap: [
    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sw_agent') THEN CREATE ROLE sw_agent LOGIN; END IF; END $$;",
    'ALTER ROLE sw_agent NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;',
  ],

  /**
   * REVOKEs that matter. PostgreSQL grants a great deal to PUBLIC by default —
   * notably `CREATE` on schema `public` (pre-14) and `EXECUTE` on every
   * function — so the default state must be revoked explicitly rather than
   * assumed absent.
   *
   * WHY THE DEFAULT-PRIVILEGES ROW IS NOT OPTIONAL: every `REVOKE … ON ALL
   * FUNCTIONS` above is a ONE-SHOT SNAPSHOT of the functions that exist at the
   * moment it runs. A function created afterwards is granted to PUBLIC again
   * by the same default privileges that gave the current one away, so the
   * revocation silently decays to nothing on a database that receives DDL. The
   * `ALTER DEFAULT PRIVILEGES` row is what stops the decay; run it as the role
   * that owns the objects (or as a superuser, which covers every future object),
   * and re-run it after any role that creates functions is added.
   */
  revokes: [
    // The connector talks to exactly one database; drop everything else.
    'REVOKE ALL ON DATABASE <database> FROM PUBLIC;',
    'REVOKE ALL ON SCHEMA public FROM PUBLIC;',
    'REVOKE ALL ON SCHEMA public FROM sw_agent;',
    'REVOKE CREATE ON SCHEMA public FROM PUBLIC;',
    // Function execution is the  attack surface: any VOLATILE or SECURITY
    // DEFINER function reachable from a SELECT is arbitrary code execution.
    'REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;',
    'REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM sw_agent;',
    'REVOKE EXECUTE ON ALL PROCEDURES IN SCHEMA public FROM PUBLIC;',
    'REVOKE EXECUTE ON ALL PROCEDURES IN SCHEMA public FROM sw_agent;',
    // Stops the two REVOKEs above decaying: functions created LATER are not
    // granted to PUBLIC in the first place.
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON PROCEDURES FROM PUBLIC;',
    // No sequence access: nextval/setval mutate shared state.
    'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sw_agent;',
    // No large objects, no foreign tables, no type creation.
    'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sw_agent;',
    'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;',
  ],

  /** The only privileges the read-only posture needs. */
  grants: [
    'GRANT CONNECT ON DATABASE <database> TO sw_agent;',
    'GRANT USAGE ON SCHEMA public TO sw_agent;',
    'GRANT SELECT ON ALL TABLES IN SCHEMA public TO sw_agent;',
    // TEMP would let any statement create scratch tables in pg_temp.
    'REVOKE TEMP ON DATABASE <database> FROM sw_agent;',
  ],

  /**
   * Session hardening, applied to every connection the role opens. The agent
   * additionally sets `default_transaction_read_only` per connection for
   * `read_only` entries; pinning it on the role means the guarantee also holds
   * for an operator's own psql session and for any path the agent misses.
   */
  role_settings: [
    'ALTER ROLE sw_agent SET search_path = pg_catalog, public;',
    'ALTER ROLE sw_agent SET default_transaction_read_only = on;',
    'ALTER ROLE sw_agent SET statement_timeout = 30s;',
    'ALTER ROLE sw_agent SET idle_in_transaction_session_timeout = 60s;',
    'ALTER ROLE sw_agent SET log_statement = none;',
  ],

  /**
   * What `doctor` should check on the connected role. Each row is a query and
   * the value that means "acceptable"; anything else is reported to the
   * operator as a finding.
   */
  verification_queries: [
    {
      sql: `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
            FROM pg_roles WHERE rolname = current_user`,
      expect: 'six columns, every boolean false',
    },
    {
      sql: `SELECT has_database_privilege(current_user, current_database(), 'TEMP') AS can_create_temp`,
      expect: 'false',
    },
    {
      sql: `SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_in_public`,
      expect: 'false',
    },
    {
      sql: `SELECT count(*) > 0 AS has_table_access
            FROM pg_roles r
            JOIN pg_auth_members m ON m.roleid = r.oid
            WHERE r.rolname IN ('pg_read_server_files', 'pg_write_server_files',
                                'pg_execute_server_program', 'pg_monitor',
                                'pg_read_all_data', 'pg_write_all_data')`,
      expect: 'false',
    },
    {
      sql: 'SHOW default_transaction_read_only',
      expect: 'on',
    },
  ],
} as const;
