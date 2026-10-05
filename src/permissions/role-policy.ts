import { Role } from '../protocol/envelope';
import { StatementClassification } from '../execution/types';

/** What a role can do, regardless of permission level. */
export type RoleCapability =
  | 'introspect' // schema snapshot
  | 'query_read' // SELECT, EXPLAIN, VALUES, etc.
  | 'query_write' // INSERT, UPDATE, DELETE
  | 'ddl' // CREATE, ALTER, DROP, TRUNCATE, GRANT
  | 'migration_run' // execute migration plans
  | 'cancel' // cancel in-flight requests
  | 'view_history' // see audit history (Part 7)
  | 'manage_team' // add/remove teammates (browser only, not agent concern)
  | 'manage_agent'; // link/unlink agent, rotate token

export const ROLE_CAPABILITIES: Record<Role, RoleCapability[]> = {
  admin: [
    'introspect',
    'query_read',
    'query_write',
    'ddl',
    'migration_run',
    'cancel',
    'view_history',
    'manage_team',
    'manage_agent',
  ],
  developer: [
    'introspect',
    'query_read',
    'query_write',
    'ddl',
    'migration_run',
    'cancel',
    'view_history',
  ],
  data_reader: ['introspect', 'query_read', 'view_history'],
  viewer: ['introspect', 'query_read', 'view_history'],
};

/** Check if a role has a specific capability. */
export function hasCapability(role: Role, cap: RoleCapability): boolean {
  return ROLE_CAPABILITIES[role]?.includes(cap) || false;
}

/** Map a statement classification to the capability required to run it. */
export function capabilityForClassification(
  c: StatementClassification,
): RoleCapability | null {
  switch (c.type) {
    case 'read':
      return 'query_read';
    case 'write':
      return 'query_write';
    case 'ddl':
      return 'ddl';
    case 'migration':
      return 'migration_run';
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
