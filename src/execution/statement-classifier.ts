import { StatementClassification } from './types';

function stripComments(sql: string): string {
  let cleaned = sql;
  // Strip multi-line comments
  cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');
  // Strip single-line comments
  cleaned = cleaned.replace(/--.*$/gm, '');
  return cleaned.trim();
}

function getSignificantTokens(sql: string): string[] {
  const cleaned = stripComments(sql);
  return cleaned
    .split(/\s+/)
    .map(t => t.replace(/[^a-zA-Z0-9_]/g, '').toUpperCase())
    .filter(Boolean);
}

/**
 * Classify a SQL statement by parsing the first tokens.
 * This is NOT a full SQL parser — it's a fast keyword-based classifier.
 *
 * Rules:
 *  - Strip comments (-- and /* *\/)
 *  - Take first 2-3 significant tokens
 *  - Match against known patterns
 */
export function classifyStatement(sql: string): StatementClassification {
  const tokens = getSignificantTokens(sql);
  if (tokens.length === 0) {
    return { type: 'unknown', kind: 'UNKNOWN', transactional: true, verb: '' };
  }

  const verb = tokens[0];

  if (verb === 'EXPLAIN') {
    if (tokens[1] === 'ANALYZE') {
      return { type: 'write', kind: 'EXPLAIN ANALYZE', transactional: true, verb: 'EXPLAIN' };
    }
    return { type: 'read', kind: 'EXPLAIN', transactional: true, verb: 'EXPLAIN' };
  }

  if (['SELECT', 'WITH', 'VALUES', 'TABLE', 'SHOW'].includes(verb)) {
    if (verb === 'WITH') {
      const hasWrite = tokens.some(t => ['INSERT', 'UPDATE', 'DELETE', 'MERGE'].includes(t));
      if (hasWrite) {
        return { type: 'write', kind: 'INSERT/UPDATE/DELETE', transactional: true, verb };
      }
    }
    return { type: 'read', kind: 'SELECT', transactional: true, verb };
  }

  if (['INSERT', 'UPDATE', 'DELETE', 'MERGE'].includes(verb)) {
    return { type: 'write', kind: 'INSERT/UPDATE/DELETE', transactional: true, verb };
  }

  if (verb === 'CREATE' || verb === 'DROP' || verb === 'ALTER' || verb === 'TRUNCATE') {
    const kind = `${verb} ${tokens[1] || ''}`.trim();

    if (verb === 'CREATE' && tokens.slice(1, 4).includes('INDEX')) {
      const idxOfConcurrently = tokens.indexOf('CONCURRENTLY');
      if (idxOfConcurrently !== -1 && idxOfConcurrently < 6) {
        return { type: 'ddl', kind: 'CREATE INDEX CONCURRENTLY', transactional: false, verb };
      }
    }

    if (tokens[1] === 'DATABASE') {
      return { type: 'ddl', kind, transactional: false, verb };
    }

    if (tokens[1] === 'TABLESPACE') {
      return { type: 'ddl', kind, transactional: false, verb };
    }

    return { type: 'ddl', kind, transactional: true, verb };
  }

  if (verb === 'REINDEX') {
    return { type: 'ddl', kind: 'REINDEX', transactional: false, verb };
  }

  if (['VACUUM', 'ANALYZE', 'CLUSTER'].includes(verb)) {
    return { type: 'utility', kind: verb, transactional: false, verb };
  }

  if (['BEGIN', 'COMMIT', 'ROLLBACK', 'SAVEPOINT'].includes(verb)) {
    return { type: 'utility', kind: 'TX_CONTROL', transactional: true, verb };
  }

  if (['SET', 'RESET', 'DISCARD', 'LOAD'].includes(verb)) {
    return { type: 'utility', kind: 'SET', transactional: true, verb };
  }

  if (['GRANT', 'REVOKE'].includes(verb)) {
    return { type: 'ddl', kind: verb, transactional: true, verb };
  }

  return { type: 'unknown', kind: 'UNKNOWN', transactional: true, verb };
}

/** Quick check: is this statement transactional? */
export function isTransactional(sql: string): boolean {
  return classifyStatement(sql).transactional;
}

/** Quick check: is this a read-only statement? */
export function isReadOnly(sql: string): boolean {
  return classifyStatement(sql).type === 'read';
}

/** Extract verb (first significant keyword, uppercased). */
export function extractVerb(sql: string): string {
  const tokens = getSignificantTokens(sql);
  return tokens.length > 0 ? tokens[0] : '';
}
