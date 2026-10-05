import { classifyStatement } from './statement-classifier';

export interface NonTxCheckResult {
  has_non_transactional: boolean;
  /** Indices of statements that can't run in a transaction. */
  non_tx_indices: number[];
  /** Human-readable summary. */
  summary: string;
}

/**
 * Detects if a list of migration statements contains any non-transactional DDL.
 * Used by migration-runner to decide whether to auto-switch strategy.
 */
export function detectNonTransactional(statements: string[]): NonTxCheckResult {
  const non_tx_indices: number[] = [];
  const summaries: string[] = [];

  statements.forEach((stmt, idx) => {
    const classification = classifyStatement(stmt);
    if (!classification.transactional) {
      non_tx_indices.push(idx);
      summaries.push(`Statement ${idx + 1}: ${classification.kind || classification.verb || 'unknown'} cannot run inside a transaction`);
    }
  });

  return {
    has_non_transactional: non_tx_indices.length > 0,
    non_tx_indices,
    summary: summaries.join(', ') || 'All statements are transactional',
  };
}
