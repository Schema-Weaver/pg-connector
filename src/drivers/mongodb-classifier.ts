import type { StatementClassification } from '../execution/types';
import { parseMongoQuery } from './mongodb-query';

/**
 * Classify a MongoDB command from its JSON payload.
 *
 * Unlike SQL there is no grammar to interpret: the command names its own
 * method, and the method is the classification. `find`, `aggregate`, `count`
 * and `distinct` are reads; every other method is refused by
 * {@link parseMongoQuery} before a classification is produced.
 *
 * `function_effects` is always `[]`, never absent. `isProvableRead()` treats an
 * absent array as "unknown functions may be called" and refuses the statement;
 * MongoDB has no function-call surface, so an empty, present array is the
 * truthful verdict and is what makes a validated command a provable read.
 */
export async function classifyMongoStatement(json: string): Promise<StatementClassification> {
  const query = parseMongoQuery(json);
  const verb = query.method.toUpperCase();

  return {
    type: 'read',
    kind: `MONGO_${verb}`,
    transactional: true,
    verb,
    statement_count: 1,
    parse_ok: true,
    read_violations: [],
    function_effects: [],
    side_effects: [],
  };
}
