export type {
  AuditAction,
  AuditDecision,
  AuditOutcome,
  AuditEvent,
  AuditFilter,
  AuditQueryResult,
} from './types';

export { computeHash, verifyChain } from './chain';
export { fingerprintStatement, previewStatement } from './redact';
export { LocalAuditWriter, type LocalWriterOptions } from './local-writer';
export { CloudAuditWriter, type CloudWriterConfig, type CloudWriterResult } from './cloud-writer';
export { AuditSink, type AuditSinkOptions } from './sink';
export {
  getAuditFilesChronological,
  getAuditFilesReverse,
  parseSince,
  eventMatchesFilter,
  readAuditEvents,
  type AuditLogFilter,
} from './files';
