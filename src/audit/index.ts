export type {
  AuditAction,
  AuditDecision,
  AuditOutcome,
  AuditActor,
  AuditRole,
  AuditPermissionLevel,
  AuditEvent,
  AuditHead,
  AuditFilter,
  AuditQueryResult,
  AuditWriterHealth,
  AuditSinkHealth,
} from './types';

export {
  computeHash,
  computeMac,
  computeEventMac,
  canonicalStringify,
  isHash64,
  loadAuditKey,
  tryLoadAuditKey,
  decodeKeyMaterial,
  deriveChainId,
  readHead,
  readHeadFloor,
  resolveAnchor,
  writeHead,
  writeHeadFloor,
  floorPathFor,
  headPathFor,
  makeHead,
  verifyChain,
  verifyChainAgainstHead,
  verifyHashChain,
  ChainVerifier,
  AuditKeyError,
  GENESIS_HASH,
  AUDIT_KEY_BYTES,
  AUDIT_KEY_ENV,
  AUDIT_KEY_FILENAME,
  AUDIT_HEAD_FILENAME,
  AUDIT_FLOOR_SUFFIX,
  type AnchorClaim,
  type AuditKey,
  type AuditKeySource,
  type ChainFailureReason,
  type ChainVerifyResult,
  type ChainVerifyOptions,
  type MacInput,
  type ResolvedAnchor,
  type WriteHeadOptions,
  type LoadAuditKeyOptions,
} from './chain';

export {
  fingerprintStatement,
  previewStatement,
  redactSqlLiterals,
  isUnredactable,
  UNREDACTABLE,
  PREVIEW_MAX_LENGTH,
} from './redact';

export {
  LocalAuditWriter,
  verifyAuditLog,
  verifyStream,
  ACTIVE_AUDIT_FILE,
  type LocalWriterOptions,
  type AppendOptions,
  type VerifyAuditLogOptions,
  type VerifyStreamOptions,
  type AuditLogVerification,
} from './local-writer';

export { CloudAuditWriter, type CloudWriterConfig, type CloudWriterResult } from './cloud-writer';

export { AuditSink, type AuditSinkOptions, type PendingEvent } from './sink';

export {
  UNRESOLVED_DB_ALIAS,
  UNRESOLVED_DB_IDENTITY,
  currentResolvedDbIdentity,
  resolvedIdentityOf,
  withResolvedDatabase,
  type ResolvedDbIdentity,
} from './context';

export {
  getAuditFilesChronological,
  getAuditFilesReverse,
  readAuditLogChronological,
  ensureAuditDir,
  probeAuditDir,
  repairAuditDirMode,
  AUDIT_DIR_MODE,
  AUDIT_FILE_MODE,
  parseSince,
  eventMatchesFilter,
  readAuditEvents,
  type AuditLogFilter,
  type AuditLogReadResult,
  type AuditDirProbe,
} from './files';
