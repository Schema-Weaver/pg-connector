export const VERSION = '0.1.2';

// Config (from Part 2)
export * from './config/machine-config';
export * from './config/db-config';
export * from './config/paths';
export * from './config/token';
export * from './config/schema';

// Protocol (new in Part 3)
export { PROTOCOL_VERSION, DEFAULTS, LIMITS } from './protocol/constants';
export {
  AgentMessage,
  Role,
  MessageType,
  EventKind, 
  MigrationStatementStatus,
  createMessage,
} from './protocol/envelope';
export * from './protocol/messages';
export {
  ErrorCode,
  ErrorMetadata,
  ERROR_CATALOG,
  getErrorMetadata,
  isFatalError,
  isRetryableError,
  makeError,
} from './protocol/errors';
export {
  serialize,
  deserialize,
  serializeToBytes,
  deserializeFromBytes,
  ProtocolError,
} from './protocol/serialize';
export {
  validateEnvelope,
  validatePayload,
  validateMessage,
} from './protocol/validate';

// Channels (new in Part 4)
export { WakeChannel, WakeChannelOptions } from './channels/wake-channel';
export { DataChannel, DataChannelOptions } from './channels/data-channel';
export { AgentSession, AgentSessionOptions } from './channels/agent-session';
export { Backoff, sleep, withJitter } from './channels/reconnect';
export {
  WakeChannelState,
  DataChannelState,
  DataChannelCloseReason,
  WakeEvent,
  AgentSessionState,
  MessageHandler,
  StateChangeHandler,
} from './channels/types';

// Execution (new in Part 5)
export { PoolManager, PoolError } from './execution/pool';
export { QueryRunner, QueryTooLargeError, QueryCancelledError, QueryRunContext } from './execution/query-runner';
export { MigrationRunner, MigrationInProgressError, MigrationContext } from './execution/migration-runner';
export { Canceller } from './execution/canceller';
export { Introspector } from './execution/introspection';
export { Dispatcher, DispatcherOptions } from './execution/dispatcher';
export { classifyStatement } from './execution/statement-classifier';
export { detectNonTransactional } from './execution/non-tx-detector';
export * from './execution/types';

// Permissions (new in Part 6)
export { PermissionChecker, PermissionCheckerOptions } from './permissions/checker';
export { AutoUpgradeChecker, AutoUpgradeOptions } from './permissions/auto-upgrade';
export { ManualApprovalHandler, ManualApprovalOptions } from './permissions/manual-approval';
export { PlanRegistry, RegisteredPlan, PlanRegistryOptions } from './permissions/plan-registry';
export {
  ROLE_CAPABILITIES, RoleCapability, hasCapability,
  capabilityForClassification, capabilityForMessageType,
} from './permissions/role-policy';
export {
  ActionRequest, PermissionDecision, AutoUpgradeResult, ManualApprovalResult,
} from './permissions/types';

// Audit (Part 7)
export * from './audit';
