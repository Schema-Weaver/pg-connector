import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

/**
 * The environment variables that relocate the agent home, in precedence order.
 * `AGENT_HOME` is deliberately absent: nothing reads it, and the startup banner
 * used to print it as if it did, which invited an operator to "move the token
 * store" by setting a variable that is silently ignored.
 */
export const AGENT_HOME_ENV_VARS = ['PG_CONNECTOR_HOME', 'SW_AGENT_HOME'] as const;

/**
 * Returns the agent home directory.
 * If PG_CONNECTOR_HOME or SW_AGENT_HOME is set, uses that. Otherwise uses
 * ~/.sw-agent.
 * Created with 0o700 on POSIX; a pre-existing directory is chmod'ed back to
 * 0o700 rather than trusted, since a 0o755 home exposes the token and the
 * database config inside it. mkdir is attempted and only EEXIST is ignored:
 * an existsSync check followed by mkdirSync is a race, and it skips the repair
 * for a directory that already exists.
 */
export function getAgentHome(): string {
  const envHome = process.env.PG_CONNECTOR_HOME || process.env.SW_AGENT_HOME;
  const homeDir = envHome ? envHome : path.join(os.homedir(), '.sw-agent');
  try {
    fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });
  } catch (err) {
    if (!isErrnoCode(err, 'EEXIST')) throw err;
  }
  try {
    fs.chmodSync(homeDir, 0o700);
  } catch {
    // Not the owner, or a filesystem without POSIX modes: the caller still
    // gets the path, and every config write re-asserts 0o600 on the file.
  }
  return homeDir;
}

function isErrnoCode(err: unknown, code: string): boolean {
  return typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === code;
}

export function getSwAgentDir(): string {
  return getAgentHome();
}

/**
 * Returns the path to the machine config file sw-agent.config.json.
 */
export function getMachineConfigPath(): string {
  return path.join(getAgentHome(), 'sw-agent.config.json');
}

/**
 * Returns the path to the database config file databases.config.json.
 */
export function getDbConfigPath(): string {
  return path.join(getAgentHome(), 'databases.config.json');
}

/**
 * Returns the path to the machine-local credential key file that encrypts
 * database passwords at rest.
 *
 * Deliberately placed outside the agent home directory: a copy of the agent
 * home (backup, sync folder, snapshot, EDR upload) must never carry the key
 * that decrypts the credentials sitting next to it. The key file is created
 * with mode 0400 and is only ever readable by its owner.
 */
export function getCredentialKeyPath(): string {
  return path.join(os.homedir(), '.sw-agent-credential.key');
}

/**
 * Returns the path to the audit log directory audit/.
 */
export function getAuditDirPath(): string {
  return path.join(getAgentHome(), 'audit');
}

/**
 * Returns the path to the active audit log file, audit/audit.jsonl.
 * Archives (audit-1.jsonl …) live next to it; the sink rolls them.
 */
export function getAuditLogPath(): string {
  return path.join(getAuditDirPath(), 'audit.jsonl');
}

/**
 * Returns the path to the daemon PID file sw-agent.pid.
 */
export function getPidFilePath(): string {
  return path.join(getAgentHome(), 'sw-agent.pid');
}

/**
 * Returns the path to the daemon status file sw-agent.status.
 */
export function getStatusFilePath(): string {
  return path.join(getAgentHome(), 'sw-agent.status');
}

/**
 * Returns the path to the daemon diagnostic log file daemon.log.
 */
export function getDaemonLogPath(): string {
  return path.join(getAgentHome(), 'daemon.log');
}

/**
 * Returns the path to the active daemon error log errors.jsonl.
 * Archives (errors-1.jsonl …) live next to it; the error tracker rolls them.
 */
export function getErrorsPath(): string {
  return path.join(getAgentHome(), 'errors.jsonl');
}
