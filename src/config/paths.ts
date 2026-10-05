import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

/**
 * Returns the agent home directory.
 * If SW_AGENT_HOME env var is set, uses that. Otherwise uses ~/.sw-agent.
 * Creates the directory recursive with 0o700 permissions on POSIX.
 */
export function getAgentHome(): string {
  const envHome = process.env.PG_CONNECTOR_HOME || process.env.SW_AGENT_HOME;
  const homeDir = envHome ? envHome : path.join(os.homedir(), '.sw-agent');
  if (!fs.existsSync(homeDir)) {
    fs.mkdirSync(homeDir, { recursive: true, mode: 0o700 });
  }
  return homeDir;
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
 * Returns the path to the audit log file audit.log.
 */
export function getAuditLogPath(): string {
  return path.join(getAgentHome(), 'audit.log');
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
