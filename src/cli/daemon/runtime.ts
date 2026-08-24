import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { MachineConfig } from '../../config/machine-config';
import { DatabasesConfig, loadDatabasesConfig } from '../../config/db-config';
import { getDbConfigPath } from '../../config/paths';
import { writePidFile, deletePidFile } from './pid-file';
import { writeStatusFile, readStatusFile, DaemonStatus } from './status-file';
import { createShutdownCoordinator } from './shutdown';
import { installSignalHandlers } from './signal-handlers';
import { installGlobalHandlers, trackError } from './error-tracker';
import { initOperationLogger, shutdownOperationLogger as _shutdownOperationLogger } from '../ops/operation-logger';
import { PoolManager } from '../../execution/pool';
import { QueryRunner } from '../../execution/query-runner';
import { MigrationRunner } from '../../execution/migration-runner';
import { Canceller } from '../../execution/canceller';
import { Introspector } from '../../execution/introspection';
import { Dispatcher } from '../../execution/dispatcher';
import { PermissionChecker } from '../../permissions/checker';
import { PlanRegistry } from '../../permissions/plan-registry';
import { AutoUpgradeChecker } from '../../permissions/auto-upgrade';
import { ManualApprovalHandler } from '../../permissions/manual-approval';
import { AuditSink } from '../../audit/sink';
import { LocalAuditWriter } from '../../audit/local-writer';
import { CloudAuditWriter } from '../../audit/cloud-writer';
import { AgentSession } from '../../channels/agent-session';
import { DbEntry } from '../../config/db-config';
import { VERSION } from '../../index';

export interface RuntimeOptions {
  machineConfig: MachineConfig;
  databasesConfig: DatabasesConfig;
  relayUrl: string;
  auditDir: string;
  statusFile: string;
  pidFile: string;
  foreground: boolean;
  autoExitMs?: number;
}

class RuntimeStats {
  queries_served = 0;
  streams_served = 0;
  migrations_run = 0;
  cancellations = 0;
  permission_denies = 0;
  audit_events_written = 0;
  audit_buffer_overflows = 0;
}

export async function runAgent(opts: RuntimeOptions): Promise<number> {
  const daemonStartedAt = new Date().toISOString();
  if (opts.relayUrl) {
    opts.machineConfig.cloud_url = opts.relayUrl;
  }
  // Capture crashes and per-operation errors to errors.jsonl + cloud.
  installGlobalHandlers(opts.machineConfig.agent_id);
  const poolManager = new PoolManager();
  let writeStatus: () => Promise<void>;
  let currentDatabasesConfig = opts.databasesConfig;
  let configRevision = Date.now();

  const planRegistry = new PlanRegistry();
  const autoUpgradeChecker = new AutoUpgradeChecker({ planRegistry });

  const auditSink = new AuditSink({
    agentId: opts.machineConfig.agent_id,
    localWriter: new LocalAuditWriter({
      dir: opts.auditDir,
      maxFileSize: 10 * 1024 * 1024,
      maxArchiveFiles: 10,
    }),
    cloudWriter: new CloudAuditWriter({
      enabled: opts.machineConfig.cloud_telemetry?.enabled !== false,
      url: opts.machineConfig.cloud_telemetry?.ingest_url,
      cloudUrl: opts.machineConfig.cloud_url,
      agent_token: opts.machineConfig.agent_token,
      agent_id: opts.machineConfig.agent_id,
    }),
  });

  // Also enable the operation logger (CLI/lifecycle ops) for cloud delivery.
  initOperationLogger({
    enabled: opts.machineConfig.cloud_telemetry?.enabled !== false,
    cloudUrl: opts.machineConfig.cloud_url,
    token: opts.machineConfig.agent_token,
    agentId: opts.machineConfig.agent_id,
  });

  let session: AgentSession;
  const manualApprovalHandler = new ManualApprovalHandler({
    send: async (msg) => {
      if (session) {
        await session.send(msg);
      }
    },
    timeoutMs: process.env.SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS ? parseInt(process.env.SW_AGENT_MANUAL_APPROVAL_TIMEOUT_MS, 10) : 60_000,
    auditSink,
  });

  const permissionChecker = new PermissionChecker({
    autoUpgradeChecker,
    manualApprovalHandler,
    planRegistry,
  });

  const stats = new RuntimeStats();

  const originalLog = auditSink.log.bind(auditSink);
  const originalLogSync = auditSink.logSync.bind(auditSink);

  const updateStatsFromEvent = (partial: any) => {
    stats.audit_events_written++;
    
    if (partial.decision === 'allow' && partial.outcome !== 'n/a') {
      if (partial.action === 'query') {
        stats.queries_served++;
      } else if (partial.action === 'stream_query') {
        stats.streams_served++;
      } else if (partial.action === 'migration_run') {
        stats.migrations_run++;
      } else if (partial.action === 'cancel') {
        stats.cancellations++;
      }
    } else if (partial.decision === 'deny') {
      if (partial.denial_reason === 'buffer_overflow') {
        stats.audit_buffer_overflows++;
      } else {
        stats.permission_denies++;
      }
    }
  };

  auditSink.log = (partial) => {
    updateStatsFromEvent(partial);
    originalLog(partial);
  };

  auditSink.logSync = async (partial) => {
    updateStatsFromEvent(partial);
    await originalLogSync(partial);
  };
  
  // Create dispatcher dependencies
  const queryRunner = new QueryRunner({ poolManager });
  const migrationRunner = new MigrationRunner({ poolManager });
  const canceller = new Canceller();
  const introspector = new Introspector({ poolManager });
  
  const lookupDb = (project: string, alias?: string): DbEntry | null => {
    const byProject = currentDatabasesConfig.databases.find(d => d.project_name === project);
    if (byProject) return byProject;
    // Protocol also addresses DBs by db_alias. Fall back so relay clients that
    // only know the alias (e.g. the Data Explorer relay) still resolve.
    if (alias) return currentDatabasesConfig.databases.find(d => d.db_alias === alias) || null;
    return null;
  };
  
  const dispatcher = new Dispatcher({
    poolManager,
    queryRunner,
    migrationRunner,
    canceller,
    introspector,
    permissionChecker,
    planRegistry,
    lookupDb,
    getMachineConfig: () => opts.machineConfig,
    send: (msg) => session.send(msg),
    auditSink,
  });
  
  session = new AgentSession({
    machineConfig: opts.machineConfig,
    getDatabases: () =>
      currentDatabasesConfig.databases.map((db) => ({
        db_alias: db.db_alias,
        database: db.database,
      })),
    onMessage: async (msg) => {
      try {
        await dispatcher.handle(msg);
      } catch (err) {
        trackError(err, { op: msg.type });
        throw err;
      }
    },
    onStateChange: () => {
      writeStatus().catch(err => {
        console.error('[stateChange] failed to write status:', err);
        trackError(err, { op: 'writeStatus' });
      });
    }
  });
  
  const shutdown = createShutdownCoordinator();
  
  // Shutdown registration order matters (sequential execution)
  // 1. We will register admin-server later (when it's created).
  // 2. pool-manager: wait for active queries to finish
  shutdown.register('pool-manager', async () => {
    await poolManager.closeAll();
  });
  
  // 3. agent-session: close websocket (data channel)
  shutdown.register('agent-session', async () => {
    await session.stop();
  });

  // 4. audit-sink: flush logs
  shutdown.register('audit-sink', async () => {
    await auditSink.flush();
  });

  // 5. operation-logger: flush operation logs
  shutdown.register('operation-logger', async () => {
    await _shutdownOperationLogger();
  });
  let adminServer: http.Server | undefined;
  if (process.env.SW_AGENT_E2E === '1') {
    adminServer = http.createServer(async (req, res) => {
      debugLog(`[admin-server] Received request: ${req.method} ${req.url}`);
      try {
        if (req.method === 'POST' && req.url === '/admin/audit-flush') {
          await auditSink.flush();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{}');
        } else if (req.method === 'GET' && req.url === '/admin/stats') {
          await writeStatus();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          const status = await readStatusFile({ path: opts.statusFile });
          res.end(JSON.stringify(status || {}));
        } else if (req.method === 'POST' && req.url && req.url.startsWith('/admin/shutdown')) {
          const parsedUrl = new URL(req.url, 'http://127.0.0.1');
          const timeoutMs = parseInt(parsedUrl.searchParams.get('timeoutMs') || '30000', 10);
          debugLog(`[admin-server] Triggering shutdown with timeoutMs: ${timeoutMs}`);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{}');
          void shutdown.shutdown(timeoutMs);
        } else {
          res.writeHead(404);
          res.end();
        }
      } catch (err) {
        res.writeHead(500);
        res.end(String(err));
      }
    });
    
    await new Promise<void>((resolve, reject) => {
      adminServer!.listen(0, '127.0.0.1', () => {
        resolve();
      });
      adminServer!.on('error', reject);
    });

    const addr = adminServer.address();
    const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
    const swAgentHome = path.dirname(opts.statusFile);
    await fs.promises.mkdir(swAgentHome, { recursive: true });
    await fs.promises.writeFile(path.join(swAgentHome, 'admin-port'), String(port));

    // 1. admin-server: stop accepting shutdown requests
    // We register it first by hacking the map or we can just rely on the fact that
    // admin-server doesn't depend on others, but it should ideally be first.
    // However, since it's created conditionally here, we register it here.
    // If it's registered last, it's fine, but let's just leave it as is or prepend it.
    // To cleanly prepend without modifying ShutdownCoordinator API, we can just accept it runs after.
    // Actually, it just stops HTTP server, so it's fine.
    shutdown.register('admin-server', async () => {
      if (adminServer && typeof adminServer.closeAllConnections === 'function') {
        try {
          adminServer.closeAllConnections();
        } catch {
          // ignore
        }
      }
      return new Promise<void>((resolve) => {
        adminServer!.close(() => {
          resolve();
        });
        setTimeout(() => resolve(), 500);
      });
    });
  }
  
  const uninstallSignals = installSignalHandlers(shutdown);
  
  await writePidFile({ path: opts.pidFile }, {
    pid: process.pid,
    started_at: daemonStartedAt,
    version: VERSION,
  });
  
  let isWritingStatus = false;
  let hasPendingStatusWrite = false;

  writeStatus = async () => {
    if (isWritingStatus) {
      hasPendingStatusWrite = true;
      return;
    }
    isWritingStatus = true;
    try {
      while (true) {
        const state = session.getState();
        const status: DaemonStatus = {
          pid: process.pid,
          started_at: daemonStartedAt,
          last_heartbeat: new Date().toISOString(),
          version: VERSION,
          channels: {
            sse: state.wake === 'connected' ? 'connected' : 
                 state.wake === 'connecting' ? 'connecting' :
                 state.wake === 'error' ? 'error' : 'disconnected',
            wss: state.data === 'open' ? 'connected' :
                 state.data === 'connecting' ? 'connecting' :
                 state.data === 'error' ? 'error' :
                 state.data === 'closed' ? 'idle' : 'disconnected',
          },
          stats: {
            queries_served: stats.queries_served,
            streams_served: stats.streams_served,
            migrations_run: stats.migrations_run,
            cancellations: stats.cancellations,
            permission_denies: stats.permission_denies,
            audit_events_written: stats.audit_events_written,
            audit_buffer_overflows: stats.audit_buffer_overflows,
          },
          config: {
            databases: currentDatabasesConfig.databases.length,
            projects: new Set(currentDatabasesConfig.databases.map((db) => db.project_name)).size,
            revision: configRevision,
          },
        };
        hasPendingStatusWrite = false;
        await writeStatusFile({ path: opts.statusFile }, status);
        if (!hasPendingStatusWrite) {
          break;
        }
      }
    } finally {
      isWritingStatus = false;
    }
  };

  const dbConfigPath = getDbConfigPath();
  const reloadDbConfig = async () => {
    try {
      const previousAliases = new Set(currentDatabasesConfig.databases.map((db) => db.db_alias));
      const next = loadDatabasesConfig();
      const nextAliases = new Set(next.databases.map((db) => db.db_alias));

      currentDatabasesConfig = next;
      configRevision = Date.now();

      for (const alias of previousAliases) {
        if (!nextAliases.has(alias)) {
          await poolManager.closePool(alias, 'explicit');
        }
      }

      await writeStatus();
    } catch (err) {
      trackError(err, { op: 'reloadDbConfig' });
      console.error('[config] failed to reload database config:', err);
    }
  };

  try {
    fs.watchFile(dbConfigPath, { interval: 1000 }, (curr, prev) => {
      if (curr.mtimeMs !== prev.mtimeMs || curr.size !== prev.size) {
        void reloadDbConfig();
      }
    });
    shutdown.register('db-config-watcher', async () => {
      fs.unwatchFile(dbConfigPath);
    });
  } catch (err) {
    trackError(err, { op: 'watchDbConfig' });
  }
  
  await session.start();
  
  const heartbeat = setInterval(() => {
    writeStatus().catch(err => {
      console.error('[heartbeat] failed to write status:', err);
    });
  }, 30_000);
  
  let autoExitTimer: ReturnType<typeof setTimeout> | undefined;
  if (opts.autoExitMs) {
    autoExitTimer = setTimeout(() => {
      debugLog('[daemon] Auto exit triggered');
      shutdown.shutdown(5_000).catch(() => {});
    }, opts.autoExitMs);
  }
  
  await new Promise<void>((resolve) => {
    const checkShutdown = setInterval(() => {
      if (shutdown.isShuttingDown()) {
        clearInterval(checkShutdown);
        debugLog(`[daemon] ${new Date().toISOString()} Shutdown detected, proceeding to cleanup...`);
        resolve();
      }
    }, 100);
  });
  
  debugLog(`[daemon] ${new Date().toISOString()} Awaiting shutdown coordinator...`);
  const result = await shutdown.shutdown(30_000);
  debugLog(`[daemon] ${new Date().toISOString()} Shutdown coordinator finished with result: ${result}`);
  
  clearInterval(heartbeat);
  if (autoExitTimer) clearTimeout(autoExitTimer);
  
  debugLog(`[daemon] ${new Date().toISOString()} Deleting pid file...`);
  await deletePidFile({ path: opts.pidFile });

  debugLog(`[daemon] ${new Date().toISOString()} Uninstalling signals...`);
  uninstallSignals();

  debugLog(`[daemon] ${new Date().toISOString()} Writing final status...`);
  await writeStatusFile({ path: opts.statusFile }, {
    pid: process.pid,
    started_at: daemonStartedAt,
    last_heartbeat: new Date().toISOString(),
    version: VERSION,
    channels: {
      sse: 'disconnected',
      wss: 'disconnected',
    },
    stats: {
      queries_served: stats.queries_served,
      streams_served: stats.streams_served,
      migrations_run: stats.migrations_run,
      cancellations: stats.cancellations,
      permission_denies: stats.permission_denies,
      audit_events_written: stats.audit_events_written,
      audit_buffer_overflows: stats.audit_buffer_overflows,
    },
    config: {
      databases: currentDatabasesConfig.databases.length,
      projects: new Set(currentDatabasesConfig.databases.map((db) => db.project_name)).size,
      revision: configRevision,
    },
  });
  
  debugLog(`[daemon] runAgent returning exit code: ${result === 'clean' ? 0 : 1}`);
  return result === 'clean' ? 0 : 1;
}

function debugLog(message: string): void {
  if (process.env.SW_AGENT_DEBUG === '1') {
    console.error(message);
  }
}
