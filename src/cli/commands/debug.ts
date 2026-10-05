import * as path from 'path';
import * as os from 'os';
import * as dns from 'dns/promises';
import * as net from 'net';
import * as tls from 'tls';
import { URL } from 'url';
import { VERSION } from '../../index';
import { getAgentHome, getMachineConfigPath, getDbConfigPath, getAuditLogPath, getDaemonLogPath, getPidFilePath } from '../../config/paths';
import { machineConfigExists, loadMachineConfig } from '../../config/machine-config';
import { dbConfigExists, loadDbConfig } from '../../config/db-config';
import { readPidFile, isProcessAlive } from '../daemon/pid-file';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';
import { runDbTest } from './db-test';
import { verifyFile } from './audit-verify';
import { getAuditFilesChronological } from '../../audit/files';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export async function runDebug(args: string[] = []): Promise<void> {
  const verbose = args.includes('--verbose') || args.includes('-v');

  console.log();
  console.log(`  ${C.bold(C.brand('Schema Weaver Connector — Diagnostic Debugger'))}`);
  console.log(`  ${C.dim(`CLI v${VERSION} · Node ${process.version} · ${os.type()} ${os.release()} (${os.arch()})`)}`);
  console.log();

  // 1. Environment & Paths
  console.log(`  ${C.bold('1. Runtime Environment & Paths')}`);
  const home = getAgentHome();
  const machineConfigPath = getMachineConfigPath();
  const dbConfigPath = getDbConfigPath();
  const auditPath = getAuditLogPath();
  const daemonLogPath = getDaemonLogPath();
  const pidPath = getPidFilePath();

  console.log(`     Home Directory : ${C.white(home)}`);
  console.log(`     Machine Config : ${C.dim(machineConfigPath)} ${machineConfigExists() ? C.green(S.check) : C.red(S.cross)}`);
  console.log(`     DB Config      : ${C.dim(dbConfigPath)} ${dbConfigExists() ? C.green(S.check) : C.yellow(S.warning)}`);
  console.log(`     Audit Trail    : ${C.dim(auditPath)}`);
  console.log(`     Daemon Log     : ${C.dim(daemonLogPath)}`);

  // Daemon PID state
  const pidInfo = await readPidFile({ path: pidPath });
  const isAlive = pidInfo ? isProcessAlive(pidInfo.pid) : false;
  console.log(`     Daemon Process : ${pidInfo ? (isAlive ? `${C.green('RUNNING')} (pid ${pidInfo.pid})` : C.red('STALE PID')) : C.dim('STOPPED')}`);
  console.log();

  // 2. Network & Proxy Configuration
  console.log(`  ${C.bold('2. Network & Proxy Configuration')}`);
  const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy || null;
  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy || null;
  const noProxy = process.env.NO_PROXY || process.env.no_proxy || null;

  if (httpProxy || httpsProxy) {
    console.log(`     HTTP Proxy     : ${C.cyan(httpProxy || 'none')}`);
    console.log(`     HTTPS Proxy    : ${C.cyan(httpsProxy || 'none')}`);
    if (noProxy) console.log(`     No Proxy List  : ${C.dim(noProxy)}`);
  } else {
    console.log(`     Corporate Proxy: ${C.dim('Direct Outbound (no HTTP_PROXY set)')}`);
  }

  // Probe Relay
  if (machineConfigExists()) {
    const config = loadMachineConfig();
    const relay = config.cloud_url;
    console.log(`     Relay Endpoint : ${C.white(relay)}`);

    try {
      const parsed = new URL(relay);
      const host = parsed.hostname;
      const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80);

      // DNS lookup
      const dnsStart = Date.now();
      const addresses = await dns.lookup(host, { all: true });
      const dnsLatency = Date.now() - dnsStart;
      console.log(`     DNS Resolution : ${C.green(S.check)} ${addresses.map(a => a.address).join(', ')} (${C.cyan(`${dnsLatency}ms`)})`);

      // TCP Connect Probe
      const tcpStart = Date.now();
      await new Promise<void>((resolve, reject) => {
        const socket = net.createConnection({ host, port, timeout: 5000 }, () => {
          socket.end();
          resolve();
        });
        socket.on('error', reject);
        socket.on('timeout', () => {
          socket.destroy();
          reject(new Error('TCP connect timed out'));
        });
      });
      const tcpLatency = Date.now() - tcpStart;
      console.log(`     TCP Handshake  : ${C.green(S.check)} Port ${port} reachable (${C.cyan(`${tcpLatency}ms`)})`);

      // TLS Handshake Probe (if HTTPS/WSS)
      if (parsed.protocol === 'https:' || parsed.protocol === 'wss:') {
        const tlsStart = Date.now();
        await new Promise<void>((resolve, reject) => {
          const tlsSocket = tls.connect({ host, port, servername: host, timeout: 5000 }, () => {
            tlsSocket.end();
            resolve();
          });
          tlsSocket.on('error', reject);
          tlsSocket.on('timeout', () => {
            tlsSocket.destroy();
            reject(new Error('TLS handshake timed out'));
          });
        });
        const tlsLatency = Date.now() - tlsStart;
        console.log(`     TLS Handshake  : ${C.green(S.check)} TLS negotiation successful (${C.cyan(`${tlsLatency}ms`)})`);
      }
    } catch (err: any) {
      console.log(`     Relay Probe    : ${C.red(S.cross)} ${err.message}`);
    }
  } else {
    console.log(`     Relay Endpoint : ${C.dim('Not initialized (run pg-connector init)')}`);
  }
  console.log();

  // 3. Cryptographic Audit Log Integrity
  console.log(`  ${C.bold('3. Audit Log Integrity Check')}`);
  const auditDir = path.join(home, 'audit');
  try {
    const files = await getAuditFilesChronological(auditDir);
    if (files.length === 0) {
      console.log(`     Audit Trail    : ${C.dim('No audit log entries recorded yet.')}`);
    } else {
      let totalEvents = 0;
      let totalHashErrors = 0;
      for (const file of files) {
        const res = await verifyFile(file, verbose);
        totalEvents += res.totalEvents;
        totalHashErrors += res.hashErrors;
      }
      if (totalHashErrors === 0) {
        console.log(`     Audit Trail    : ${C.green(S.check)} ${C.white(String(totalEvents))} events across ${files.length} file(s) verified (0 hash errors)`);
      } else {
        console.log(`     Audit Trail    : ${C.yellow(S.warning)} ${totalEvents} events, ${C.red(`${totalHashErrors} hash error(s)`)} detected`);
      }
    }
  } catch {
    console.log(`     Audit Trail    : ${C.dim('No audit directory found.')}`);
  }
  console.log();

  // 4. Database Probes
  console.log(`  ${C.bold('4. Database Probes & Reachability')}`);
  if (dbConfigExists()) {
    const dbs = loadDbConfig();
    console.log(`     Configured DBs : ${C.white(String(dbs.length))}`);
    console.log();
    // Run db test in detailed mode
    await runDbTest(['--all', '--detailed']);
  } else {
    console.log(`     Configured DBs : ${C.dim('No databases configured. Run db add.')}`);
    console.log();
  }

  console.log(`  ${C.green(S.check)} Diagnostic inspection complete.`);
  console.log();
  exit_(0);
}
