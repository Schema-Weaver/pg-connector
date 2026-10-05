import * as path from 'path';
import * as fs from 'fs';
import { getSwAgentDir } from '../../config/paths';
import { AuditEvent } from '../../audit/types';
import {
  AuditLogFilter,
  eventMatchesFilter,
  readAuditEvents,
} from '../../audit/files';
import { formatEventRow, formatTableHeader, renderLogTable } from '../logs/format';
import { startLogViewer } from '../logs/viewer';
import { isReplMode } from '../prompt';
import { C, S } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface LogsOptions {
  limit?: number;
  project?: string;
  user?: string;
  action?: string;
  decision?: string;
  outcome?: string;
  search?: string;
  since?: string;
  until?: string;
  order?: 'asc' | 'desc';
  follow?: boolean;
  json?: boolean;
  interactive?: boolean;
}

export async function runLogs(args: string[], opts: LogsOptions = {}): Promise<void> {
  if (args.includes('--help') || args.includes('-h')) {
    printLogsHelp();
    exit_(0);
  }

  const limitArg = findArg(args, '--limit', '-l');
  const limit = opts.limit ?? (limitArg ? parseInt(limitArg, 10) : 20);
  const project = opts.project ?? findArg(args, '--project', '-p');
  const user = opts.user ?? findArg(args, '--user', '-u');
  const action = opts.action ?? findArg(args, '--action', '-a');
  const decision = opts.decision ?? findArg(args, '--decision', '-d');
  const outcome = opts.outcome ?? findArg(args, '--outcome', '-o');
  const search = opts.search ?? findArg(args, '--search', '-q');
  const since = opts.since ?? findArg(args, '--since', '');
  const until = opts.until ?? findArg(args, '--until', '');

  const isAsc = args.includes('--asc');
  const order: 'asc' | 'desc' = opts.order ?? (isAsc ? 'asc' : 'desc');

  const follow = opts.follow || args.includes('--follow') || args.includes('-f');
  const json = opts.json || args.includes('--json') || args.includes('-j');
  const interactiveExplicit = opts.interactive || args.includes('--interactive') || args.includes('-i');
  const noInteractive = args.includes('--no-interactive');

  const swAgentDir = getSwAgentDir();
  const auditDir = path.join(swAgentDir, 'audit');

  // Interactive TUI mode condition:
  // - Explicit flag: -i / --interactive
  // - In REPL mode when no output format flags (-f, -j, --no-interactive) are passed
  //   and no dump flags are passed, or explicitly invoked with `logs`
  const shouldRunInteractive =
    !follow &&
    !json &&
    !noInteractive &&
    process.stdin.isTTY &&
    (interactiveExplicit || (isReplMode() && args.length === 0));

  if (shouldRunInteractive) {
    await startLogViewer({
      auditDir,
      initialFilter: {
        project,
        user,
        action,
        decision,
        outcome,
        search,
        since,
        until,
        order,
        limit: Math.max(limit, 100),
      },
    });
    exit_(0);
  }

  console.log();

  if (follow) {
    await followLogs(auditDir, {
      project,
      user,
      action,
      decision,
      outcome,
      search,
      json,
    });
  } else {
    await dumpLogs(auditDir, {
      limit,
      project,
      user,
      action,
      decision,
      outcome,
      search,
      since,
      until,
      order,
      json,
    });
  }

  exit_(0);
}

function findArg(args: string[], longFlag: string, shortFlag: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if ((longFlag && args[i] === longFlag) || (shortFlag && args[i] === shortFlag)) {
      return args[i + 1];
    }
    if (longFlag && args[i].startsWith(longFlag + '=')) {
      return args[i].slice(longFlag.length + 1);
    }
  }
  return undefined;
}

function printLogsHelp(): void {
  console.log();
  console.log(C.bold('  Audit Logs Command'));
  console.log();
  console.log(`  ${C.dim('Usage:')} sw-agent logs [options]`);
  console.log();
  console.log(C.brand('  Interactive Viewer:'));
  console.log(`    ${C.cyan('-i, --interactive')}         Open interactive TUI log viewer (default in REPL)`);
  console.log();
  console.log(C.brand('  Filters:'));
  console.log(`    ${C.cyan('-p, --project <name>')}      Filter by project`);
  console.log(`    ${C.cyan('-u, --user <id>')}           Filter by user ID`);
  console.log(`    ${C.cyan('-a, --action <action>')}     Filter by action (query, stream_query, migration_run, etc.)`);
  console.log(`    ${C.cyan('-d, --decision <dec>')}      Filter by decision (allow, deny, pending, approved, rejected)`);
  console.log(`    ${C.cyan('-o, --outcome <out>')}       Filter by outcome (success, error, cancelled)`);
  console.log(`    ${C.cyan('-q, --search <query>')}      Search statement preview, table names, errors, users`);
  console.log(`    ${C.cyan('--since <time>')}             Logs since duration/date (e.g. 15m, 1h, 24h, 7d, today, ISO)`);
  console.log(`    ${C.cyan('--until <time>')}             Logs until duration/date`);
  console.log();
  console.log(C.brand('  Display & Output:'));
  console.log(`    ${C.cyan('-l, --limit <n>')}           Number of logs to output (default: 20)`);
  console.log(`    ${C.cyan('--desc / --asc')}            Sort newest-first (default) or chronological`);
  console.log(`    ${C.cyan('-f, --follow')}              Stream live logs in real time`);
  console.log(`    ${C.cyan('-j, --json')}                Output raw JSONL`);
  console.log(`    ${C.cyan('--no-interactive')}          Force plain table dump (no TUI)`);
  console.log();
}

async function dumpLogs(
  auditDir: string,
  opts: {
    limit: number;
    project?: string;
    user?: string;
    action?: string;
    decision?: string;
    outcome?: string;
    search?: string;
    since?: string;
    until?: string;
    order: 'asc' | 'desc';
    json: boolean;
  }
): Promise<void> {
  const filter: AuditLogFilter = {
    limit: opts.limit,
    project: opts.project,
    user: opts.user,
    action: opts.action,
    decision: opts.decision,
    outcome: opts.outcome,
    search: opts.search,
    since: opts.since,
    until: opts.until,
    order: opts.order,
  };

  const events = await readAuditEvents(auditDir, filter);

  if (events.length === 0) {
    console.log(`  ${C.yellow(S.warning)} No logs found matching the filter.`);
    console.log();
    return;
  }

  if (opts.json) {
    for (const event of events) {
      console.log(JSON.stringify(event));
    }
  } else {
    const sortLabel = opts.order === 'asc' ? 'chronological' : 'newest first';
    console.log(C.bold(`  Audit Logs (${C.cyan(sortLabel)})`));
    console.log();
    console.log(renderLogTable(events));
    console.log();
    console.log(
      `  ${C.dim('Showing')} ${C.white(String(events.length))} ${C.dim('events.')} ` +
      `${C.dim('Use')} ${C.cyan('logs -i')} ${C.dim('for interactive viewer,')} ${C.cyan('logs --json')} ${C.dim('for full JSON.')}`
    );
  }
  console.log();
}

async function followLogs(
  auditDir: string,
  opts: {
    project?: string;
    user?: string;
    action?: string;
    decision?: string;
    outcome?: string;
    search?: string;
    json: boolean;
  }
): Promise<void> {
  const activeFile = path.join(auditDir, 'audit.jsonl');

  let fd: number | null = null;
  let tailSize = 0;
  let interval: ReturnType<typeof setInterval> | null = null;
  let isRunning = true;

  const cleanup = () => {
    isRunning = false;
    if (interval) {
      clearInterval(interval);
      interval = null;
    }
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
      fd = null;
    }
  };

  const onSigint = () => {
    cleanup();
    console.log();
    console.log(`  ${C.dim('Follow mode stopped.')}`);
  };
  process.on('SIGINT', onSigint);

  try {
    fd = fs.openSync(activeFile, 'r');
    const stat = fs.fstatSync(fd);
    tailSize = stat.size;
  } catch {
    console.log(`  ${C.yellow(S.warning)} Active audit log not found. Waiting for new entries...`);
  }

  console.log(`  ${C.cyan(S.link)} Following ${C.white('audit.jsonl')} (active log)...`);
  console.log(`  ${C.dim('Press Ctrl+C to stop.')}`);
  console.log();
  if (!opts.json) {
    console.log(formatTableHeader());
  }

  const filter: AuditLogFilter = {
    project: opts.project,
    user: opts.user,
    action: opts.action,
    decision: opts.decision,
    outcome: opts.outcome,
    search: opts.search,
  };
  const searchLower = opts.search?.toLowerCase();

  interval = setInterval(() => {
    if (!isRunning) return;

    // Check if active file was rotated or newly created
    try {
      if (fd === null) {
        if (fs.existsSync(activeFile)) {
          fd = fs.openSync(activeFile, 'r');
          const stat = fs.fstatSync(fd);
          tailSize = stat.size;
        }
        return;
      }

      const stat = fs.fstatSync(fd);
      const newSize = stat.size;

      // File was rotated / truncated
      if (newSize < tailSize) {
        tailSize = 0;
      }

      if (newSize > tailSize) {
        const readSize = newSize - tailSize;
        const readBuf = Buffer.alloc(readSize);
        fs.readSync(fd, readBuf, 0, readSize, tailSize);
        const lines = readBuf.toString('utf8').split('\n').filter(Boolean);

        for (const line of lines) {
          try {
            const event = JSON.parse(line) as AuditEvent;
            if (!eventMatchesFilter(event, filter, null, null, searchLower)) {
              continue;
            }

            if (opts.json) {
              console.log(JSON.stringify(event));
            } else {
              console.log(formatEventRow(event));
            }
          } catch {
            // ignore malformed lines
          }
        }
        tailSize = newSize;
      }
    } catch {
      // ignore transient fs errors
    }
  }, 1000);

  // Wait for SIGINT
  await new Promise<void>((resolve) => {
    const check = setInterval(() => {
      if (!isRunning) {
        clearInterval(check);
        process.off('SIGINT', onSigint);
        resolve();
      }
    }, 100);
  });

  cleanup();
}
