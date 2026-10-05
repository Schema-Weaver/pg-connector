import * as path from 'path';
import * as fs from 'fs';
import { getSwAgentDir } from '../../config/paths';
import { AuditEvent } from '../../audit/types';
import { verifyHashChain } from '../../audit/chain';
import { getAuditFilesChronological } from '../../audit/files';
import { isReplMode } from '../prompt';
import { C, S, createSpinner } from '../ui';

function exit_(code: number): never {
  if (isReplMode()) {
    throw { __exitCode: code };
  }
  process.exit(code);
}

export interface AuditVerifyOptions {
  verbose?: boolean;
}

export interface VerifyResult {
  file: string;
  totalEvents: number;
  validEvents: number;
  hashErrors: number;
  parseErrors: number;
  chainBrokenIndex?: number;
}

export async function runAuditVerify(args: string[], opts: AuditVerifyOptions = {}): Promise<void> {
  const verbose = opts.verbose || args.includes('--verbose') || args.includes('-v');

  const swAgentDir = getSwAgentDir();
  const auditDir = path.join(swAgentDir, 'audit');

  const files = await getAuditFilesChronological(auditDir);

  console.log();
  console.log(C.bold(C.brand('  Audit Log Verification')));
  console.log();

  if (files.length === 0) {
    console.log(`  ${C.yellow(S.warning)} No audit log files found.`);
    console.log();
    exit_(0);
  }

  let totalEvents = 0;
  let totalHashErrors = 0;
  let totalParseErrors = 0;
  let allPassed = true;
  const spinner = createSpinner();
  spinner.start('Verifying audit log integrity...');

  await new Promise((resolve) => setTimeout(resolve, 300)); // visual feedback

  for (const file of files) {
    const result = await verifyFile(file, verbose);
    totalEvents += result.totalEvents;
    totalHashErrors += result.hashErrors;
    totalParseErrors += result.parseErrors;

    if (result.chainBrokenIndex !== undefined || result.hashErrors > 0) {
      allPassed = false;
    }
  }

  spinner.stop();

  console.log();
  console.log(`  ${C.bold('Results:')}`);
  console.log(`    Files:       ${C.white(String(files.length))}`);
  console.log(`    Events:      ${C.white(String(totalEvents))}`);
  if (totalHashErrors > 0) {
    console.log(`    Hash errors: ${C.red(String(totalHashErrors))}`);
  }
  if (totalParseErrors > 0) {
    console.log(`    Parse errors: ${C.yellow(String(totalParseErrors))}`);
  }
  console.log();

  if (allPassed && totalHashErrors === 0) {
    console.log(`  ${C.green(S.check)} ${C.brightGreen('Audit log integrity verified.')}`);
  } else {
    console.log(`  ${C.red(S.cross)} ${C.brightRed('Audit log integrity check failed.')}`);
  }
  console.log();

  exit_(allPassed && totalHashErrors === 0 ? 0 : 1);
}

export async function verifyFile(file: string, _verbose: boolean): Promise<VerifyResult> {
  const result: VerifyResult = {
    file: path.basename(file),
    totalEvents: 0,
    validEvents: 0,
    hashErrors: 0,
    parseErrors: 0,
  };

  let content: string;
  try {
    content = await fs.promises.readFile(file, 'utf8');
  } catch {
    return result;
  }

  const lines = content.split('\n').filter(Boolean);
  result.totalEvents = lines.length;

  const events: AuditEvent[] = [];

  for (let i = 0; i < lines.length; i++) {
    try {
      const event = JSON.parse(i === 0 ? stripBom(lines[i]) : lines[i]) as AuditEvent;
      events.push(event);
      result.validEvents++;
    } catch {
      result.parseErrors++;
    }
  }

  if (events.length > 0) {
    const verified = verifyHashChain(events);
    if (!verified.intact) {
      result.hashErrors++;
      result.chainBrokenIndex = verified.brokenAt;
    }
  }

  return result;
}

function stripBom(content: string): string {
  return content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
}
