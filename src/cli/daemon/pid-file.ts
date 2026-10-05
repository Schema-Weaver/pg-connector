import * as fs from 'fs';
import * as path from 'path';

export interface PidFile {
  pid: number;
  started_at: string;
  version: string;
}

export interface PidFileOptions {
  path: string;
}

export async function writePidFile(opts: PidFileOptions, info: PidFile): Promise<void> {
  const dir = path.dirname(opts.path);
  await fs.promises.mkdir(dir, { recursive: true, mode: 0o700 });
  
  const existing = await readPidFile(opts);
  if (existing && isProcessAlive(existing.pid)) {
    throw new Error(`Agent already running (pid ${existing.pid})`);
  }
  
  await fs.promises.writeFile(opts.path, JSON.stringify(info, null, 2), {
    mode: 0o600,
    encoding: 'utf8',
  });
}

export async function readPidFile(opts: PidFileOptions): Promise<PidFile | null> {
  try {
    const content = await fs.promises.readFile(opts.path, 'utf8');
    return JSON.parse(content) as PidFile;
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

export async function deletePidFile(opts: PidFileOptions): Promise<void> {
  try {
    await fs.promises.unlink(opts.path);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') {
      throw err;
    }
  }
}

export function isProcessAlive(pid: number): boolean {
  if (pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
