import * as fs from 'fs';
import * as path from 'path';
import { AuditEvent } from './types';

export interface LocalWriterOptions {
  dir: string;
  maxFileSize: number;
  maxArchiveFiles: number;
  fileMode?: number;
}

const DEFAULT_FILE_MODE = 0o600;
const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;
const DEFAULT_MAX_ARCHIVE_FILES = 10;

export class LocalAuditWriter {
  private readonly opts: Required<LocalWriterOptions>;
  private readonly activePath: string;
  private lastKnownSize: number | null = null;

  constructor(opts: LocalWriterOptions) {
    this.opts = {
      dir: opts.dir,
      maxFileSize: opts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
      maxArchiveFiles: opts.maxArchiveFiles ?? DEFAULT_MAX_ARCHIVE_FILES,
      fileMode: opts.fileMode ?? DEFAULT_FILE_MODE,
    };
    this.activePath = path.join(this.opts.dir, 'audit.jsonl');
  }

  async append(event: AuditEvent): Promise<void> {
    await fs.promises.mkdir(this.opts.dir, { recursive: true, mode: this.opts.fileMode });
    
    const line = JSON.stringify(event) + '\n';
    const lineBytes = Buffer.byteLength(line, 'utf8');
    
    const currentSize = await this.currentFileSize();
    if (currentSize + lineBytes > this.opts.maxFileSize && currentSize > 0) {
      await this.rotate();
      this.lastKnownSize = 0;
    }
    
    const fd = await fs.promises.open(this.activePath, 'a', this.opts.fileMode);
    try {
      await fd.appendFile(line);
      await fd.sync();
    } finally {
      await fd.close();
    }
    
    this.lastKnownSize = (this.lastKnownSize ?? 0) + lineBytes;
  }

  private async currentFileSize(): Promise<number> {
    if (this.lastKnownSize !== null) {
      try {
        const stat = await fs.promises.stat(this.activePath);
        return stat.size;
      } catch {
        return 0;
      }
    }
    
    try {
      const stat = await fs.promises.stat(this.activePath);
      return stat.size;
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        return 0;
      }
      throw err;
    }
  }

  private async rotate(): Promise<void> {
    for (let i = this.opts.maxArchiveFiles - 1; i >= 1; i--) {
      const from = path.join(this.opts.dir, `audit-${i}.jsonl`);
      const to = path.join(this.opts.dir, `audit-${i + 1}.jsonl`);
      try {
        await fs.promises.rename(from, to);
      } catch (err: unknown) {
        const code = (err as NodeJS.ErrnoException).code;
        if (code !== 'ENOENT') throw err;
      }
    }
    
    try {
      await fs.promises.rename(
        this.activePath,
        path.join(this.opts.dir, 'audit-1.jsonl'),
      );
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') throw err;
    }
    
    for (let i = this.opts.maxArchiveFiles + 1; i <= this.opts.maxArchiveFiles + 5; i++) {
      const p = path.join(this.opts.dir, `audit-${i}.jsonl`);
      // eslint-disable-next-line no-empty
      try {
        await fs.promises.unlink(p);
      } catch {
      }
    }
    
    const fd = await fs.promises.open(this.activePath, 'a', this.opts.fileMode);
    await fd.close();
  }

  async readAll(): Promise<AuditEvent[]> {
    const events: AuditEvent[] = [];
    
    const archivePattern = /^audit-(\d+)\.jsonl$/;
    const files: { path: string; index: number }[] = [];
    
    // eslint-disable-next-line no-empty
    try {
      const entries = await fs.promises.readdir(this.opts.dir);
      for (const entry of entries) {
        const match = entry.match(archivePattern);
        if (match) {
          files.push({ path: entry, index: parseInt(match[1], 10) });
        }
      }
    } catch {
    }
    
    files.sort((a, b) => b.index - a.index);
    
    for (const file of files) {
      const p = path.join(this.opts.dir, file.path);
      // eslint-disable-next-line no-empty
      try {
        const content = await fs.promises.readFile(p, 'utf8');
        const lines = content.split('\n').filter(line => line.trim().length > 0);
        for (const line of lines) {
          // eslint-disable-next-line no-empty
          try {
            events.push(JSON.parse(line) as AuditEvent);
          } catch {
          }
        }
      } catch {
      }
    }
    
    // eslint-disable-next-line no-empty
    try {
      const content = await fs.promises.readFile(this.activePath, 'utf8');
      const lines = content.split('\n').filter(line => line.trim().length > 0);
      for (const line of lines) {
        // eslint-disable-next-line no-empty
        try {
          events.push(JSON.parse(line) as AuditEvent);
        } catch {
        }
      }
    } catch {
    }
    
    return events;
  }
}
