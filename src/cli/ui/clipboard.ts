import { spawn } from 'child_process';
import * as process from 'process';

export interface ClipboardResult {
  copied: boolean;
  method: string | null;
}

export function copyToClipboard(text: string): ClipboardResult {
  const platform = process.platform;

  if (platform === 'win32') {
    try {
      const proc = spawn('clip', [], { stdio: ['pipe', 'inherit', 'inherit'] });
      proc.stdin.write(text);
      proc.stdin.end();
      return { copied: true, method: 'clip' };
    } catch {
      return { copied: false, method: null };
    }
  }

  if (platform === 'darwin') {
    try {
      const proc = spawn('pbcopy', [], { stdio: ['pipe', 'inherit', 'inherit'] });
      proc.stdin.write(text);
      proc.stdin.end();
      return { copied: true, method: 'pbcopy' };
    } catch {
      return { copied: false, method: null };
    }
  }

  // Linux: try xclip, then xsel
  for (const cmd of ['xclip -selection clipboard', 'xsel --clipboard --input']) {
    const [bin, ...args] = cmd.split(' ');
    try {
      const proc = spawn(bin, args, { stdio: ['pipe', 'inherit', 'inherit'] });
      proc.stdin.write(text);
      proc.stdin.end();
      return { copied: true, method: bin };
    } catch {
      // try next
    }
  }

  return { copied: false, method: null };
}
