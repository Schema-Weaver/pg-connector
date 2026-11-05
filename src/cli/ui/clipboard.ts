import { spawnSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as process from 'process';

export interface ClipboardResult {
  copied: boolean;
  method: string | null;
  error?: string | null;
}

export interface ClipboardCommand {
  bin: string;
  args: string[];
}

export interface ClipboardOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  spawnSync?: typeof spawnSync;
  spawn?: typeof spawn;
}

/**
 * Detects if the current Linux environment is headless (lacks a display server).
 * A GUI clipboard service requires either DISPLAY (X11) or WAYLAND_DISPLAY (Wayland).
 */
export function isHeadlessLinux(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (platform !== 'linux') {
    return false;
  }
  const hasDisplay = Boolean(env.DISPLAY && env.DISPLAY.trim() !== '');
  const hasWayland = Boolean(env.WAYLAND_DISPLAY && env.WAYLAND_DISPLAY.trim() !== '');
  return !hasDisplay && !hasWayland;
}

/**
 * Checks whether an executable command exists and is executable in PATH
 * before attempting to spawn it, preventing ENOENT errors.
 */
export function isCommandAvailable(
  command: string,
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (!command || typeof command !== 'string') {
    return false;
  }

  // If command includes a directory separator, resolve directly
  const hasSep =
    command.includes(path.sep) ||
    command.includes('/') ||
    (platform === 'win32' && command.includes('\\'));

  if (hasSep) {
    try {
      if (fs.existsSync(command)) {
        if (platform !== 'win32') {
          fs.accessSync(command, fs.constants.X_OK);
        }
        return true;
      }
    } catch {
      return false;
    }
    return false;
  }

  const rawPath = env.PATH ?? (platform === 'win32' ? env.Path : undefined) ?? '';
  if (!rawPath) {
    return false;
  }

  const delimiter = platform === 'win32' ? ';' : ':';
  const dirs = rawPath.split(delimiter).filter(Boolean);

  const extensions =
    platform === 'win32'
      ? (env.PATHEXT ? env.PATHEXT.split(';') : ['.exe', '.cmd', '.bat', '.com'])
      : [''];

  const checkExts =
    platform === 'win32' && path.extname(command)
      ? ['', ...extensions]
      : extensions;

  for (const dir of dirs) {
    for (const ext of checkExts) {
      const fullPath = path.join(dir, command + ext);
      try {
        if (fs.existsSync(fullPath)) {
          if (platform !== 'win32') {
            fs.accessSync(fullPath, fs.constants.X_OK);
          }
          return true;
        }
      } catch {
        // Continue searching
      }
    }
  }

  return false;
}

/**
 * Returns candidate clipboard utilities for the target platform and environment.
 * In headless Linux, returns an empty array to skip clipboard operations entirely.
 */
export function getClipboardCandidates(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): ClipboardCommand[] {
  if (platform === 'win32') {
    return [{ bin: 'clip', args: [] }];
  }

  if (platform === 'darwin') {
    return [{ bin: 'pbcopy', args: [] }];
  }

  // Headless Linux / EC2 has no display server or graphical clipboard daemon
  if (isHeadlessLinux(platform, env)) {
    return [];
  }

  // On Wayland, prioritize wl-copy; on X11, prioritize xclip
  if (env.WAYLAND_DISPLAY?.trim()) {
    return [
      { bin: 'wl-copy', args: [] },
      { bin: 'xclip', args: ['-selection', 'clipboard'] },
      { bin: 'xsel', args: ['--clipboard', '--input'] },
    ];
  }

  return [
    { bin: 'xclip', args: ['-selection', 'clipboard'] },
    { bin: 'wl-copy', args: [] },
    { bin: 'xsel', args: ['--clipboard', '--input'] },
  ];
}

/**
 * Returns true if a suitable clipboard utility is available in the current environment.
 */
export function isClipboardAvailable(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const candidates = getClipboardCandidates(platform, env);
  for (const candidate of candidates) {
    if (isCommandAvailable(candidate.bin, platform, env)) {
      return true;
    }
  }
  return false;
}

/**
 * Attempts to copy text to the system clipboard in a best-effort manner.
 * Never throws or terminates the process on failure.
 *
 * Handles:
 * - Missing executable (ENOENT)
 * - Process spawn / execution errors
 * - Non-zero exit codes
 * - Headless Linux / EC2 environments
 * - Timeouts
 */
export function copyToClipboard(
  text: string,
  options: ClipboardOptions = {},
): ClipboardResult {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const timeoutMs = options.timeoutMs ?? 3000;
  const runSpawnSync = options.spawnSync ?? spawnSync;

  if (typeof text !== 'string') {
    return { copied: false, method: null, error: 'Input text must be a string' };
  }

  // On headless Linux or when no clipboard candidate exists, skip operations
  const candidates = getClipboardCandidates(platform, env);
  if (candidates.length === 0) {
    return { copied: false, method: null, error: 'Clipboard unavailable in current environment' };
  }

  // Try available utilities in order of priority
  for (const candidate of candidates) {
    // Detect availability before attempting to run
    if (!isCommandAvailable(candidate.bin, platform, env)) {
      continue;
    }

    try {
      const res = runSpawnSync(candidate.bin, candidate.args, {
        input: text,
        encoding: 'utf-8',
        timeout: timeoutMs,
        windowsHide: true,
        stdio: ['pipe', 'ignore', 'ignore'],
        env,
      });

      if (res.error) {
        // Process error (e.g. ENOENT, EACCES, ETIMEDOUT, EPIPE)
        continue;
      }

      if (res.status === 0) {
        return { copied: true, method: candidate.bin };
      }

      // Non-zero exit code (e.g. Display server error or clipboard access denied)
      continue;
    } catch {
      // Catch any unexpected synchronous errors
      continue;
    }
  }

  return { copied: false, method: null, error: 'Clipboard utility failed or unavailable' };
}

/**
 * Asynchronous best-effort clipboard copy with graceful error handling.
 */
export async function copyToClipboardAsync(
  text: string,
  options: ClipboardOptions = {},
): Promise<ClipboardResult> {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const timeoutMs = options.timeoutMs ?? 3000;
  const runSpawn = options.spawn ?? spawn;

  if (typeof text !== 'string') {
    return { copied: false, method: null, error: 'Input text must be a string' };
  }

  const candidates = getClipboardCandidates(platform, env);
  if (candidates.length === 0) {
    return { copied: false, method: null, error: 'Clipboard unavailable in current environment' };
  }

  for (const candidate of candidates) {
    if (!isCommandAvailable(candidate.bin, platform, env)) {
      continue;
    }

    const success = await new Promise<boolean>((resolve) => {
      let settled = false;
      const settle = (val: boolean) => {
        if (!settled) {
          settled = true;
          resolve(val);
        }
      };

      try {
        const proc = runSpawn(candidate.bin, candidate.args, {
          stdio: ['pipe', 'ignore', 'ignore'],
          windowsHide: true,
          env,
        });

        const timer = setTimeout(() => {
          try {
            proc.kill();
          } catch {
            // Ignore
          }
          settle(false);
        }, timeoutMs);

        // Handle process errors (ENOENT, etc.)
        proc.on('error', () => {
          clearTimeout(timer);
          settle(false);
        });

        // Handle exit codes
        proc.on('close', (code) => {
          clearTimeout(timer);
          settle(code === 0);
        });

        // Handle stdin errors (EPIPE, etc.)
        if (proc.stdin) {
          proc.stdin.on('error', () => {
            clearTimeout(timer);
            settle(false);
          });

          proc.stdin.write(text, (err) => {
            if (err) {
              clearTimeout(timer);
              settle(false);
            } else {
              try {
                proc.stdin.end();
              } catch {
                clearTimeout(timer);
                settle(false);
              }
            }
          });
        }
      } catch {
        settle(false);
      }
    });

    if (success) {
      return { copied: true, method: candidate.bin };
    }
  }

  return { copied: false, method: null, error: 'Clipboard utility failed or unavailable' };
}
