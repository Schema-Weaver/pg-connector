import * as readline from 'readline';
import { select } from '@inquirer/prompts';
import { C } from './ui/colors';

let rl: readline.Interface | null = null;

export function setReplInterface(interface_: readline.Interface | null): void {
  rl = interface_;
}

let replMode = false;

export function setReplMode(mode: boolean): void {
  replMode = mode;
}

export function isReplMode(): boolean {
  return replMode;
}

export function getReplInterface(): readline.Interface | null {
  return rl;
}

export function ask(question: string, defaultValue?: string): Promise<string> {
  return new Promise((resolve) => {
    const displayDefault = defaultValue !== undefined ? C.dim(` [${defaultValue}]`) : '';
    const promptText = `${C.brand('?')} ${C.white(question)}${displayDefault} `;

    if (rl) {
      rl.pause();
      const tempRl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: true,
      });

      tempRl.question(promptText, (answer) => {
        try {
          tempRl.close();
        } catch {
          // ignore
        }
        rl?.resume();
        const trimmed = answer.trim();
        if (trimmed === '' && defaultValue !== undefined) {
          resolve(defaultValue);
        } else {
          resolve(trimmed);
        }
      });
    } else {
      const promptInterface = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });

      promptInterface.question(promptText, (answer) => {
        promptInterface.close();
        const trimmed = answer.trim();
        if (trimmed === '' && defaultValue !== undefined) {
          resolve(defaultValue);
        } else {
          resolve(trimmed);
        }
      });
    }
  });
}

export function askSecret(question: string): Promise<string> {
  return new Promise((resolve) => {
    const promptText = `${C.brand('?')} ${C.white(question)} `;

    if (rl) {
      rl.pause();
    }

    const stdout = process.stdout;
    const stdin = process.stdin;
    let password = '';

    stdout.write(promptText);

    if (stdin.isTTY) {
      stdin.setRawMode(true);
    }
    stdin.resume();

    const onData = (chunk: Buffer) => {
      const str = chunk.toString('utf8');
      for (const ch of str) {
        const code = ch.charCodeAt(0);
        if (code === 3) {
          // Ctrl+C
          cleanup();
          process.exit(130);
        }
        if (code === 13 || code === 10) {
          // Enter
          cleanup();
          stdout.write('\n');
          resolve(password.trim());
          return;
        }
        if (code === 127 || code === 8) {
          // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
            if (stdout.isTTY) {
              stdout.write('\b \b');
            }
          }
          continue;
        }
        if (code === 27) {
          // Escape sequences (arrow keys, etc.) - ignore
          continue;
        }
        if (code < 32) {
          // Control characters - ignore
          continue;
        }
        password += ch;
        if (stdout.isTTY) {
          stdout.write(C.dim('*'));
        }
      }
    };

    const cleanup = () => {
      stdin.removeListener('data', onData);
      if (stdin.isTTY) {
        try {
          stdin.setRawMode(false);
        } catch {
          // ignore
        }
      }
      rl?.resume();
    };

    stdin.on('data', onData);
  });
}

export async function askChoice(
  question: string,
  choices: string[],
  defaultValue?: string,
): Promise<string> {
  if (rl) {
    rl.pause();
  }

  try {
    const result = await select({
      message: question,
      choices: choices.map((c) => ({ name: c, value: c })),
      default: defaultValue,
    });
    return result;
  } finally {
    rl?.resume();
  }
}

export async function askConfirm(question: string, defaultValue: boolean): Promise<boolean> {
  const displaySuffix = defaultValue ? C.dim(' (Y/n)') : C.dim(' (y/N)');
  for (;;) {
    const ans = await ask(`${question}${displaySuffix}`);
    if (ans === '') {
      return defaultValue;
    }
    const lower = ans.toLowerCase();
    if (lower === 'y' || lower === 'yes') {
      return true;
    }
    if (lower === 'n' || lower === 'no') {
      return false;
    }
    console.log(C.yellow('  Please enter "y" or "n".'));
  }
}

export function closePrompts(): void {
  // No-op - readline interfaces are managed per-call
}
