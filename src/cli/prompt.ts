import * as fs from 'fs';
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

/**
 * Where a resolved value came from.
 *
 * `'argv'` is reachable only for a value the caller proved carries no secret
 * (see {@link ResolveSecretOptions.assertArgvValueSafe}); a secret is never
 * sourced from argv. `'env'` means a value read from a named environment
 * variable by the caller, which is a private channel on Linux because
 * `/proc/<pid>/environ` is mode 0400 and owned by the process's own user.
 */
export type SecretSource = 'file' | 'stdin' | 'env' | 'argv' | 'prompt';

export interface ResolvedSecret {
  /** The secret, or undefined when no source supplied one. */
  value?: string;
  source?: SecretSource;
}

export interface ResolveSecretOptions {
  args: string[];
  /** Human name used in messages, e.g. "Database password". */
  label: string;
  /**
   * Flags whose value would put the secret inline in `process.argv`.
   *
   * An argv value is REFUSED, not warned about: `/proc/<pid>/cmdline` is
   * world-readable on Linux, so a warning still leaks the credential to every
   * local UID for the lifetime of the process, and the value is already written
   * to the shell history by the time the warning is printed. A warning that the
   * deprecated flag "still works" is a credential leak with extra steps.
   *
   * The exception is a value that is only ARGUMENT-SAFE when it carries no
   * secret — a connection URL without userinfo. `db add --url` passes such a
   * value through `assertArgvValueSafe`, which is what decides; a URL with a
   * password in it is refused by that assertion.
   */
  argvFlags: readonly string[];
  /** Proves an argv value carries no credential. Omit to refuse every one. */
  assertArgvValueSafe?: (value: string) => void;
  /** Flags naming a file to read the secret from. */
  fileFlags: readonly string[];
  /** Flags that read the secret from stdin. */
  stdinFlags: readonly string[];
  /** Masked prompt to fall back to when nothing was supplied. */
  promptWhenMissing?: boolean;
  /** Stdin reader, injectable for tests. Defaults to reading fd 0. */
  readStdin?: () => string;
  /** Masked prompt, injectable for tests. Defaults to {@link askSecret}. */
  prompt?: (label: string) => Promise<string>;
  /**
   * Accepted for source compatibility. A refusal no longer consults it: whether
   * an argv value is acceptable is decided by `assertArgvValueSafe`, and the
   * answer can no longer be downgraded to a warning.
   */
  shouldWarnOnArgv?: (value: string) => boolean;
}

function findFlagValue(args: string[], ...names: string[]): string | undefined {
  for (const name of names) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length && !args[idx + 1].startsWith('-')) {
      return args[idx + 1];
    }
  }
  return undefined;
}

function hasFlag(args: string[], ...names: string[]): boolean {
  return names.some((name) => args.includes(name));
}

/** True when both ends are a terminal, i.e. a human can answer a prompt. */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

function stripTrailingNewline(value: string): string {
  return value.replace(/\r?\n$/, '');
}

/**
 * Machine-readable reasons a credential channel was refused. Printed in the
 * refusal headline so an operator (and a CI gate) can grep for the code instead
 * of parsing prose.
 */
export type SecretRefusalCode = 'password_in_argv_refused' | 'password_file_not_private';

/**
 * A credential channel was refused.
 *
 * `message` is the complete, self-contained operator explanation — including
 * the code — because callers that do not know about this class (any command
 * that catches and prints `err.message`) must still produce the full refusal
 * text rather than a bare "refused". `lines` is the same text split for
 * commanders that render it.
 *
 * Nothing in a `SecretRefusalError` may contain the rejected secret. The whole
 * point of refusing is that the value does not reach the terminal, the shell
 * history again, `errors.jsonl`, or `daemon.log`.
 */
export class SecretRefusalError extends Error {
  readonly code: SecretRefusalCode;
  /** The operator-facing explanation, one array entry per line. */
  readonly lines: readonly string[];

  constructor(code: SecretRefusalCode, headline: string, detail: readonly string[]) {
    const lines = [`${code}: ${headline}`, ...detail];
    super(lines.join('\n'));
    this.name = 'SecretRefusalError';
    this.code = code;
    this.lines = lines;
  }
}

/** True when `err` is a refusal this module raised. */
export function isSecretRefusalError(err: unknown): err is SecretRefusalError {
  return err instanceof SecretRefusalError;
}

/**
 * Why a value on the command line cannot be treated as a private channel.
 *
 * `/proc/<pid>/cmdline` is world-readable on Linux under the default
 * `hidepid=0`, so an argument is readable by EVERY local UID for the lifetime of
 * the process — by `ps`, by every process-listing tool, and by anything
 * scraping `/proc`. The same value is additionally retained in the shell's
 * history file, in terminal scrollback, and in CI job logs, which is why
 * removing the code path is the only real fix: a warning that a credential
 * "still works" is a warning that still leaks.
 */
function argvExposureExplanation(alternatives: readonly string[]): readonly string[] {
  return [
    'On Linux /proc/<pid>/cmdline is world-readable (hidepid=0 by default), so this value is',
    'visible to every local user for as long as the process lives, and to any process-listing',
    'tool (`ps`, `top`, a /proc scan). It is also recorded in your shell history, in terminal',
    'scrollback, and in CI job logs.',
    `Use a channel that is not argv instead: ${alternatives.join(', ')} — or run the command`,
    'with no flags for a masked prompt.',
  ];
}

/** The safe channels, in the order they should be tried. */
function safeChannelAlternatives(opts: {
  fileFlags: readonly string[];
  stdinFlags: readonly string[];
}): string[] {
  return [...opts.fileFlags.map((f) => `${f} <path>`), ...opts.stdinFlags];
}

/**
 * Builds the refusal for a secret supplied inline on the command line.
 *
 * The rejected value is never echoed. The explanation names the flags, states
 * why argv is not private, and lists the channels that are.
 */
export function refuseSecretInArgv(
  flags: readonly string[],
  label: string,
  alternatives: readonly string[],
): SecretRefusalError {
  const flagList = flags.join('/');
  return new SecretRefusalError(
    'password_in_argv_refused',
    `${flagList} passes the ${label} in process.argv, so this command refuses to run.`,
    argvExposureExplanation(alternatives),
  );
}

/** Matches the userinfo of a `scheme://user:secret@host` prefix. */
const URL_WITH_USERINFO = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/;

/** The placeholder a redacted password is replaced with. Matches `redactSecrets`. */
export const REDACTED_PLACEHOLDER = '***';

/**
 * Replaces the password in a connection URL with a placeholder while keeping
 * the URL recognisable, so a refusal can show the operator exactly what was
 * rejected without the rejection itself becoming the leak.
 *
 * Percent-encoded passwords are handled by construction: `URL.password` keeps
 * the encoding, so assigning over the field deletes the whole encoded value
 * rather than a decoded fragment of it. The textual fallback covers a URL the
 * WHATWG parser rejects, where the last `@` in the authority is treated as the
 * userinfo separator.
 */
export function redactUrlPassword(raw: string): string {
  try {
    const url = new URL(raw);
    if (url.password === '') return raw;
    url.password = REDACTED_PLACEHOLDER;
    return url.toString();
  } catch {
    const match = URL_WITH_USERINFO.exec(raw);
    if (!match) return raw;
    const [, scheme, authority, rest] = match;
    const at = authority.lastIndexOf('@');
    const colon = authority.indexOf(':');
    if (at === -1 || colon === -1 || colon > at) return raw;
    return `${scheme}${authority.slice(0, colon + 1)}${REDACTED_PLACEHOLDER}${authority.slice(at)}${rest}`;
  }
}

/**
 * True when a connection URL carries userinfo, i.e. a credential.
 *
 * A URL the parser rejects counts as carrying one: refusing an unparseable URL
 * is strictly safer than forwarding a value whose shape was never understood.
 */
export function urlCarriesCredentials(value: string): boolean {
  try {
    const u = new URL(value);
    return u.username.length > 0 || u.password.length > 0;
  } catch {
    return true;
  }
}

/**
 * Asserts a connection URL taken from argv carries no password.
 *
 * The URL is the only argv value this CLI still accepts, and only because a URL
 * without userinfo is not a credential. One WITH userinfo is refused and echoed
 * back redacted, so the operator can see which URL was rejected without the
 * rejection itself becoming the leak.
 */
export function assertUrlHasNoPassword(value: string): void {
  try {
    if (new URL(value).password === '') return;
  } catch {
    // An unparseable URL is refused below with the textual check.
  }
  throw new SecretRefusalError(
    'password_in_argv_refused',
    '--url carries a password in process.argv, so this command refuses to run.',
    [
      `Rejected: ${redactUrlPassword(value)}`,
      ...argvExposureExplanation([
        '--url-file <path> (mode 0600)',
        '--url-stdin',
        '--url with no password, plus --password-file <path>, --password-stdin or --env <var>',
      ]),
    ],
  );
}

/**
 * Refuses a credential file that any local user can read, or that is a symlink.
 *
 * Two separate attacks, so two separate refusals:
 *
 *  - Permissions. `fs.readFileSync` on a 0644 file hands the password to every
 *    local UID. Accepting it would move the leak out of argv (where it is at
 *    least momentary) and into a file that stays exposed for as long as it
 *    exists. Owner-only (`0600`, `0400`) is the requirement.
 *  - Symlink. A link planted by another local user makes the read return whatever
 *    the link target holds, so the "password" the CLI stores is not necessarily
 *    the one on disk, and the operator's real secret file can be aimed at a
 *    process that will read it. `lstat`, never `stat`: `stat` follows the link
 *    and reports the target's type, which is exactly the check that has to fail.
 *
 * POSIX modes are meaningless on Windows, so the permission check is POSIX-only.
 */
export function assertSecretFileIsPrivate(filePath: string, label: string): void {
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (err) {
    throw new Error(
      `Could not inspect the ${label} file "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (stats.isSymbolicLink()) {
    throw new SecretRefusalError(
      'password_file_not_private',
      `refusing to read the ${label} file "${filePath}" because it is a symbolic link.`,
      [
        'A link planted by another local user decides what this read returns, and can aim the',
        'read at a file that has nothing to do with the password. Pass the real file instead.',
      ],
    );
  }

  if (!stats.isFile()) {
    throw new SecretRefusalError(
      'password_file_not_private',
      `refusing to read the ${label} file "${filePath}" because it is not a regular file.`,
      ['A directory, socket or device is not a credential file.'],
    );
  }

  if (process.platform === 'win32') return;

  const mode = stats.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new SecretRefusalError(
      'password_file_not_private',
      `refusing to read the ${label} file "${filePath}" because it has mode ${mode.toString(8).padStart(4, '0')}.`,
      [
        'A credential file must be readable by its owner only; the group and other bits hand the',
        'password to every local user.',
        `Fix it with: chmod 600 ${filePath}`,
      ],
    );
  }
}

/**
 * Reads a secret from a file. Refuses a group- or world-readable file and a
 * symlink first — see {@link assertSecretFileIsPrivate} — then throws with a
 * caller-facing message on failure.
 */
export function readSecretFromFile(filePath: string, label: string): string {
  assertSecretFileIsPrivate(filePath, label);
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new Error(
      `Could not read the ${label} file "${filePath}": ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const value = stripTrailingNewline(raw);
  if (value.length === 0) {
    throw new Error(`The ${label} file "${filePath}" is empty.`);
  }
  return value;
}

/**
 * Reads a secret from stdin (fd 0) to end-of-input, so the secret never
 * appears in argv. Throws when the input is empty.
 */
export function readSecretFromStdin(label: string, reader?: () => string): string {
  let raw: string;
  try {
    raw = reader ? reader() : fs.readFileSync(0, 'utf8');
  } catch (err) {
    throw new Error(
      `Could not read the ${label} from stdin: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const value = stripTrailingNewline(raw);
  if (value.length === 0) {
    throw new Error(`No ${label} was received on stdin.`);
  }
  return value;
}

/**
 * The deprecation warning printed when a secret is taken from argv.
 *
 * Kept only so an operator who already scripted the old flag gets told what to
 * use instead. Nothing calls it on the success path any more: `resolveSecret`
 * REFUSES an argv secret, and only a refusal is printed.
 */
export function secretArgvExposureWarning(
  flags: readonly string[],
  label: string,
  alternatives: readonly string[],
): string {
  const flagList = flags.join('/');
  return [
    `  ${C.yellow('!')} ${C.yellow(`REFUSED: ${flagList} would pass the ${label} in process.argv.`)}`,
    `    ${C.dim('It is readable by any local user via ps and /proc/<pid>/cmdline, and it is kept in your')}`,
    `    ${C.dim('shell history, terminal scrollback and CI job logs. Use')} ${C.cyan(alternatives.join(' or '))} ${C.dim('instead.')}`,
  ].join('\n');
}

/** Prints the refusal notice for an argv-supplied secret. */
export function warnSecretExposedInArgv(
  flags: readonly string[],
  label: string,
  alternatives: readonly string[],
): void {
  console.log(secretArgvExposureWarning(flags, label, alternatives));
}

/**
 * Resolves a secret from a channel that is not argv, in order: a private file,
 * stdin, then a masked prompt.
 *
 * An argv value is never returned unless the caller supplied
 * `assertArgvValueSafe` AND it accepted the value. Without that assertion
 * (`db add --password`, `db edit --pw`, and every future caller that has not
 * thought about it) the flag is refused with `password_in_argv_refused` and no
 * value is ever read out of argv, so the secret cannot reach `ps`,
 * `/proc/<pid>/cmdline`, the shell history, or any log this process writes.
 *
 * Refusal is checked BEFORE the safe channels on purpose. `db add --password x
 * --password-file f` is refused rather than quietly honoured via the file: the
 * value is already in argv whatever this command does next, so the operator
 * needs to hear about it, and the shell history needs to be cleaned.
 */
export async function resolveSecret(opts: ResolveSecretOptions): Promise<ResolvedSecret> {
  const argvFlag = opts.argvFlags.find((f) => hasFlag(opts.args, f));
  if (argvFlag) {
    const inline = findFlagValue(opts.args, argvFlag);
    if (inline === undefined) {
      throw new Error(`${argvFlag} requires a value.`);
    }
    if (opts.assertArgvValueSafe) {
      opts.assertArgvValueSafe(inline);
      return { value: inline, source: 'argv' };
    }
    throw refuseSecretInArgv(opts.argvFlags, opts.label, safeChannelAlternatives(opts));
  }

  const fileFlag = opts.fileFlags.find((f) => hasFlag(opts.args, f));
  if (fileFlag) {
    const filePath = findFlagValue(opts.args, fileFlag);
    if (filePath === undefined) {
      throw new Error(`${fileFlag} requires a path.`);
    }
    return { value: readSecretFromFile(filePath, opts.label), source: 'file' };
  }

  const stdinFlag = opts.stdinFlags.find((f) => hasFlag(opts.args, f));
  if (stdinFlag) {
    return {
      value: readSecretFromStdin(opts.label, opts.readStdin),
      source: 'stdin',
    };
  }

  if (opts.promptWhenMissing && isInteractive()) {
    const value = await (opts.prompt ?? askSecret)(opts.label);
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      return { value: trimmed, source: 'prompt' };
    }
  }

  return {};
}
