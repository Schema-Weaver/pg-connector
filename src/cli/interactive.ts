import { stdin, stdout } from 'node:process';
import { printBanner } from './banner';
import { setReplMode } from './prompt';
import { runInit } from './commands/init';
import {
  runDbAdd,
  runDbList,
  runDbTest,
  runDbPing,
  runDbRemove,
  runDbEdit,
  runDbQuery,
  runDbConnect,
  runDbLogs,
  runDbShow,
} from './commands/db';
import { runProjectList, runProjectShow } from './commands/project';
import { runStart, runStop, runStatus, runRestart, runClean } from './commands/agent';
import { runDoctor } from './commands/doctor';
import { runLogs } from './commands/logs';
import { runAuditVerify } from './commands/audit-verify';
import { runConfigShow, runConfigGet, runConfigSet, runConfigPath } from './commands/config';
import { runLink } from './commands/link';
import {
  C,
  S,
  alignAnsi,
  clearScreen,
  fitLine,
  terminalWidth,
  truncateAnsi,
  visibleLength,
} from './ui';

const PROMPT = C.brand('sw-agent') + C.gray(' > ');

interface CommandDesc {
  name: string;
  desc: string;
  category: 'Databases' | 'Projects' | 'Agent' | 'Setup' | 'Ops';
  action: (args: string[]) => Promise<void>;
  aliases?: string[];
}

const COMMANDS: CommandDesc[] = [
  {
    name: 'db list',
    desc: 'List configured databases',
    category: 'Databases',
    action: (a) => runDbList(a),
    aliases: ['ls'],
  },
  {
    name: 'db show',
    desc: 'Show database details & live status',
    category: 'Databases',
    action: (a) => runDbShow(a),
    aliases: ['info'],
  },
  {
    name: 'db add',
    desc: 'Add a database',
    category: 'Databases',
    action: (a) => runDbAdd(a),
    aliases: ['add'],
  },
  {
    name: 'db edit',
    desc: 'Edit a database entry',
    category: 'Databases',
    action: (a) => runDbEdit(a),
    aliases: ['edit'],
  },
  {
    name: 'db remove',
    desc: 'Remove a database entry',
    category: 'Databases',
    action: (a) => runDbRemove(a),
    aliases: ['rm'],
  },
  {
    name: 'db test',
    desc: 'Test database connection',
    category: 'Databases',
    action: (a) => runDbTest(a),
    aliases: ['test'],
  },
  {
    name: 'db ping',
    desc: 'Ping database connection latency',
    category: 'Databases',
    action: (a) => runDbPing(a),
    aliases: ['ping'],
  },
  {
    name: 'db connect',
    desc: 'Open interactive SQL console (classified, audited)',
    category: 'Databases',
    action: (a) => runDbConnect(a),
    aliases: ['connect'],
  },
  {
    name: 'db query',
    desc: 'Execute SQL query against database (permission-checked)',
    category: 'Databases',
    action: (a) => runDbQuery(a),
    aliases: ['query'],
  },
  {
    name: 'db logs',
    desc: 'View audit logs for a database',
    category: 'Databases',
    action: (a) => runDbLogs(a),
  },

  {
    name: 'project list',
    desc: 'List linked projects',
    category: 'Projects',
    action: (a) => runProjectList(a),
    aliases: ['projects'],
  },
  {
    name: 'project show',
    desc: 'Show project details',
    category: 'Projects',
    action: (a) => runProjectShow(a),
  },

  {
    name: 'agent start',
    desc: 'Start the daemon',
    category: 'Agent',
    action: (a) => runStart(a),
    aliases: ['start', 'up'],
  },
  {
    name: 'agent stop',
    desc: 'Stop the daemon',
    category: 'Agent',
    action: (a) => runStop(a),
    aliases: ['stop', 'down'],
  },
  {
    name: 'agent restart',
    desc: 'Restart the daemon',
    category: 'Agent',
    action: (a) => runRestart(a),
    aliases: ['restart'],
  },
  {
    name: 'agent status',
    desc: 'Show agent status',
    category: 'Agent',
    action: (a) => runStatus(a),
    aliases: ['status', 'ps', 'top'],
  },
  {
    name: 'agent clean',
    desc: 'Clean daemon & stale PID/status files',
    category: 'Agent',
    action: (a) => runClean(a),
    aliases: ['clean', 'kill'],
  },

  { name: 'init', desc: 'First-time setup', category: 'Setup', action: (a) => runInit(a) },
  {
    name: 'doctor',
    desc: 'Run diagnostics',
    category: 'Setup',
    action: (a) => runDoctor(a),
    aliases: ['doc'],
  },
  {
    name: 'config show',
    desc: 'Show machine configuration',
    category: 'Setup',
    action: (a) => runConfigShow(a),
    aliases: ['config', 'conf', 'cfg'],
  },
  {
    name: 'config get',
    desc: 'Get a configuration setting',
    category: 'Setup',
    action: (a) => runConfigGet(a),
  },
  {
    name: 'config set',
    desc: 'Update a configuration setting',
    category: 'Setup',
    action: (a) => runConfigSet(a),
  },
  {
    name: 'config path',
    desc: 'Show config and state file paths',
    category: 'Setup',
    action: () => runConfigPath(),
  },
  {
    name: 'link',
    desc: 'Pairing stub for browser projects',
    category: 'Setup',
    action: (a) => runLink(a),
  },

  {
    name: 'logs',
    desc: 'Interactive audit log browser & viewer',
    category: 'Ops',
    action: (a) => runLogs(a),
    aliases: ['log'],
  },
  {
    name: 'audit verify',
    desc: 'Verify audit chain integrity',
    category: 'Ops',
    action: (a) => runAuditVerify(a),
    aliases: ['verify'],
  },
  { name: 'help', desc: 'Show help', category: 'Ops', action: () => showHelp() },
  {
    name: 'clear',
    desc: 'Clear screen',
    category: 'Ops',
    action: async () => {
      clearScreen();
      printBanner();
    },
  },
  { name: 'exit', desc: 'Quit', category: 'Ops', action: async () => {} },
];

export const PALETTE_ITEMS = COMMANDS.map((c) => ({
  command: c.name,
  desc: c.desc,
  category: c.category,
}));

const ALIAS_MAP = new Map<string, string>();
for (const cmd of COMMANDS) {
  for (const alias of cmd.aliases ?? []) {
    ALIAS_MAP.set(alias, cmd.name);
  }
}

function findCommand(input: string): CommandDesc | null {
  // Category fallbacks
  if (input === 'db') return COMMANDS.find((c) => c.name === 'db list') ?? null;
  if (input === 'agent') return COMMANDS.find((c) => c.name === 'agent status') ?? null;
  if (input === 'project') return COMMANDS.find((c) => c.name === 'project list') ?? null;
  if (input === 'audit') return COMMANDS.find((c) => c.name === 'audit verify') ?? null;

  const exact = COMMANDS.find((c) => c.name === input);
  if (exact) return exact;

  const alias = ALIAS_MAP.get(input);
  if (alias) {
    return COMMANDS.find((c) => c.name === alias) ?? null;
  }

  const legacy = input.replace(/:/g, ' ');
  const legacyCmd = COMMANDS.find((c) => c.name === legacy);
  if (legacyCmd) return legacyCmd;

  const matches = COMMANDS.filter((c) => c.name.startsWith(input));
  return matches.length === 1 ? matches[0] : null;
}

async function showHelp(): Promise<void> {
  console.log();
  console.log(C.bold('  Commands'));
  console.log();

  const categories: CommandDesc['category'][] = ['Databases', 'Projects', 'Agent', 'Setup', 'Ops'];
  for (const cat of categories) {
    console.log(C.brand(`  ${cat}`));
    for (const cmd of COMMANDS.filter((c) => c.category === cat)) {
      const aliasStr = cmd.aliases?.length ? C.dim(` (${cmd.aliases.join(', ')})`) : '';
      console.log(`    ${C.cyan(cmd.name.padEnd(18))}  ${C.dim(cmd.desc)}${aliasStr}`);
    }
    console.log();
  }

  console.log(`  ${C.dim('Type')} ${C.cyan('/')} ${C.dim('to open the command palette.')}`);
  console.log(`  ${C.dim('Type')} ${C.cyan('exit')} ${C.dim('to quit.')}`);
  console.log();
}

async function runCommand(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err: unknown) {
    if (err && typeof err === 'object' && '__exitCode' in err) {
      return;
    }
    console.log(`  ${C.red('Error:')} ${err instanceof Error ? err.message : String(err)}`);
  }
}

export async function dispatchCommand(input: string): Promise<'continue' | 'exit'> {
  const trimmed = input.trim();
  if (!trimmed) return 'continue';

  if (trimmed === 'exit' || trimmed === 'quit') return 'exit';
  if (trimmed === 'help') {
    await showHelp();
    return 'continue';
  }
  if (trimmed === 'clear') {
    clearScreen();
    printBanner();
    return 'continue';
  }

  if (trimmed.includes(':')) {
    const legacy = trimmed.replace(/:/g, ' ');
    if (findCommand(legacy)) {
      console.log(
        `  ${C.yellow('Deprecated:')} ${C.dim(trimmed)} -> use ${C.cyan(legacy)} instead`,
      );
    }
  }

  const parts = trimmed.split(/\s+/);
  let cmd: CommandDesc | null = null;
  let args: string[] = [];

  for (let wordCount = Math.min(parts.length, 3); wordCount >= 1; wordCount--) {
    const candidate = parts.slice(0, wordCount).join(' ');
    const found = findCommand(candidate);
    if (found) {
      cmd = found;
      args = parts.slice(wordCount);
      break;
    }
  }

  if (!cmd) {
    console.log(`  ${C.yellow('Unknown command:')} ${C.white(trimmed)}`);
    console.log(
      `  ${C.dim('Type')} ${C.cyan('/')} ${C.dim('for suggestions or')} ${C.cyan('help')} ${C.dim('for commands.')}`,
    );
    return 'continue';
  }

  if (cmd.name === 'exit') return 'exit';

  await runCommand(() => cmd!.action(args));

  if (
    cmd.name === 'agent start' ||
    cmd.name === 'agent stop' ||
    cmd.name === 'agent restart' ||
    cmd.name === 'agent clean'
  ) {
    await runCommand(() => runStatus([]));
  }

  return 'continue';
}

interface PaletteState {
  query: string;
  selected: number;
  scroll: number;
}

class TerminalRepl {
  private buffer = '';
  private cursor = 0;
  private palette: PaletteState | null = null;
  private isExecuting = false;
  private renderedLines = 0;
  private resizeTimer: ReturnType<typeof setTimeout> | null = null;
  private resolve!: (code: number) => void;
  private readonly onDataBound = this.onKey.bind(this);
  private readonly onResizeBound = this.onResize.bind(this);

  async run(): Promise<number> {
    printBanner();
    setReplMode(true);
    stdout.write(
      `  ${C.dim('Type')} ${C.cyan('/')} ${C.dim('for commands,')} ${C.cyan('help')} ${C.dim('for help,')} ${C.cyan('exit')} ${C.dim('to quit.')}\n\n`,
    );

    if (stdin.isTTY) {
      stdin.setRawMode(true);
    }
    stdin.resume();
    stdin.on('data', this.onDataBound);
    stdout.on('resize', this.onResizeBound);
    this.render();

    return new Promise<number>((resolve) => {
      this.resolve = resolve;
    });
  }

  private onResize() {
    if (this.resizeTimer) clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => this.render(), 50);
  }

  private onKey(chunk: Buffer) {
    if (this.isExecuting) return;

    const sequences = splitInput(chunk.toString('utf8'));
    for (const token of sequences) {
      if (this.handleToken(token)) return;
    }
    this.render();
  }

  private handleToken(token: string): boolean {
    if (token === '\x03') {
      this.shutdown();
      return true;
    }

    if (token === '\r' || token === '\n') {
      if (this.palette) {
        const match = this.filteredPalette()[this.palette.selected];
        if (match) {
          this.buffer = match.command;
          this.cursor = this.buffer.length;
          this.palette = null;
          this.render();
          this.submit();
        }
        return true;
      }
      this.submit();
      return true;
    }

    if (token === '\x1b') {
      if (this.palette && this.buffer.startsWith('/')) {
        this.buffer = '';
        this.cursor = 0;
      }
      this.palette = null;
      return false;
    }

    if (token === '\x7f' || token === '\b') {
      this.backspace();
      return false;
    }

    if (token === '\t') {
      if (this.palette) {
        this.movePalette(1);
      }
      return false;
    }

    if (token === '\x1b[A') {
      if (this.palette) this.movePalette(-1);
      return false;
    }
    if (token === '\x1b[B') {
      if (this.palette) this.movePalette(1);
      return false;
    }
    if (token === '\x1b[D') {
      this.cursor = Math.max(0, this.cursor - 1);
      return false;
    }
    if (token === '\x1b[C') {
      this.cursor = Math.min(this.buffer.length, this.cursor + 1);
      return false;
    }
    if (token === '\x1b[H' || token === '\x1b[1~') {
      this.cursor = 0;
      return false;
    }
    if (token === '\x1b[F' || token === '\x1b[4~') {
      this.cursor = this.buffer.length;
      return false;
    }
    if (token === '\x1b[3~') {
      this.deleteForward();
      return false;
    }

    if (/^[ -~]$/.test(token)) {
      this.insert(token);
    }

    return false;
  }

  private insert(ch: string) {
    this.buffer = this.buffer.slice(0, this.cursor) + ch + this.buffer.slice(this.cursor);
    this.cursor += ch.length;

    if (this.buffer.startsWith('/')) {
      this.palette = {
        query: this.buffer.slice(1).trimStart(),
        selected: 0,
        scroll: 0,
      };
    }
  }

  private backspace() {
    if (this.cursor <= 0) return;
    this.buffer = this.buffer.slice(0, this.cursor - 1) + this.buffer.slice(this.cursor);
    this.cursor -= 1;

    if (this.palette) {
      if (!this.buffer.startsWith('/')) {
        this.palette = null;
      } else {
        this.palette.query = this.buffer.slice(1).trimStart();
        this.palette.selected = 0;
        this.palette.scroll = 0;
        if (this.palette.query === '' && this.buffer === '') {
          this.palette = null;
        }
      }
    }
  }

  private deleteForward() {
    if (this.cursor >= this.buffer.length) return;
    this.buffer = this.buffer.slice(0, this.cursor) + this.buffer.slice(this.cursor + 1);
    if (this.palette) {
      this.palette.query = this.buffer.startsWith('/') ? this.buffer.slice(1).trimStart() : '';
    }
  }

  private movePalette(delta: number) {
    if (!this.palette) return;
    const matches = this.filteredPalette();
    if (matches.length === 0) return;

    this.palette.selected = Math.max(
      0,
      Math.min(matches.length - 1, this.palette.selected + delta),
    );
    const height = this.paletteHeight();
    if (this.palette.selected < this.palette.scroll) {
      this.palette.scroll = this.palette.selected;
    } else if (this.palette.selected >= this.palette.scroll + height) {
      this.palette.scroll = this.palette.selected - height + 1;
    }
  }

  private async submit() {
    const input = this.buffer.trim();
    this.palette = null;

    if (!input) {
      this.render();
      return;
    }

    this.clearRenderedBlock();
    stdout.write(`${PROMPT}${this.buffer}\n`);
    this.buffer = '';
    this.cursor = 0;

    this.isExecuting = true;
    this.setRawMode(false);
    let result: 'continue' | 'exit' = 'continue';
    try {
      result = await dispatchCommand(input);
    } finally {
      this.setRawMode(true);
      this.isExecuting = false;
    }

    if (result === 'exit') {
      this.shutdown();
      return;
    }

    this.render();
  }

  private filteredPalette() {
    if (!this.palette) return PALETTE_ITEMS;
    const q = this.palette.query.toLowerCase();
    if (!q) return PALETTE_ITEMS;

    return PALETTE_ITEMS.map((item) => ({ item, score: rankPalette(q, item) }))
      .filter(({ score }) => score < 50)
      .sort((a, b) => a.score - b.score || a.item.command.localeCompare(b.item.command))
      .map(({ item }) => item);
  }

  private paletteHeight() {
    const rows = Math.max(3, Math.min(8, Math.floor((process.stdout.rows || 24) / 3)));
    return rows;
  }

  private renderPalette(): string[] {
    if (!this.palette) return [];

    const width = Math.max(28, Math.min(64, terminalWidth() - 4));
    const inner = width - 2;
    const matches = this.filteredPalette();
    const height = this.paletteHeight();
    const visible = matches.slice(this.palette.scroll, this.palette.scroll + height);
    const lines: string[] = [];

    const title = this.palette.query ? ` Commands matching "${this.palette.query}" ` : ' Commands ';
    const titleWidth = Math.min(visibleLength(title), inner - 2);
    lines.push(
      C.cyan(
        S.tl +
          S.h +
          truncateAnsi(title, titleWidth) +
          S.h.repeat(Math.max(0, inner - titleWidth - 1)) +
          S.tr,
      ),
    );

    if (visible.length === 0) {
      lines.push(C.cyan(S.v) + ' ' + alignAnsi(C.dim('No matches'), inner - 1) + C.cyan(S.v));
    } else {
      for (let i = 0; i < height; i++) {
        const item = visible[i];
        if (!item) {
          lines.push(C.cyan(S.v) + ' '.repeat(inner) + C.cyan(S.v));
          continue;
        }
        const index = this.palette.scroll + i;
        const selected = index === this.palette.selected;
        const marker = selected ? C.brand(S.right) : ' ';
        const cmdWidth = Math.min(22, Math.max(12, Math.floor(inner * 0.42)));
        const descWidth = Math.max(8, inner - cmdWidth - 5);
        const cmd = selected ? C.bold(C.brand(item.command)) : C.cyan(item.command);
        const desc = selected ? C.white(item.desc) : C.dim(item.desc);
        const body =
          ` ${marker} ` +
          alignAnsi(truncateAnsi(cmd, cmdWidth, S.ellipsis), cmdWidth) +
          '  ' +
          alignAnsi(truncateAnsi(desc, descWidth, S.ellipsis), descWidth);
        const fitted = truncateAnsi(body, inner, '');
        lines.push(
          C.cyan(S.v) +
            fitted +
            ' '.repeat(Math.max(0, inner - visibleLength(fitted))) +
            C.cyan(S.v),
        );
      }
    }

    const total = matches.length;
    const start = total === 0 ? 0 : this.palette.selected + 1;
    const footer = ` ${start}/${total}  Enter select  Esc cancel  Backspace close `;
    lines.push(C.cyan(S.bl + S.h.repeat(inner) + S.br));
    lines.push(C.dim('  ' + truncateAnsi(footer.trim(), width - 2)));
    return lines;
  }

  private render() {
    this.clearRenderedBlock();
    const lines = this.renderPalette();
    for (const line of lines) {
      stdout.write(fitLine(line) + '\n');
    }

    const promptLine = PROMPT + this.buffer;
    stdout.write('\r\x1b[2K' + fitLine(promptLine));
    this.renderedLines = lines.length + 1;

    const cursorColumn = visibleLength(PROMPT) + this.cursor;
    if (cursorColumn > 0) {
      stdout.write(`\r\x1b[${cursorColumn}C`);
    }
  }

  private clearRenderedBlock() {
    if (this.renderedLines === 0) return;
    stdout.write('\r\x1b[2K');
    for (let i = 1; i < this.renderedLines; i++) {
      stdout.write('\x1b[1A\x1b[2K');
    }
    stdout.write('\r');
    this.renderedLines = 0;
  }

  private shutdown() {
    this.clearRenderedBlock();
    setReplMode(false);
    stdin.off('data', this.onDataBound);
    stdout.off('resize', this.onResizeBound);
    if (this.resizeTimer) clearTimeout(this.resizeTimer);
    this.setRawMode(false);
    stdout.write(`\n  ${C.green('Bye.')} ${C.dim('See you next time.')}\n\n`);
    this.resolve(0);
  }

  private setRawMode(enabled: boolean) {
    if (!stdin.isTTY) return;
    try {
      stdin.setRawMode(enabled);
    } catch {
      // ignore
    }
  }
}

function rankPalette(
  query: string,
  item: { command: string; desc: string; category: string },
): number {
  const cmd = item.command.toLowerCase();
  const desc = item.desc.toLowerCase();
  const cat = item.category.toLowerCase();
  if (cmd === query) return 0;
  if (cmd.startsWith(query)) return 1;
  if (cmd.includes(query)) return 5;
  if (cat.startsWith(query)) return 10;
  if (desc.includes(query)) return 20;
  return 50;
}

/**
 * A single ANSI escape sequence, built from the escape byte rather than written
 * as `\x1b` inside a pattern literal so the rule does not trip
 * `no-control-regex`.
 */
const ESCAPE_SEQUENCE = new RegExp(`^\\u001b\\[[0-9;]*[~A-Za-z]`);

function splitInput(input: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < input.length; ) {
    if (input[i] === '\x1b') {
      const match = ESCAPE_SEQUENCE.exec(input.slice(i));
      if (match) {
        out.push(match[0]);
        i += match[0].length;
      } else {
        out.push('\x1b');
        i += 1;
      }
      continue;
    }
    const codePoint = input.codePointAt(i);
    if (codePoint === undefined) break;
    const char = String.fromCodePoint(codePoint);
    out.push(char);
    i += char.length;
  }
  return out;
}

export async function startInteractive(): Promise<number> {
  const repl = new TerminalRepl();
  return repl.run();
}
