/**
 * Minimal full-screen terminal layer used by the interactive CLI dialogs.
 *
 * It deliberately has no third-party dependency: OpenTUI's current releases
 * need Node.js 26's `node:ffi`, while this package supports Node.js 18+. This
 * module provides the pieces the CLI actually needs — alternate screen, raw
 * keyboard input, SGR mouse reporting, clickable regions and a clean restore —
 * so the UI still behaves like a modern full-screen TUI.
 */
import { stdin, stdout } from 'node:process';
import { truncateAnsi, visibleLength } from '../ui/colors';

export interface TuiRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface TuiKey {
  name: string;
  sequence: string;
  ctrl: boolean;
  shift: boolean;
  meta: boolean;
}

export type TuiMouseButton = 'left' | 'middle' | 'right' | 'wheelUp' | 'wheelDown';
export type TuiMouseAction = 'down' | 'up' | 'move';

export interface TuiMouseEvent {
  x: number;
  y: number;
  button: TuiMouseButton;
  action: TuiMouseAction;
}

export interface TuiRegion {
  rect: TuiRect;
  onClick?: (event: TuiMouseEvent) => void;
  onWheel?: (delta: number) => void;
}

export interface TuiFrame {
  lines: string[];
  regions?: TuiRegion[];
  cursor?: { x: number; y: number };
}

export interface TuiScreen {
  readonly width: number;
  readonly height: number;
  render(frame: TuiFrame): void;
  onKey(handler: (key: TuiKey) => void): () => void;
  onMouse(handler: (event: TuiMouseEvent) => void): () => void;
  onResize(handler: () => void): () => void;
  destroy(): void;
}

let tuiActive = false;

export function isTuiActive(): boolean {
  return tuiActive;
}

export function setTuiActive(active: boolean): void {
  tuiActive = active;
}

/** A real terminal is required for alternate screen, raw mode and mouse input. */
export function isTuiSupported(): boolean {
  if (process.env.SW_AGENT_NO_TUI === '1') return false;
  return Boolean(stdin.isTTY && stdout.isTTY);
}

export function createTuiScreen(): TuiScreen | null {
  return isTuiSupported() ? new AnsiTuiScreen() : null;
}

class AnsiTuiScreen implements TuiScreen {
  private readonly keyHandlers = new Set<(key: TuiKey) => void>();
  private readonly mouseHandlers = new Set<(event: TuiMouseEvent) => void>();
  private readonly resizeHandlers = new Set<() => void>();
  private frame: TuiFrame = { lines: [] };
  private buffer = '';
  private destroyed = false;
  private escapeTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly onDataBound = (chunk: Buffer) => this.handleData(chunk);
  private readonly onResizeBound = () => this.handleResize();
  private readonly onExitBound = () => this.restoreTerminal();

  constructor() {
    stdout.write('\x1b[?1049h\x1b[?25l\x1b[?1003h\x1b[?1006h');
    if (stdin.isTTY) {
      try {
        stdin.setRawMode(true);
      } catch {
        // A non-raw TTY still handles Enter; arrows and mouse may not work.
      }
    }
    stdin.resume();
    stdin.on('data', this.onDataBound);
    stdout.on('resize', this.onResizeBound);
    process.once('exit', this.onExitBound);
  }

  get width(): number {
    return stdout.columns || 80;
  }

  get height(): number {
    return stdout.rows || 24;
  }

  render(frame: TuiFrame): void {
    if (this.destroyed) return;
    this.frame = frame;

    let output = '\x1b[H\x1b[?25l';
    for (let y = 0; y < this.height; y += 1) {
      const line = truncateAnsi(frame.lines[y] ?? '', this.width, '');
      output += `\x1b[${y + 1};1H\x1b[2K${line}`;
    }

    if (frame.cursor) {
      const x = Math.max(0, Math.min(this.width - 1, frame.cursor.x));
      const y = Math.max(0, Math.min(this.height - 1, frame.cursor.y));
      output += `\x1b[${y + 1};${x + 1}H\x1b[?25h`;
    }

    stdout.write(output);
  }

  onKey(handler: (key: TuiKey) => void): () => void {
    this.keyHandlers.add(handler);
    return () => this.keyHandlers.delete(handler);
  }

  onMouse(handler: (event: TuiMouseEvent) => void): () => void {
    this.mouseHandlers.add(handler);
    return () => this.mouseHandlers.delete(handler);
  }

  onResize(handler: () => void): () => void {
    this.resizeHandlers.add(handler);
    return () => this.resizeHandlers.delete(handler);
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.escapeTimer) clearTimeout(this.escapeTimer);
    stdin.off('data', this.onDataBound);
    stdout.off('resize', this.onResizeBound);
    process.off('exit', this.onExitBound);
    this.restoreTerminal();
  }

  private restoreTerminal(): void {
    if (stdin.isTTY) {
      try {
        stdin.setRawMode(false);
      } catch {
        // ignore
      }
    }
    stdout.write('\x1b[?1006l\x1b[?1003l\x1b[?25h\x1b[?1049l\x1b[0m');
  }

  private handleResize(): void {
    for (const handler of this.resizeHandlers) handler();
  }

  private handleData(chunk: Buffer): void {
    if (this.escapeTimer) {
      clearTimeout(this.escapeTimer);
      this.escapeTimer = null;
    }

    const parsed = parseTuiInput(this.buffer + chunk.toString('utf8'), false);
    this.buffer = parsed.rest;

    for (const token of parsed.tokens) {
      if (token.type === 'mouse') {
        const event = token.event;
        const region = [...(this.frame.regions ?? [])]
          .reverse()
          .find(
            (item) =>
              event.x >= item.rect.x &&
              event.x < item.rect.x + item.rect.width &&
              event.y >= item.rect.y &&
              event.y < item.rect.y + item.rect.height,
          );
        if (event.action === 'move') {
          region?.onClick?.(event);
        } else if (event.action === 'down') {
          if (event.button === 'wheelUp' || event.button === 'wheelDown') {
            region?.onWheel?.(event.button === 'wheelUp' ? -1 : 1);
          } else if (event.button === 'left') {
            region?.onClick?.(event);
          }
        }
        for (const handler of this.mouseHandlers) handler(event);
        continue;
      }

      for (const handler of this.keyHandlers) handler(token.key);
    }

    // Hold a trailing Escape briefly so a split ESC [ A arrow sequence is not
    // mistaken for the Escape key.
    if (this.buffer === '\x1b') {
      this.escapeTimer = setTimeout(() => {
        if (this.buffer !== '\x1b' || this.destroyed) return;
        this.buffer = '';
        for (const handler of this.keyHandlers) handler(keyFromSequence('\x1b'));
      }, 50);
    }
  }
}

type ParsedToken = { type: 'key'; key: TuiKey } | { type: 'mouse'; event: TuiMouseEvent };

/**
 * Split terminal input into keys and SGR mouse events.
 *
 * `final=false` keeps incomplete escape sequences in `rest` so they can be
 * combined with the next chunk. `final=true` treats a trailing Escape as a key.
 */
export function parseTuiInput(
  input: string,
  final: boolean,
): { tokens: ParsedToken[]; rest: string } {
  const tokens: ParsedToken[] = [];
  let i = 0;

  while (i < input.length) {
    if (input[i] !== '\x1b') {
      const codePoint = input.codePointAt(i);
      if (codePoint === undefined) break;
      const sequence = String.fromCodePoint(codePoint);
      tokens.push({ type: 'key', key: keyFromSequence(sequence) });
      i += sequence.length;
      continue;
    }

    // SGR mouse: ESC [< button ; x ; y M/m
    if (input.startsWith('\x1b[<', i)) {
      // eslint-disable-next-line no-control-regex -- matching the ESC byte is the intent
      const match = /^\x1b\[<(\d+);(\d+);(\d+)([Mm])/.exec(input.slice(i));
      if (!match) break;
      tokens.push({ type: 'mouse', event: mouseFromSgr(match) });
      i += match[0].length;
      continue;
    }

    if (input[i + 1] === '[' || input[i + 1] === 'O') {
      const opener = input[i + 1];
      let end = i + 2;
      while (end < input.length) {
        const code = input.charCodeAt(end);
        const isFinal =
          opener === '[' ? code >= 0x40 && code <= 0x7e : code >= 0x41 && code <= 0x7e;
        if (isFinal) break;
        end += 1;
      }
      if (end >= input.length) break;
      const sequence = input.slice(i, end + 1);
      tokens.push({ type: 'key', key: keyFromSequence(sequence) });
      i = end + 1;
      continue;
    }

    // A lone ESC is the Escape key. Do not emit it yet if more input may arrive
    // and turn it into an escape sequence.
    if (i + 1 >= input.length) {
      if (!final) break;
      tokens.push({ type: 'key', key: keyFromSequence('\x1b') });
      i += 1;
      continue;
    }

    tokens.push({ type: 'key', key: keyFromSequence('\x1b') });
    i += 1;
  }

  return { tokens, rest: input.slice(i) };
}

const ARROW_NAMES: Record<string, string> = {
  A: 'up',
  B: 'down',
  C: 'right',
  D: 'left',
  H: 'home',
  F: 'end',
};

function keyFromSequence(sequence: string): TuiKey {
  const base: TuiKey = {
    name: sequence,
    sequence,
    ctrl: false,
    shift: false,
    meta: false,
  };

  if (sequence === '\x1b') return { ...base, name: 'escape' };
  if (sequence === '\r' || sequence === '\n') return { ...base, name: 'return' };
  if (sequence === '\x7f' || sequence === '\b') return { ...base, name: 'backspace' };
  if (sequence === '\t') return { ...base, name: 'tab' };

  if (sequence.startsWith('\x1b[')) {
    const body = sequence.slice(2);
    const exact = body.match(/^(\d+)?;?(\d+)?([A-Za-z~])$/);
    const final = body.slice(-1);
    if (ARROW_NAMES[final]) {
      const modifier = exact?.[2] ? Number(exact[2]) : 1;
      return {
        ...base,
        name: ARROW_NAMES[final],
        ctrl: modifier >= 5 && modifier <= 8,
        shift: modifier === 2 || modifier === 4 || modifier === 6 || modifier === 8,
      };
    }
    if (body === '3~') return { ...base, name: 'delete' };
    if (body === '5~') return { ...base, name: 'pageup' };
    if (body === '6~') return { ...base, name: 'pagedown' };
    if (body === '1~' || body === '7~') return { ...base, name: 'home' };
    if (body === '4~' || body === '8~') return { ...base, name: 'end' };
    return { ...base, name: `key-${body}` };
  }

  if (sequence.startsWith('\x1bO')) {
    const final = sequence.slice(-1);
    if (ARROW_NAMES[final]) return { ...base, name: ARROW_NAMES[final] };
    return { ...base, name: `key-${final}` };
  }

  const code = sequence.codePointAt(0) ?? 0;
  if (code < 32) {
    return {
      ...base,
      name: String.fromCharCode(code + 96),
      ctrl: true,
    };
  }
  if (code >= 65 && code <= 90) {
    return { ...base, name: sequence.toLowerCase(), shift: true };
  }
  return { ...base, name: sequence };
}

function mouseFromSgr(match: RegExpExecArray): TuiMouseEvent {
  const code = Number(match[1]);
  const x = Math.max(0, Number(match[2]) - 1);
  const y = Math.max(0, Number(match[3]) - 1);
  const pressed = match[4] === 'M';
  const motion = (code & 32) !== 0;
  const wheel = (code & 64) !== 0;
  const buttonBits = code & 3;

  let button: TuiMouseButton;
  if (wheel) button = buttonBits === 0 ? 'wheelUp' : 'wheelDown';
  else if (buttonBits === 0) button = 'left';
  else if (buttonBits === 1) button = 'middle';
  else button = 'right';

  const action: TuiMouseAction = !pressed ? 'up' : motion ? 'move' : 'down';
  return { x, y, button, action };
}

/** Wrap text on word boundaries, breaking overlong words when necessary. */
export function wrapTuiText(text: string, width: number): string[] {
  if (width <= 0) return [''];
  const rows: string[] = [];
  for (const paragraph of text.split('\n')) {
    let line = '';
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      if (visibleLength(line) === 0) {
        let rest = word;
        while (visibleLength(rest) > width) {
          rows.push(rest.slice(0, width));
          rest = rest.slice(width);
        }
        line = rest;
        continue;
      }
      if (visibleLength(line) + 1 + visibleLength(word) <= width) {
        line += ` ${word}`;
      } else {
        rows.push(line);
        line = word;
      }
    }
    rows.push(line);
  }
  return rows.length > 0 ? rows : [''];
}

/** Draw a reverse-video cursor character inside a text field. */
export function tuiCursorChar(char: string): string {
  return `\x1b[7m${char || ' '}\x1b[27m`;
}
