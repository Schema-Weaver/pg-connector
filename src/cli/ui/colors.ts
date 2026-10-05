/**
 * Modern UI color palette for SW Agent CLI.
 * Inspired by modern CLI tools (Vite, Claude Code, Cargo, etc.)
 */

const isTTY = Boolean(process.stdout.isTTY);
const colorsDisabled =
  process.env.NO_COLOR !== undefined ||
  process.env.SW_AGENT_NO_COLOR === '1' ||
  process.env.TERM === 'dumb';

function wrap(c: string): (s: string) => string {
  return (s: string) => isTTY && !colorsDisabled ? `\x1b[${c}m${s}\x1b[0m` : s;
}

export const C = {
  // Reset
  reset: '\x1b[0m',

  // Primary palette
  green: wrap('32'),          // Success, checkmarks
  brightGreen: wrap('92'),    // Highlighted success
  cyan: wrap('36'),           // Info, links, paths
  brightCyan: wrap('96'),    // Brand accent
  yellow: wrap('33'),         // Warnings
  brightYellow: wrap('93'),  // Attention
  red: wrap('31'),            // Errors
  brightRed: wrap('91'),     // Fatal errors
  blue: wrap('34'),           // Labels, metadata
  brightBlue: wrap('94'),    // Secondary accent
  magenta: wrap('35'),       // Special state
  brightMagenta: wrap('95'), // Highlight
  gray: wrap('90'),          // Muted, dim, timestamps
  white: wrap('37'),         // Normal text
  brightWhite: wrap('97'),   // Emphasized text

  // Styles
  dim: wrap('2'),
  bold: wrap('1'),
  italic: wrap('3'),
  underline: wrap('4'),
  strikethrough: wrap('9'),

  // Backgrounds
  bgGreen: wrap('42'),
  bgCyan: wrap('46'),
  bgYellow: wrap('43'),
  bgRed: wrap('41'),
  bgGray: wrap('100'),

  // Brand colors
  brand: wrap('96'),        // Schema Weaver cyan
  accent: wrap('94'),       // Secondary blue
};

export function bold(text: string): string { return C.bold(text); }
export function dim(text: string): string { return C.dim(text); }
export function green(text: string): string { return C.green(text); }
export function brightGreen(text: string): string { return C.brightGreen(text); }
export function cyan(text: string): string { return C.cyan(text); }
export function brightCyan(text: string): string { return C.brightCyan(text); }
export function yellow(text: string): string { return C.yellow(text); }
export function brightYellow(text: string): string { return C.brightYellow(text); }
export function red(text: string): string { return C.red(text); }
export function brightRed(text: string): string { return C.brightRed(text); }
export function blue(text: string): string { return C.blue(text); }
export function gray(text: string): string { return C.gray(text); }
export function white(text: string): string { return C.white(text); }
export function brightWhite(text: string): string { return C.brightWhite(text); }
export function magenta(text: string): string { return C.magenta(text); }
export function brand(text: string): string { return C.brand(text); }
export function accent(text: string): string { return C.accent(text); }

export function stripAnsi(str: string): string {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');
}

export function visibleLength(str: string): number {
  return stripAnsi(str).length;
}

export function padAnsi(str: string, totalWidth: number): string {
  const visible = visibleLength(str);
  if (visible >= totalWidth) return str;
  return str + ' '.repeat(totalWidth - visible);
}

export function alignAnsi(
  str: string,
  totalWidth: number,
  align: 'left' | 'right' | 'center' = 'left',
): string {
  const visible = visibleLength(str);
  if (visible >= totalWidth) return str;
  const pad = totalWidth - visible;
  if (align === 'right') return ' '.repeat(pad) + str;
  if (align === 'center') {
    const left = Math.floor(pad / 2);
    return ' '.repeat(left) + str + ' '.repeat(pad - left);
  }
  return str + ' '.repeat(pad);
}

export function truncateAnsi(str: string, maxWidth: number, suffix = '...'): string {
  if (maxWidth <= 0) return '';
  if (visibleLength(str) <= maxWidth) return str;

  const suffixWidth = visibleLength(suffix);
  if (maxWidth <= suffixWidth) {
    return suffix.slice(0, maxWidth);
  }

  let output = '';
  let visible = 0;
  let sawAnsi = false;
  const limit = maxWidth - suffixWidth;

  for (let i = 0; i < str.length;) {
    if (str[i] === '\x1b') {
      const match = /^\x1b\[[0-9;?]*[ -/]*[@-~]/.exec(str.slice(i));
      if (match) {
        output += match[0];
        i += match[0].length;
        sawAnsi = true;
        continue;
      }
    }

    const codePoint = str.codePointAt(i);
    if (codePoint === undefined) break;
    const char = String.fromCodePoint(codePoint);
    if (visible + 1 > limit) break;
    output += char;
    visible += 1;
    i += char.length;
  }

  return output + suffix + (sawAnsi ? C.reset : '');
}
