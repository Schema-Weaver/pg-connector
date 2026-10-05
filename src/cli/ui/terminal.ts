import { visibleLength, truncateAnsi } from './colors';

export function terminalWidth(fallback = 80): number {
  const override = process.env.SW_AGENT_COLUMNS ? parseInt(process.env.SW_AGENT_COLUMNS, 10) : 0;
  if (Number.isFinite(override) && override >= 20) {
    return override;
  }
  const columns = process.stdout.columns;
  if (!columns || columns < 20) {
    return fallback;
  }
  return columns;
}

export function clampWidth(width: number, min: number, max = terminalWidth()): number {
  return Math.max(min, Math.min(width, max));
}

export function clearScreen(): void {
  process.stdout.write('\x1b[2J\x1b[3J\x1b[H');
}

export function clearLine(): void {
  process.stdout.write('\r\x1b[2K');
}

export function fitLine(line: string, width = terminalWidth()): string {
  if (visibleLength(line) <= width) {
    return line;
  }
  return truncateAnsi(line, Math.max(1, width));
}

export function indentLines(text: string, spaces = 2): string {
  const prefix = ' '.repeat(spaces);
  return text.split('\n').map((line) => prefix + line).join('\n');
}
