import { C, alignAnsi, truncateAnsi, visibleLength } from './colors';
import { S } from './symbols';
import { terminalWidth } from './terminal';

interface BoxOptions {
  width?: number;
  padding?: number;
  title?: string;
  titleStyle?: (s: string) => string;
  style?: 'single' | 'double' | 'thin';
  borderColor?: (s: string) => string;
  align?: 'left' | 'center' | 'right';
}

export function box(content: string, opts: BoxOptions = {}): string {
  const { width, padding = 1, title, titleStyle = C.brand, style = 'single', borderColor = C.gray, align = 'left' } = opts;

  const lines = content.split('\n');
  const maxContentWidth = Math.max(...lines.map((l) => visibleLength(l)));
  const outerLimit = Math.max(24, terminalWidth() - 2);
  const requestedWidth = width ? Math.min(width, outerLimit) : Math.min(maxContentWidth + 2 + padding * 2, outerLimit);
  const innerWidth = Math.max(8, requestedWidth - 2 - padding * 2);
  const boxWidth = innerWidth + 2 + padding * 2;

  const chars = style === 'double' ? { h: S.dh, v: S.dv, tl: S.dtl, tr: S.dtr, bl: S.dbl, br: S.dbr } : { h: S.h, v: S.v, tl: S.tl, tr: S.tr, bl: S.bl, br: S.br };

  const topBorder = borderColor(`${chars.tl}${chars.h.repeat(boxWidth - 2)}${chars.tr}`);
  const bottomBorder = borderColor(`${chars.bl}${chars.h.repeat(boxWidth - 2)}${chars.br}`);

  const titleText = title ? truncateAnsi(title, Math.max(1, boxWidth - 6)) : '';
  const titleLine = title
    ? borderColor(`${chars.tl}${chars.h}${titleStyle(` ${titleText} `)}${chars.h.repeat(Math.max(0, boxWidth - 4 - visibleLength(titleText) - 2))}${chars.tr}`)
    : topBorder;
  const top = title ? titleLine : topBorder;

  const body = lines.map((line) => {
    const fitted = truncateAnsi(line, innerWidth, S.ellipsis);
    const aligned = alignAnsi(fitted, innerWidth, align);
    return `${borderColor(chars.v)}${' '.repeat(padding)}${aligned}${' '.repeat(padding)}${borderColor(chars.v)}`;
  });

  return [top, ...body, bottomBorder].join('\n');
}

export function divider(width: number, color: (s: string) => string = C.dim): string {
  return color(S.h.repeat(width));
}

export function separator(label?: string, width = 56): string {
  if (!label) return C.dim(S.h.repeat(width));
  const labelVisible = visibleLength(label);
  const remaining = width - labelVisible - 3;
  const left = Math.floor(remaining / 2);
  const right = remaining - left;
  return C.dim(S.h.repeat(left)) + ' ' + C.brand(label) + ' ' + C.dim(S.h.repeat(right));
}

export function indent(text: string, spaces = 2): string {
  return text.split('\n').map((l) => ' '.repeat(spaces) + l).join('\n');
}

export function bullet(text: string, color: (s: string) => string = C.cyan): string {
  return `${color(S.bullet)} ${text}`;
}

export function check(text: string): string {
  return `${C.green(S.check)} ${text}`;
}

export function cross(text: string): string {
  return `${C.red(S.cross)} ${text}`;
}

export function warn(text: string): string {
  return `${C.yellow(S.warning)} ${text}`;
}

export function info(text: string): string {
  return `${C.blue(S.info)} ${text}`;
}

export function arrow(text: string, color: (s: string) => string = C.cyan): string {
  return `${color(S.right)} ${text}`;
}
