function supportsUnicode(): boolean {
  if (process.env.SW_AGENT_ASCII === '1') return false;
  if (process.env.SW_AGENT_UNICODE === '1') return true;
  if (process.env.TERM === 'dumb') return false;
  if (process.platform !== 'win32') return true;

  return Boolean(
    process.env.WT_SESSION ||
    process.env.TERM_PROGRAM ||
    process.env.MSYSTEM ||
    process.env.ConEmuANSI === 'ON' ||
    process.env.TERM?.includes('xterm'),
  );
}

const unicode = supportsUnicode();

const unicodeSymbols = {
  check: '\u2713',
  cross: '\u2717',
  arrow: '\u2192',
  dot: '\u25cf',
  bullet: '\u2022',
  dash: '\u2500',
  dotSmall: '\u00b7',

  h: '\u2500',
  v: '\u2502',
  tl: '\u250c',
  tr: '\u2510',
  bl: '\u2514',
  br: '\u2518',
  t: '\u252c',
  b: '\u2534',
  l: '\u251c',
  r: '\u2524',
  crossBox: '\u253c',

  dh: '\u2550',
  dv: '\u2551',
  dtl: '\u2554',
  dtr: '\u2557',
  dbl: '\u255a',
  dbr: '\u255d',
  dt: '\u2566',
  db: '\u2569',
  dl: '\u2560',
  dr: '\u2563',

  right: '\u25b8',
  left: '\u25c2',
  up: '\u25b2',
  down: '\u25bc',
  rightThin: '\u203a',
  leftThin: '\u2039',

  ellipsis: '\u2026',
  info: '\u2139',
  warning: '\u26a0',
  gear: '\u2699',
  link: '\u26d3',
  play: '\u25b6',
  stop: '\u25a0',
  pause: '\u23f8',
  spinner: ['\u280b', '\u2819', '\u2839', '\u2838', '\u283c', '\u2834', '\u2826', '\u2827', '\u2807', '\u280f'],
};

const asciiSymbols = {
  check: 'v',
  cross: 'x',
  arrow: '->',
  dot: '*',
  bullet: '-',
  dash: '-',
  dotSmall: '.',

  h: '-',
  v: '|',
  tl: '+',
  tr: '+',
  bl: '+',
  br: '+',
  t: '+',
  b: '+',
  l: '+',
  r: '+',
  crossBox: '+',

  dh: '=',
  dv: '|',
  dtl: '+',
  dtr: '+',
  dbl: '+',
  dbr: '+',
  dt: '+',
  db: '+',
  dl: '+',
  dr: '+',

  right: '>',
  left: '<',
  up: '^',
  down: 'v',
  rightThin: '>',
  leftThin: '<',

  ellipsis: '...',
  info: 'i',
  warning: '!',
  gear: '*',
  link: '#',
  play: '>',
  stop: '#',
  pause: '||',
  spinner: ['-', '\\', '|', '/'],
};

export const S = unicode ? unicodeSymbols : asciiSymbols;
export const HAS_UNICODE = unicode;
