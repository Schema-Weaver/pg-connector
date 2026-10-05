import { stdin, stdout } from 'node:process';
import { C, visibleLength } from './ui/colors';
import { S } from './ui/symbols';

interface PaletteItem {
  command: string;
  desc: string;
}

interface PaletteResult {
  command: string;
  args: string[];
}

const PALETTE_MAX_VISIBLE = 8;
const PALETTE_WIDTH = 48;
const MOUSE_ENABLE = '\x1b[?1000h\x1b[?1002h\x1b[?1006h';
const MOUSE_DISABLE = '\x1b[?1006l\x1b[?1002l\x1b[?1000l';

function rank(query: string, item: PaletteItem): number {
  if (!query) return 0;
  const q = query.toLowerCase();
  const cmd = item.command.toLowerCase();
  const desc = item.desc.toLowerCase();

  const cmdIdx = cmd.indexOf(q);
  const descIdx = desc.indexOf(q);

  if (cmdIdx === 0) return -3; // exact prefix match on command
  if (cmdIdx >= 0) return -2;  // substring match on command
  if (descIdx === 0) return -1; // exact prefix match on description
  if (descIdx >= 0) return 0;   // substring match on description
  return 1; // no match
}

export async function showInlinePalette(
  items: PaletteItem[],
  _initialQuery: string
): Promise<PaletteResult | null> {
  return new Promise((resolve) => {
    let query = _initialQuery;
    let filtered = [...items];
    let selected = 0;
    let done = false;

    const getScreenWidth = (): number => stdout.columns || 80;

    const enableMouse = () => {
      stdout.write(MOUSE_ENABLE);
    };
    const disableMouse = () => {
      stdout.write(MOUSE_DISABLE);
    };

    const filter = () => {
      const q = query.toLowerCase();
      if (!q) {
        filtered = [...items];
      } else {
        filtered = items
          .filter((item) => rank(q, item) < 1)
          .sort((a, b) => rank(q, a) - rank(q, b));
      }
      selected = 0;
    };

    const dropdownWidth = (): number => Math.min(PALETTE_WIDTH, getScreenWidth() - 4);

    const drawDropdown = () => {
      const w = dropdownWidth();
      const visible = filtered.slice(0, PALETTE_MAX_VISIBLE);

      const lines: string[] = [];

      // Top border
      lines.push(C.cyan(S.tl) + C.cyan(S.h.repeat(w - 2)) + C.cyan(S.tr));

      // Items
      if (filtered.length === 0) {
        lines.push(C.cyan(S.v) + ' ' + C.dim('No matches') + ' '.repeat(w - 14) + C.cyan(S.v));
      } else {
        for (let i = 0; i < visible.length; i++) {
          const item = visible[i];
          const isSelected = i === selected;

          let line = '';
          line += C.cyan(S.v);

          if (isSelected) {
            line += ' ' + C.brand('▸') + ' ';
            line += C.brand(C.bold(item.command));
          } else {
            line += '   ';
            line += C.cyan(item.command);
          }

          const cmdLen = visibleLength(item.command);
          const padding = Math.max(0, 20 - cmdLen);
          line += ' '.repeat(padding);

          if (isSelected) {
            line += C.brand(item.desc);
          } else {
            line += C.dim(item.desc);
          }

          const descLen = visibleLength(item.desc);
          const rightPad = Math.max(0, w - 4 - padding - cmdLen - descLen);
          line += ' '.repeat(rightPad);
          line += C.cyan(S.v);
          lines.push(line);
        }
      }

      // Fill empty rows
      for (let i = visible.length; i < PALETTE_MAX_VISIBLE; i++) {
        lines.push(C.cyan(S.v) + ' '.repeat(w - 2) + C.cyan(S.v));
      }

      // Bottom border
      lines.push(C.cyan(S.bl) + C.cyan(S.h.repeat(w - 2)) + C.cyan(S.br));

      // Status line
      const status = filtered.length > 0
        ? `${selected + 1}/${filtered.length}  ${query ? 'filtered' : 'all'}`
        : '0/0';
      lines.push(C.dim('  ' + status + '   Enter=select  Esc=cancel  ↑↓=nav'));

      return lines;
    };

    const openDropdown = () => {
      stdout.write('\n');
      const lines = drawDropdown();
      for (const line of lines) {
        stdout.write(line + '\n');
      }
    };

    const closeDropdown = () => {
      const totalLines = PALETTE_MAX_VISIBLE + 3; // items + borders + status
      // Move cursor up to the top of the dropdown
      for (let i = 0; i < totalLines; i++) {
        stdout.write('\x1b[1A\x1b[K');
      }
    };

    const redraw = () => {
      closeDropdown();
      stdout.write('\n');
      const lines = drawDropdown();
      for (const line of lines) {
        stdout.write(line + '\n');
      }
    };

    const selectAndClose = () => {
      if (filtered.length > 0) {
        const item = filtered[selected];
        cleanup();
        resolve({ command: item.command, args: [] });
      }
    };

    const parseMouseEvent = (str: string): { action: string; y: number } | null => {
      const match = str.match(/^\x1b\[<(\d+);(\d+);(\d+)([Mm])/);
      if (!match) return null;
      const button = parseInt(match[1], 10);
      const y = parseInt(match[3], 10) - 1;
      let action = match[4] === 'M' ? 'press' : 'release';
      if (button & 64) {
        action = (button & 1) ? 'scroll_down' : 'scroll_up';
      }
      return { action, y };
    };

    const handleMouseClick = (y: number) => {
      // The dropdown starts at the line after the prompt. We need to figure out
      // which row was clicked. Since we don't know the absolute cursor position,
      // we approximate: the first item row is 1 line after the top border.
      // This is a simplified approach.
      const clickedIndex = y; // Approximate
      if (clickedIndex >= 0 && clickedIndex < Math.min(filtered.length, PALETTE_MAX_VISIBLE)) {
        selected = clickedIndex;
        selectAndClose();
      }
    };

    const onData = (chunk: Buffer) => {
      const str = chunk.toString('utf8');

      const mouseEvent = parseMouseEvent(str);
      if (mouseEvent) {
        if (mouseEvent.action === 'scroll_up') {
          selected = Math.max(0, selected - 1);
          redraw();
        } else if (mouseEvent.action === 'scroll_down') {
          selected = Math.min(filtered.length - 1, selected + 1);
          redraw();
        } else if (mouseEvent.action === 'press') {
          handleMouseClick(mouseEvent.y);
        }
        return;
      }

      if (str.startsWith('\x1b[')) {
        const code = str.slice(2);
        if (code === 'A') { selected = Math.max(0, selected - 1); redraw(); return; }
        if (code === 'B') { selected = Math.min(filtered.length - 1, selected + 1); redraw(); return; }
        return;
      }

      for (const ch of str) {
        const code = ch.charCodeAt(0);

        if (code === 3) { cleanup(); resolve(null); return; }
        if (code === 13 || code === 10) { selectAndClose(); return; }
        if (code === 27) { cleanup(); resolve(null); return; }
        if (code === 9) { selected = (selected + 1) % Math.max(1, filtered.length); redraw(); return; }
        if (code === 127 || code === 8) {
          if (query.length > 0) {
            query = query.slice(0, -1);
            filter();
            redraw();
          }
          return;
        }
        if (code >= 32 && code < 127) {
          query += ch;
          filter();
          redraw();
          return;
        }
      }
    };

    const cleanup = () => {
      if (done) return;
      done = true;
      stdin.removeListener('data', onData);
      closeDropdown();
      disableMouse();
    };

    filter();
    enableMouse();
    openDropdown();
    stdin.on('data', onData);
  });
}
