import { C, truncateAnsi, visibleLength } from '../ui/colors';
import {
  createTuiScreen,
  setTuiActive,
  type TuiKey,
  type TuiMouseEvent,
  type TuiRegion,
  type TuiScreen,
} from './screen';

export interface ChoiceDialogOptions {
  /** Inject a screen for tests; production uses a real full-screen TTY. */
  screen?: TuiScreen;
}

export type ChoiceDialogResult =
  | { status: 'selected'; value: string }
  | { status: 'unavailable' };

/** Full-screen choice dialog: arrows, number keys and mouse clicks all work. */
export async function runChoiceDialog(
  question: string,
  choices: string[],
  defaultValue?: string,
  options: ChoiceDialogOptions = {},
): Promise<ChoiceDialogResult> {
  if (choices.length === 0) return { status: 'unavailable' };

  const screen = options.screen ?? createTuiScreen();
  if (!screen) return { status: 'unavailable' };

  const ownsScreen = !options.screen;
  if (ownsScreen) setTuiActive(true);

  return new Promise<ChoiceDialogResult>((resolve) => {
    const defaultIndex = defaultValue ? choices.indexOf(defaultValue) : -1;
    let selectedIndex = defaultIndex >= 0 ? defaultIndex : 0;
    let settled = false;
    let offKey: (() => void) | null = null;
    let offResize: (() => void) | null = null;

    const cleanup = (): boolean => {
      if (settled) return false;
      settled = true;
      offKey?.();
      offResize?.();
      if (ownsScreen) {
        setTuiActive(false);
        screen.destroy();
      }
      return true;
    };

    const finish = () => {
      if (!cleanup()) return;
      resolve({ status: 'selected', value: choices[selectedIndex] ?? choices[0] });
    };

    const cancel = () => {
      if (!cleanup()) return;
      process.exit(130);
    };

    const move = (delta: number) => {
      selectedIndex = (selectedIndex + delta + choices.length) % choices.length;
      render();
    };

    const onKey = (key: TuiKey) => {
      if (settled) return;
      if (key.name === 'up') move(-1);
      else if (key.name === 'down') move(1);
      else if (key.name === 'pageup') move(-Math.max(1, Math.floor(choices.length / 2)));
      else if (key.name === 'pagedown') move(Math.max(1, Math.floor(choices.length / 2)));
      else if (key.name === 'home') {
        selectedIndex = 0;
        render();
      } else if (key.name === 'end') {
        selectedIndex = choices.length - 1;
        render();
      } else if (/^[0-9]$/.test(key.name)) {
        const index = Number(key.name) - 1;
        if (index >= 0 && index < choices.length) {
          selectedIndex = index;
          render();
        }
      } else if (key.ctrl && key.name === 'c') {
        cancel();
      } else if (key.name === 'return' || key.name === 'escape') {
        finish();
      }
    };

    const render = () => {
      if (settled) return;
      const width = Math.max(40, screen.width);
      const height = Math.max(10, screen.height);
      const left = 2;
      const right = Math.max(20, width - 2);
      const lines: string[] = Array.from({ length: height }, () => '');
      const regions: TuiRegion[] = [];

      const put = (row: number, col: number, text: string) => {
        if (row < 0 || row >= height || col >= width) return;
        lines[row] = lines[row].padEnd(col, ' ') + truncateAnsi(text, width - col, '');
      };

      const region = (
        row: number,
        col: number,
        regionWidth: number,
        onClick?: (event: TuiMouseEvent) => void,
        onWheel?: (delta: number) => void,
      ) => {
        regions.push({
          rect: { x: col, y: row, width: regionWidth, height: 1 },
          onClick,
          onWheel,
        });
      };

      put(0, left, C.bold(C.white('Select')));
      put(2, left, C.bold(C.brightCyan(question)));

      const footerRow = height - 2;
      const bodyLimit = footerRow - 2;
      const maxRows = Math.max(1, Math.min(choices.length, bodyLimit - 4));
      const startIndex = Math.max(
        0,
        Math.min(selectedIndex - maxRows + 1, choices.length - maxRows),
      );

      for (let i = startIndex; i < startIndex + maxRows; i += 1) {
        const row = 4 + (i - startIndex);
        const selected = i === selectedIndex;
        const marker = selected ? C.brightCyan('›') : ' ';
        const name = selected ? C.brightCyan(choices[i]) : C.white(choices[i]);
        const suffix = choices[i] === defaultValue ? C.dim('  (default)') : '';
        put(row, left + 2, `${marker} ${C.dim(`${i + 1})`)} ${name}${suffix}`);
        region(
          row,
          left,
          right - left,
          (event) => {
            if (event.action === 'move') {
              if (selectedIndex !== i) {
                selectedIndex = i;
                render();
              }
              return;
            }
            selectedIndex = i;
            finish();
          },
          (delta) => move(delta),
        );
      }

      let offset = left;
      const action = (label: string, color: (text: string) => string, handler: () => void) => {
        put(footerRow, offset, color(label));
        region(footerRow, offset, visibleLength(label), (event) => {
          if (event.action !== 'move') handler();
        });
        offset += visibleLength(label) + 3;
      };
      action('enter select', C.brightCyan, finish);
      action('esc keep current', C.dim, finish);

      screen.render({ lines, regions });
    };

    offKey = screen.onKey(onKey);
    offResize = screen.onResize(render);
    render();
  });
}
