import { stdin, stdout } from 'node:process';
import { AuditEvent } from '../../audit/types';
import { AuditLogFilter, readAuditEvents } from '../../audit/files';
import {
  DECISION_COLOR,
  OUTCOME_COLOR,
  relativeTime,
  renderEventDetailLines,
} from './format';
import {
  C,
  S,
  alignAnsi,
  fitLine,
  terminalWidth,
  truncateAnsi,
  visibleLength,
} from '../ui';

interface ViewerOptions {
  auditDir: string;
  initialFilter?: AuditLogFilter;
}

export class InteractiveLogViewer {
  private auditDir: string;
  private filter: AuditLogFilter;
  private events: AuditEvent[] = [];
  private selectedIndex = 0;
  private scrollOffset = 0;

  private isRunning = true;
  private isSearching = false;
  private searchBuffer = '';
  private modalEvent: AuditEvent | null = null;
  private modalScroll = 0;

  private renderedLines = 0;
  private resizeTimer: ReturnType<typeof setTimeout> | null = null;
  private resolve!: () => void;

  private readonly onDataBound = this.onKey.bind(this);
  private readonly onResizeBound = this.onResize.bind(this);

  constructor(opts: ViewerOptions) {
    this.auditDir = opts.auditDir;
    this.filter = {
      order: 'desc',
      limit: 200,
      ...opts.initialFilter,
    };
    if (this.filter.search) {
      this.searchBuffer = this.filter.search;
    }
  }

  async run(): Promise<void> {
    await this.reloadEvents();

    if (!stdin.isTTY) {
      // Fallback for non-TTY
      return;
    }

    stdout.write('\x1b[?25l'); // hide cursor
    try {
      stdin.setRawMode(true);
    } catch {
      // ignore
    }
    stdin.resume();
    stdin.on('data', this.onDataBound);
    stdout.on('resize', this.onResizeBound);

    this.render();

    return new Promise<void>((resolve) => {
      this.resolve = resolve;
    });
  }

  private async reloadEvents(): Promise<void> {
    const events = await readAuditEvents(this.auditDir, this.filter);
    this.events = events;
    if (this.selectedIndex >= this.events.length) {
      this.selectedIndex = Math.max(0, this.events.length - 1);
    }
    this.adjustScroll();
  }

  private onResize() {
    if (this.resizeTimer) clearTimeout(this.resizeTimer);
    this.resizeTimer = setTimeout(() => this.render(), 40);
  }

  private onKey(chunk: Buffer) {
    if (!this.isRunning) return;
    const tokens = splitInput(chunk.toString('utf8'));
    for (const token of tokens) {
      this.handleToken(token);
    }
    this.render();
  }

  private handleToken(token: string) {
    // Ctrl+C
    if (token === '\x03') {
      this.shutdown();
      return;
    }

    // Modal view active
    if (this.modalEvent) {
      if (
        token === '\r' ||
        token === '\n' ||
        token === '\x1b' ||
        token === 'q' ||
        token === ' '
      ) {
        this.modalEvent = null;
        this.modalScroll = 0;
        return;
      }
      if (token === '\x1b[A' || token === 'k') {
        this.modalScroll = Math.max(0, this.modalScroll - 1);
        return;
      }
      if (token === '\x1b[B' || token === 'j') {
        this.modalScroll += 1;
        return;
      }
      return;
    }

    // Search input active
    if (this.isSearching) {
      if (token === '\r' || token === '\n') {
        this.isSearching = false;
        this.filter.search = this.searchBuffer.trim() || undefined;
        void this.reloadEvents().then(() => this.render());
        return;
      }
      if (token === '\x1b') {
        // Cancel search
        this.isSearching = false;
        this.searchBuffer = this.filter.search || '';
        return;
      }
      if (token === '\x7f' || token === '\b') {
        if (this.searchBuffer.length > 0) {
          this.searchBuffer = this.searchBuffer.slice(0, -1);
        }
        return;
      }
      if (/^[ -~]$/.test(token)) {
        this.searchBuffer += token;
        return;
      }
      return;
    }

    // Normal browsing mode
    if (token === 'q' || token === '\x1b') {
      this.shutdown();
      return;
    }

    if (token === '\r' || token === '\n' || token === ' ') {
      if (this.events[this.selectedIndex]) {
        this.modalEvent = this.events[this.selectedIndex];
        this.modalScroll = 0;
      }
      return;
    }

    // Navigation
    if (token === '\x1b[A' || token === 'k') {
      this.moveSelection(-1);
      return;
    }
    if (token === '\x1b[B' || token === 'j') {
      this.moveSelection(1);
      return;
    }
    if (token === '\x1b[5~') {
      // PageUp
      this.moveSelection(-10);
      return;
    }
    if (token === '\x1b[6~') {
      // PageDown
      this.moveSelection(10);
      return;
    }
    if (token === '\x1b[H' || token === 'g') {
      // Home
      this.selectedIndex = 0;
      this.adjustScroll();
      return;
    }
    if (token === '\x1b[F' || token === 'G') {
      // End
      this.selectedIndex = Math.max(0, this.events.length - 1);
      this.adjustScroll();
      return;
    }

    // Search prompt toggle
    if (token === '/') {
      this.isSearching = true;
      return;
    }

    // Decision toggle: all -> deny -> allow -> pending -> all
    if (token === 'd') {
      const states = [undefined, 'deny', 'allow', 'pending'];
      const curIdx = states.indexOf(this.filter.decision);
      this.filter.decision = states[(curIdx + 1) % states.length];
      void this.reloadEvents().then(() => this.render());
      return;
    }

    // Outcome toggle: all -> error -> success -> cancelled -> all
    if (token === 'o') {
      const states = [undefined, 'error', 'success', 'cancelled'];
      const curIdx = states.indexOf(this.filter.outcome);
      this.filter.outcome = states[(curIdx + 1) % states.length];
      void this.reloadEvents().then(() => this.render());
      return;
    }

    // Sort order toggle: desc (newest) <-> asc (oldest)
    if (token === 's') {
      this.filter.order = this.filter.order === 'asc' ? 'desc' : 'asc';
      void this.reloadEvents().then(() => this.render());
      return;
    }

    // Refresh
    if (token === 'r') {
      void this.reloadEvents().then(() => this.render());
      return;
    }

    // Clear search
    if (token === 'c') {
      this.filter.search = undefined;
      this.searchBuffer = '';
      this.filter.decision = undefined;
      this.filter.outcome = undefined;
      void this.reloadEvents().then(() => this.render());
      return;
    }
  }

  private moveSelection(delta: number) {
    if (this.events.length === 0) return;
    this.selectedIndex = Math.max(0, Math.min(this.events.length - 1, this.selectedIndex + delta));
    this.adjustScroll();
  }

  private adjustScroll() {
    const visibleCount = this.visibleRowCount();
    if (this.selectedIndex < this.scrollOffset) {
      this.scrollOffset = this.selectedIndex;
    } else if (this.selectedIndex >= this.scrollOffset + visibleCount) {
      this.scrollOffset = this.selectedIndex - visibleCount + 1;
    }
  }

  private visibleRowCount(): number {
    const termHeight = process.stdout.rows || 24;
    // Reserve lines for header (4 lines) and footer (3 lines)
    return Math.max(5, termHeight - 7);
  }

  private render() {
    this.clearRenderedBlock();

    const width = Math.max(40, terminalWidth());
    const lines: string[] = [];

    if (this.modalEvent) {
      // Modal view
      const detailLines = renderEventDetailLines(this.modalEvent, width);
      const termHeight = process.stdout.rows || 24;
      const visibleHeight = Math.max(10, termHeight - 2);
      const slice = detailLines.slice(this.modalScroll, this.modalScroll + visibleHeight);

      lines.push(...slice);
    } else {
      // Main browser view
      lines.push(...this.renderHeader(width));
      lines.push(...this.renderTableHeader(width));
      lines.push(...this.renderTableRows(width));
      lines.push(...this.renderFooter(width));
    }

    for (const line of lines) {
      stdout.write(fitLine(line, width) + '\n');
    }
    this.renderedLines = lines.length;
  }

  private renderHeader(width: number): string[] {
    const isNewest = this.filter.order !== 'asc';
    const sortLabel = isNewest ? 'Newest First ▾' : 'Oldest First ▴';

    const filtersActive: string[] = [];
    if (this.filter.project) filtersActive.push(`Proj:${C.cyan(this.filter.project)}`);
    if (this.filter.user) filtersActive.push(`User:${C.cyan(this.filter.user)}`);
    if (this.filter.decision) filtersActive.push(`Dec:${C.bold(this.filter.decision)}`);
    if (this.filter.outcome) filtersActive.push(`Out:${C.bold(this.filter.outcome)}`);
    if (this.filter.search) filtersActive.push(`Query:"${C.yellow(this.filter.search)}"`);

    const filterText = filtersActive.length > 0 ? ` [${filtersActive.join(' ')}]` : '';
    const left = ` ${C.bold(C.brand('SW AUDIT LOGS'))}  ${C.dim(sortLabel)}${filterText}`;
    const count = this.events.length > 0 ? `${this.selectedIndex + 1}/${this.events.length}` : '0/0';
    const right = `${C.dim('Count:')} ${C.white(count)} `;

    const padding = Math.max(0, width - visibleLength(left) - visibleLength(right));
    const titleLine = left + ' '.repeat(padding) + right;

    let searchLine = '';
    if (this.isSearching) {
      searchLine = `  ${C.brand('Search:')} ${C.white(this.searchBuffer)}${C.brand('█')}  ${C.dim('(Enter to apply, Esc to cancel)')}`;
    }

    return searchLine ? [titleLine, searchLine] : [titleLine];
  }

  private renderTableHeader(width: number): string[] {
    const h = [
      ' ', // marker
      'WHEN'.padEnd(14),
      'AGE'.padEnd(6),
      'PROJECT'.padEnd(16),
      'USER'.padEnd(16),
      'ACTION'.padEnd(14),
      'DECISION'.padEnd(10),
      'OUTCOME'.padEnd(10),
      'TIME'.padEnd(7),
      'SQL PREVIEW',
    ].join(' ');

    return [
      C.dim(truncateAnsi(h, width)),
      C.dim(S.h.repeat(Math.min(width, 140))),
    ];
  }

  private renderTableRows(width: number): string[] {
    const visibleCount = this.visibleRowCount();
    const slice = this.events.slice(this.scrollOffset, this.scrollOffset + visibleCount);
    const lines: string[] = [];

    if (this.events.length === 0) {
      lines.push(`  ${C.yellow(S.warning)} No audit logs match the current filters.`);
      for (let i = 1; i < visibleCount; i++) {
        lines.push('');
      }
      return lines;
    }

    for (let i = 0; i < visibleCount; i++) {
      const event = slice[i];
      if (!event) {
        lines.push('');
        continue;
      }

      const globalIdx = this.scrollOffset + i;
      const isSelected = globalIdx === this.selectedIndex;

      const marker = isSelected ? C.brand(S.right) : ' ';
      const when = event.ts.slice(5, 19).replace('T', ' ').padEnd(14);
      const age = relativeTime(event.ts).padEnd(6);
      const project = truncateAnsi(event.project, 16).padEnd(16);
      const user = truncateAnsi(event.user_id, 16).padEnd(16);
      const action = truncateAnsi(event.action, 14).padEnd(14);

      const decColor = DECISION_COLOR[event.decision] ?? C.white;
      const decision = alignAnsi(decColor(event.decision), 10);

      const outColor = OUTCOME_COLOR[event.outcome] ?? C.white;
      const outcome = alignAnsi(outColor(event.outcome), 10);

      const ms = (event.duration_ms !== undefined ? `${event.duration_ms}ms` : '-').padStart(6);
      const preview = (event.statement_preview ?? '-').replace(/[\r\n\t]+/g, ' ');

      let rowText = `${marker} ${when} ${C.dim(age)} ${C.cyan(project)} ${C.dim(user)} ${action} ${decision} ${outcome} ${C.dim(ms)}  ${preview}`;

      if (isSelected) {
        rowText = C.bold(rowText);
      }

      lines.push(truncateAnsi(rowText, width));
    }

    return lines;
  }

  private renderFooter(width: number): string[] {
    const controls = [
      `${C.cyan('↑↓/jk')} Navigate`,
      `${C.cyan('Enter')} Details`,
      `${C.cyan('/')} Search`,
      `${C.cyan('d')} Decision`,
      `${C.cyan('o')} Outcome`,
      `${C.cyan('s')} Sort`,
      `${C.cyan('c')} Reset`,
      `${C.cyan('q')} Exit`,
    ].join('  ');

    return [
      C.dim(S.h.repeat(Math.min(width, 140))),
      C.dim('  ' + truncateAnsi(controls, width - 4)),
    ];
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
    this.isRunning = false;
    stdin.off('data', this.onDataBound);
    stdout.off('resize', this.onResizeBound);
    if (this.resizeTimer) clearTimeout(this.resizeTimer);

    try {
      stdin.setRawMode(false);
    } catch {
      // ignore
    }
    stdout.write('\x1b[?25h'); // restore cursor
    this.resolve();
  }
}

export async function startLogViewer(opts: ViewerOptions): Promise<void> {
  const viewer = new InteractiveLogViewer(opts);
  return viewer.run();
}

function splitInput(input: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < input.length; ) {
    if (input[i] === '\x1b') {
      // eslint-disable-next-line no-control-regex -- matching ANSI escape sequences is the intent
      const match = /^\x1b\[[0-9;]*[~A-Za-z]/.exec(input.slice(i));
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
