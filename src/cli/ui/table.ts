import { C, alignAnsi, stripAnsi, truncateAnsi, visibleLength } from './colors';
import { S } from './symbols';
import { terminalWidth } from './terminal';

export interface TableColumn<T> {
  key: string;
  header: string;
  align?: 'left' | 'right' | 'center';
  width?: number;
  minWidth?: number;
  maxWidth?: number;
  priority?: number;
  color?: (value: string, row: T) => string;
  formatter?: (value: unknown, row: T) => string;
  truncate?: boolean;
}

export interface TableOptions<T> {
  columns: TableColumn<T>[];
  headerStyle?: (s: string) => string;
  borderColor?: (s: string) => string;
  compact?: boolean;
  maxWidth?: number;
  cardWhenNarrow?: boolean;
}

interface ColumnMeta<T> {
  col: TableColumn<T>;
  index: number;
  preferred: number;
  min: number;
  width: number;
}

export function renderTable<T extends Record<string, unknown>>(rows: T[], opts: TableOptions<T>): string {
  if (rows.length === 0) return '';

  const maxWidth = Math.max(24, opts.maxWidth ?? terminalWidth());
  const columns = opts.columns.map((col, index) => ({ col, index }));
  const metas = columns.map(({ col, index }) => buildMeta(rows, col, index));
  const fitted = fitColumns(metas, maxWidth);

  if (opts.cardWhenNarrow !== false && (maxWidth < 52 || fitted.length <= 1)) {
    return renderCards(rows, opts.columns, opts);
  }

  const tableWidth = widthFor(fitted);
  if (tableWidth > maxWidth) {
    return renderCards(rows, opts.columns, opts);
  }

  return renderGrid(rows, fitted, opts);
}

function buildMeta<T extends Record<string, unknown>>(
  rows: T[],
  col: TableColumn<T>,
  index: number,
): ColumnMeta<T> {
  const headerLen = visibleLength(col.header);
  const dataMax = Math.max(
    0,
    ...rows.map((row) => visibleLength(formatValue(row, col))),
  );
  const natural = Math.max(headerLen, dataMax, col.key.length);
  const cappedNatural = col.maxWidth ? Math.min(natural, col.maxWidth) : natural;
  const preferred = Math.max(col.width ?? 0, col.minWidth ?? 0, cappedNatural, headerLen);
  const requestedMin = col.minWidth ?? Math.max(3, headerLen || 3);
  const hardMin = Math.max(3, Math.min(requestedMin, preferred));
  return {
    col,
    index,
    preferred,
    min: hardMin,
    width: preferred,
  };
}

function fitColumns<T>(metas: ColumnMeta<T>[], maxWidth: number): ColumnMeta<T>[] {
  let active = metas.map((meta) => ({ ...meta }));
  if (widthFor(active) <= maxWidth) {
    return active;
  }

  while (active.length > 2 && minWidthFor(active) > maxWidth) {
    const removable = [...active]
      .slice(1)
      .sort((a, b) => {
        const pa = a.col.priority ?? a.index + 1;
        const pb = b.col.priority ?? b.index + 1;
        if (pa !== pb) return pb - pa;
        return b.index - a.index;
      })[0];
    active = active.filter((meta) => meta !== removable);
  }

  let overflow = widthFor(active) - maxWidth;
  while (overflow > 0) {
    const shrinkable = active
      .filter((meta) => meta.width > meta.min)
      .sort((a, b) => (b.width - b.min) - (a.width - a.min))[0];
    if (!shrinkable) break;
    shrinkable.width -= 1;
    overflow -= 1;
  }

  while (widthFor(active) > maxWidth && active.length > 2) {
    const removable = [...active]
      .slice(1)
      .sort((a, b) => {
        const pa = a.col.priority ?? a.index + 1;
        const pb = b.col.priority ?? b.index + 1;
        if (pa !== pb) return pb - pa;
        return b.index - a.index;
      })[0];
    active = active.filter((meta) => meta !== removable);
  }

  return active;
}

function widthFor<T>(cols: ColumnMeta<T>[]): number {
  return cols.reduce((sum, col) => sum + col.width + 3, 1);
}

function minWidthFor<T>(cols: ColumnMeta<T>[]): number {
  return cols.reduce((sum, col) => sum + col.min + 3, 1);
}

function renderGrid<T extends Record<string, unknown>>(
  rows: T[],
  cols: ColumnMeta<T>[],
  opts: TableOptions<T>,
): string {
  const headerStyle = opts.headerStyle ?? C.bold;
  const borderColor = opts.borderColor ?? C.dim;
  const lines: string[] = [];

  lines.push(borderColor(S.tl + cols.map((c) => S.h.repeat(c.width + 2)).join(S.t) + S.tr));

  const headerCells = cols.map((meta) => {
    const text = truncateAnsi(meta.col.header, meta.width);
    return ' ' + headerStyle(alignAnsi(text, meta.width, meta.col.align ?? 'left')) + ' ';
  });
  lines.push(borderColor(S.v) + headerCells.join(borderColor(S.v)) + borderColor(S.v));

  lines.push(borderColor(S.l + cols.map((c) => S.h.repeat(c.width + 2)).join(S.crossBox) + S.r));

  for (const row of rows) {
    const cells = cols.map((meta) => {
      const raw = formatValue(row, meta.col);
      const display = truncateAnsi(raw, meta.width, S.ellipsis);
      const aligned = alignAnsi(display, meta.width, meta.col.align ?? 'left');
      const color = meta.col.color ? (s: string) => meta.col.color!(s, row) : (s: string) => s;
      return ' ' + color(aligned) + ' ';
    });
    lines.push(borderColor(S.v) + cells.join(borderColor(S.v)) + borderColor(S.v));
  }

  lines.push(borderColor(S.bl + cols.map((c) => S.h.repeat(c.width + 2)).join(S.b) + S.br));
  return lines.join('\n');
}

function renderCards<T extends Record<string, unknown>>(
  rows: T[],
  columns: TableColumn<T>[],
  opts: TableOptions<T>,
): string {
  const maxWidth = Math.max(24, opts.maxWidth ?? terminalWidth());
  const contentWidth = Math.max(18, maxWidth - 4);
  const labelWidth = Math.min(
    14,
    Math.max(...columns.map((col) => visibleLength(col.header || col.key)), 6),
  );
  const borderColor = opts.borderColor ?? C.dim;
  const lines: string[] = [];

  rows.forEach((row, rowIndex) => {
    if (rowIndex > 0) {
      lines.push(borderColor('  ' + S.h.repeat(Math.min(contentWidth, maxWidth - 2))));
    }

    for (const col of columns) {
      const label = truncateAnsi(col.header || col.key, labelWidth);
      const raw = formatValue(row, col);
      const valueWidth = Math.max(8, contentWidth - labelWidth - 2);
      const value = truncateAnsi(raw, valueWidth, S.ellipsis);
      lines.push(`  ${C.dim(alignAnsi(label, labelWidth, 'left'))}  ${value}`);
    }
  });

  return lines.join('\n');
}

function formatValue<T>(row: T, col: TableColumn<T>): string {
  const raw = (row as Record<string, unknown>)[col.key];
  if (col.formatter) {
    return col.formatter(raw, row);
  }
  if (raw === null || raw === undefined) return '-';
  if (typeof raw === 'boolean') return raw ? 'yes' : 'no';
  return String(raw);
}

export function renderSimpleTable(rows: string[][], headers?: string[]): string {
  if (rows.length === 0) return '';
  const numCols = rows[0].length;
  const colWidths = Array.from({ length: numCols }, (_, i) => {
    const headerLen = headers ? visibleLength(headers[i] || '') : 0;
    const dataLens = rows.map((row) => visibleLength(row[i] || ''));
    return Math.max(headerLen, ...dataLens);
  });

  const renderedRows = rows.map((row) => {
    return row.map((cell, i) => stripAnsi(cell).padEnd(colWidths[i])).join('  ');
  });

  if (!headers) return renderedRows.join('\n');

  const headerLine = headers.map((h, i) => h.padEnd(colWidths[i])).join('  ');
  const separator = colWidths.map((w) => S.h.repeat(w)).join('  ');
  return [C.bold(headerLine), C.dim(separator), ...renderedRows].join('\n');
}
