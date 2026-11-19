import { DEFAULTS } from '../protocol/constants';

/** Cells larger than this are replaced, not sent whole. */
const MAX_CELL_BYTES = DEFAULTS.MAX_CELL_BYTES;

export interface TruncationState {
  hasTruncated: boolean;
}

function byteLength(value: string | Buffer): number {
  return typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : value.length;
}

function truncate(value: string | Buffer): string {
  const suffix = '… [truncated]';
  if (typeof value === 'string') {
    const budget = Math.max(0, MAX_CELL_BYTES - Buffer.byteLength(suffix, 'utf8'));
    // Slice by characters first, then by bytes; a multi-byte character must not
    // be cut in half in a way that produces invalid UTF-8.
    let out = value.slice(0, budget);
    while (Buffer.byteLength(out, 'utf8') > budget) out = out.slice(0, -1);
    return out + suffix;
  }
  return `[binary ${String(value.length)} bytes, truncated]`;
}

/** Apply the per-cell presentation limit to one row. */
export function processRow(row: unknown[], state: TruncationState): unknown[] {
  return row.map((cell) => {
    if (typeof cell === 'string') {
      if (byteLength(cell) > MAX_CELL_BYTES) {
        state.hasTruncated = true;
        return truncate(cell);
      }
      return cell;
    }
    if (Buffer.isBuffer(cell)) {
      if (cell.length > MAX_CELL_BYTES) {
        state.hasTruncated = true;
        return truncate(cell);
      }
      return cell;
    }
    return cell;
  });
}

/** Approximate in-memory size of a row, used to bound a stream chunk. */
export function estimateRowBytes(row: unknown[]): number {
  let size = 0;
  for (const cell of row) {
    if (cell === null || cell === undefined) size += 4;
    else if (typeof cell === 'string') size += Buffer.byteLength(cell, 'utf8');
    else if (typeof cell === 'number') size += 8;
    else if (typeof cell === 'boolean') size += 1;
    else if (cell instanceof Date) size += 24;
    else if (Buffer.isBuffer(cell)) size += cell.length;
    else {
      try {
        size += Buffer.byteLength(JSON.stringify(cell), 'utf8');
      } catch {
        size += 64;
      }
    }
  }
  return size;
}
