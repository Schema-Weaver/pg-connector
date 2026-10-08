import * as crypto from 'crypto';

const DIGIT = /[0-9]/;

/** Postgres duplicate-key detail: Key (email)=(alice@corp.com). */
const PG_KEY_VALUE_DETAIL = /=\(([^)]*)\)/g;

/**
 * Sentinel returned when a statement cannot be fully accounted for — an
 * unterminated literal, comment or dollar quote, or input larger than
 * {@link MAX_SQL_SCAN_BYTES}. Callers must treat it as "no redacted text
 * available" and emit this marker instead of any part of the statement.
 */
export const UNREDACTABLE = '/* unredactable */';

/** Character cap on a statement preview. */
export const PREVIEW_MAX_LENGTH = 200;

/** Alias for {@link PREVIEW_MAX_LENGTH}. */
export const PREVIEW_MAX_CHARS = PREVIEW_MAX_LENGTH;

/**
 * Byte cap on a statement preview. Character counting alone is not a size
 * bound — 200 characters can be 800 bytes of multi-byte UTF-8 — and preview
 * text is written to the local audit log *and* shipped to the cloud.
 */
export const PREVIEW_MAX_BYTES = 512;

/**
 * Hard ceiling on how much SQL a single redaction pass will lex. A statement
 * larger than this is reported unredactable rather than passed through.
 */
export const MAX_SQL_SCAN_BYTES = 1_048_576;

function isTagStart(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z_]/.test(ch);
}

function isTagChar(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9_]/.test(ch);
}

export type LexForm = 'string' | 'estring' | 'unicode_string' | 'dollar' | 'identifier';

export type LexToken =
  | { kind: 'text'; value: string }
  /** `value` is the raw source slice; `open` is the length of its opening delimiter. */
  | { kind: 'literal'; value: string; form: LexForm; open: number };

export interface LexResult {
  safe: boolean;
  reason?: string;
  tokens: LexToken[];
}

/**
 * Scans a PostgreSQL statement far enough to guarantee that every character
 * which could carry data is either SQL syntax or has been replaced.
 *
 * Every literal form is tracked: single quotes with doubled-quote escapes,
 * `E'...'` escape strings with backslash escapes, `U&'...'` unicode strings
 * with `\XXXX` / `\+XXXXXX` escapes, untagged and tagged dollar quotes, and
 * double-quoted identifiers including the `U&"..."` form. Both comment forms
 * are tracked too: line comments, which run to end of line and are never
 * continued by a backslash, and nestable block comments. `#` is not a comment
 * in PostgreSQL and is not treated as one here.
 *
 * The `E'…'` and `U&'…'` introducers count only when they are not glued to a
 * preceding identifier character, which is what PostgreSQL's scanner does: in
 * `xE'a\'b'` the identifier is `xE` and the quote opens an ordinary string whose
 * body is `a\`, and this lexer closes it at the same quote the server would.
 * The two quote characters are also kept apart: a `"` inside `'…'` is data, and
 * ending the literal on it would print the remainder of the statement as text.
 * Text outside a literal is left as it is — it is syntax and identifiers, and an
 * unquoted identifier can contain neither `@` nor `.`, so nothing the server
 * would accept as row data can reach the output through it. Quoted identifiers
 * *are* tokens, because PostgreSQL prints row values between double quotes.
 *
 * Anything the scan cannot account for reports `safe: false`, and the caller
 * must emit {@link UNREDACTABLE} rather than any part of the statement.
 */
export function lexSql(sql: string): LexResult {
  const tokens: LexToken[] = [];
  let text = '';
  const n = sql.length;
  let i = 0;

  const flush = (): void => {
    if (text.length > 0) {
      tokens.push({ kind: 'text', value: text });
      text = '';
    }
  };

  while (i < n) {
    const ch = sql[i];

    // Line comment: runs to end of line.
    if (ch === '-' && sql[i + 1] === '-') {
      const nl = sql.indexOf('\n', i + 2);
      i = nl === -1 ? n : nl;
      continue;
    }

    // Block comment: PostgreSQL nests these.
    if (ch === '/' && sql[i + 1] === '*') {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (sql[j] === '/' && sql[j + 1] === '*') {
          depth++;
          j += 2;
          continue;
        }
        if (sql[j] === '*' && sql[j + 1] === '/') {
          depth--;
          j += 2;
          if (depth === 0) break;
          continue;
        }
        j++;
      }
      if (depth !== 0) return { safe: false, reason: 'unterminated block comment', tokens: [] };
      i = j;
      continue;
    }

    // `U&'...'` unicode string and `U&"..."` unicode identifier. These are
    // lexed before the single-character cases because the introducer spans
    // three characters.
    if ((ch === 'U' || ch === 'u') && sql[i + 1] === '&' && !isIdentPart(sql[i - 1] ?? '')) {
      const quote = sql[i + 2];
      if (quote === "'" || quote === '"') {
        const r = lexSingleQuoted(sql, i + 2, true, quote);
        if (r.malformed) return { safe: false, reason: r.reason, tokens: [] };
        flush();
        tokens.push({
          kind: 'literal',
          value: sql.slice(i, r.end),
          form: quote === "'" ? 'unicode_string' : 'identifier',
          open: 3,
        });
        i = r.end;
        continue;
      }
    }

    // Escape-string literal: E'...' with backslash escapes. The introducer must
    // not be the tail of a longer identifier (`fooE'x'` is `foo` then a string).
    if ((ch === 'E' || ch === 'e') && sql[i + 1] === "'" && !isIdentPart(sql[i - 1] ?? '')) {
      const r = lexSingleQuoted(sql, i + 1, true, "'");
      if (r.malformed) return { safe: false, reason: r.reason, tokens: [] };
      flush();
      tokens.push({ kind: 'literal', value: sql.slice(i, r.end), form: 'estring', open: 2 });
      i = r.end;
      continue;
    }

    // Plain string literal: '...' with doubled-quote escapes.
    if (ch === "'") {
      const r = lexSingleQuoted(sql, i, false, "'");
      if (r.malformed) return { safe: false, reason: r.reason, tokens: [] };
      flush();
      tokens.push({ kind: 'literal', value: sql.slice(i, r.end), form: 'string', open: 1 });
      i = r.end;
      continue;
    }

    // Dollar quote: $$...$$ and $tag$...$tag$.
    if (ch === '$') {
      const r = lexDollarQuote(sql, i);
      if (r.malformed) return { safe: false, reason: r.reason, tokens: [] };
      if (r.end > i) {
        flush();
        tokens.push({ kind: 'literal', value: sql.slice(i, r.end), form: 'dollar', open: r.open });
        i = r.end;
        continue;
      }
      text += ch;
      i++;
      continue;
    }

    // Quoted identifier: "..." with doubled-quote escapes.
    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      if (j >= n) return { safe: false, reason: 'unterminated quoted identifier', tokens: [] };
      flush();
      tokens.push({ kind: 'literal', value: sql.slice(i, j + 1), form: 'identifier', open: 1 });
      i = j + 1;
      continue;
    }

    text += ch;
    i++;
  }

  flush();
  return { safe: true, tokens };
}

function isIdentPart(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z0-9_$]/.test(ch);
}

/** Matches untagged and tagged dollar-quote openers; `end === start` for `$1`-style placeholders. */
function lexDollarQuote(
  sql: string,
  start: number,
): { end: number; open: number; malformed: boolean; reason?: string } {
  const n = sql.length;
  let i = start + 1;
  if (sql[i] !== '$' && isTagStart(sql[i])) {
    while (i < n && isTagChar(sql[i])) i++;
  }
  if (sql[i] !== '$') {
    return { end: start, open: 0, malformed: false };
  }
  const tag = sql.slice(start, i + 1);
  const close = sql.indexOf(tag, i + 1);
  if (close === -1) {
    return { end: start, open: 0, malformed: true, reason: 'unterminated dollar quote' };
  }
  return { end: close + tag.length, open: tag.length, malformed: false };
}

/**
 * Scan a quoted run starting at the opening quote. `escape` enables backslash
 * handling for `E'...'` and `U&'...'`. `delim` is the character that closes the
 * run: the other quote character is ordinary data inside it (`'say "hi"'` is one
 * string), and treating it as a terminator would end the literal early and print
 * the rest of the statement as text.
 *
 * Returns the index just past the closing quote, or `start` with `malformed: true`
 * when unterminated.
 */
function lexSingleQuoted(
  sql: string,
  start: number,
  escape: boolean,
  delim: "'" | '"',
): { end: number; malformed: boolean; reason?: string } {
  const n = sql.length;
  let i = start + 1;
  while (i < n) {
    const ch = sql[i];
    if (escape && ch === '\\') {
      // E'..': \x escapes any x. U&'..': \XXXX, \+XXXXXX or \\.
      if (sql[i + 1] === '+' && /^[0-9A-Fa-f]{6}/.test(sql.slice(i + 2, i + 8))) {
        i += 8;
        continue;
      }
      if (/^[0-9A-Fa-f]{4}/.test(sql.slice(i + 1, i + 5))) {
        i += 5;
        continue;
      }
      if (i + 1 >= n) return { end: start, malformed: true, reason: 'unterminated string literal' };
      i += 2;
      continue;
    }
    if (ch === delim) {
      if (sql[i + 1] === delim) {
        i += 2; // doubled-quote escape
        continue;
      }
      return { end: i + 1, malformed: false };
    }
    i++;
  }
  return { end: start, malformed: true, reason: 'unterminated string literal' };
}

export interface RedactOptions {
  /**
   * Also replace `"..."` / `U&"..."` quoted identifiers with `?`.
   *
   * **On by default.** A double-quoted run carries row data just as often as it
   * carries a schema name: PostgreSQL reports rejected values that way
   * (`invalid input syntax for type integer: "alice@corp.com"`), and a statement
   * assembled from untrusted input can put anything between the quotes. The
   * preview is an audit record, so losing `"MySchema"` there costs readability
   * while keeping it costs an email address. Pass `false` only where the
   * identifier is known-good SQL that was not built from user input.
   */
  redactIdentifiers?: boolean;
  /** Apply the `Key (col)=(value)` -> `= (?)` pass. Default true. */
  redactKeyValues?: boolean;
}

/**
 * The default for {@link RedactOptions.redactIdentifiers}, and the default every
 * exported entry point uses.
 *
 * **On.** A double-quoted run is a schema name only when the statement really is
 * trusted SQL. It is also how PostgreSQL reports a rejected row value
 * (`invalid input syntax for type integer: "alice@corp.com"`), how a careless
 * developer labels a column (`SELECT 1 AS "alice@corp.com"`) and how a path is
 * smuggled (`COPY t TO '/tmp/"secret"'`). Previews exist for auditing and
 * fingerprinting, not for round-tripping or replay, so keeping an identifier
 * buys a readable schema name at the cost of an egress channel. Callers that
 * genuinely need identifiers pass `redactIdentifiers: false` explicitly.
 */
export const REDACT_IDENTIFIERS_BY_DEFAULT = true;

/**
 * Replaces the body of every literal token, keeping the delimiters intact.
 * Quoted identifiers are redacted unless `redactIdentifiers` is explicitly false.
 */
export function redactTokens(tokens: LexToken[], redactIdentifiers = true): string {
  let out = '';
  for (const t of tokens) {
    if (t.kind === 'text') {
      out += t.value;
      continue;
    }
    if (t.form === 'identifier' && !redactIdentifiers) {
      out += t.value;
      continue;
    }
    const close =
      t.form === 'dollar' ? t.value.slice(t.value.length - t.open) : t.value[t.value.length - 1];
    out += t.value.slice(0, t.open) + '?' + close;
  }
  return out;
}

/**
 * Characters that put the next token in an *operand* position, i.e. where a
 * column value is expected rather than a structural constant.
 */
const OPERAND_INTRODUCER = /[=<>!~@|&?*+\-/%^:,.([;]/;

/**
 * Replaces bare numeric literals that are not part of a word, identifier or
 * placeholder.
 *
 * A numeric literal is data unless it is a lone single digit standing in a
 * structural position — the `1` of `SELECT 1`, which cannot identify a row and
 * is noise rather than evidence. Everything else goes: any literal of two or
 * more characters (`12345`, `1.5e3`), and any single digit in an operand
 * position, which is where a compared value actually lives (`x = 1`,
 * `VALUES (1, 2)`, `IN (1, 2)`).
 */
export function redactNumbers(sql: string): string {
  let out = '';
  let i = 0;
  const n = sql.length;
  while (i < n) {
    const ch = sql[i];
    if (!DIGIT.test(ch)) {
      out += ch;
      i++;
      continue;
    }
    const prev = i > 0 ? sql[i - 1] : '';
    // Inside an identifier (`t1`), a positional parameter (`$1`) or a qualified
    // name (`schema.1`) the digits are part of a name, not a number.
    if (prev !== '' && /[A-Za-z0-9_$]/.test(prev)) {
      out += ch;
      i++;
      continue;
    }
    let j = i;
    while (j < n && DIGIT.test(sql[j])) j++;
    if (sql[j] === '.') {
      j++;
      while (j < n && DIGIT.test(sql[j])) j++;
    }
    if (sql[j] === 'e' || sql[j] === 'E') {
      let k = j + 1;
      if (sql[k] === '+' || sql[k] === '-') k++;
      if (k < n && DIGIT.test(sql[k])) {
        j = k;
        while (j < n && DIGIT.test(sql[j])) j++;
      }
    }
    const next = sql[j] ?? '';
    if (/[A-Za-z0-9_$]/.test(next)) {
      out += ch;
      i++;
      continue;
    }
    if (j === i + 1 && !operandPosition(out)) {
      // A bare single digit in a structural position: `SELECT 1`, `LIMIT 1`.
      out += ch;
      i = j;
      continue;
    }
    out += '?';
    i = j;
  }
  return out;
}

/**
 * True when the last non-blank character already emitted puts what follows in an
 * operand position. Blank characters are skipped so `x = 1` is an operand even
 * though the digit is separated from `=`.
 */
function operandPosition(emitted: string): boolean {
  for (let k = emitted.length - 1; k >= 0; k--) {
    const c = emitted[k];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') continue;
    return OPERAND_INTRODUCER.test(c);
  }
  return false;
}

/**
 * Replace data-bearing literals with placeholders.
 *
 * Preview text is shipped to the cloud audit store, so this is a zero-retention
 * boundary, not truncation. Dollar-quoted bodies, escape-string literals,
 * unicode strings, numeric literals, quoted identifiers and both comment forms
 * all have their contents removed unless `redactIdentifiers: false` is passed
 * explicitly. A statement that cannot be fully accounted for — an unterminated
 * construct, or more than {@link MAX_SQL_SCAN_BYTES} — returns
 * {@link UNREDACTABLE} and no part of the statement text.
 */
export function redactSqlLiterals(sql: string, opts: RedactOptions = {}): string {
  if (typeof sql !== 'string') return UNREDACTABLE;
  if (Buffer.byteLength(sql, 'utf8') > MAX_SQL_SCAN_BYTES) return UNREDACTABLE;
  const lexed = lexSql(sql);
  if (!lexed.safe) return UNREDACTABLE;
  const out = redactNumbers(redactTokens(lexed.tokens, opts.redactIdentifiers !== false));
  return opts.redactKeyValues === false ? out : out.replace(PG_KEY_VALUE_DETAIL, '= (?)');
}

/**
 * True when the value is {@link UNREDACTABLE} — no redacted text is available —
 * or empty. Both must be treated as "emit nothing": an empty preview is not
 * distinguishable from a dropped one in an audit record.
 */
export function isUnredactable(value: string | undefined | null): boolean {
  return typeof value !== 'string' || value === UNREDACTABLE || value.length === 0;
}

/**
 * Key for the identifier digest embedded in a statement fingerprint.
 *
 * Generated per process and never leaves it. An *unkeyed* digest would be a
 * confirmation oracle: an attacker holding the audit log could hash a
 * dictionary of guessed addresses and learn whether a statement used one, which
 * is exactly the leak {@link REDACT_IDENTIFIERS_BY_DEFAULT} exists to stop.
 *
 * The key is process-local, so fingerprints are stable within a run and differ
 * across restarts. That is the correct trade: the audit *chain* is what has to
 * survive a restart (it is anchored in `head.json`), while a fingerprint is a
 * grouping aid for one log file.
 */
const IDENTIFIER_DIGEST_KEY = crypto.randomBytes(32);

/**
 * Delimiters for the digest placeholder inside the fingerprint input. NUL
 * cannot occur in PostgreSQL text, so the placeholder can never be forged by
 * the input; the leading `x` keeps {@link redactNumbers} from reading the hex
 * digits of the digest as a numeric literal.
 */
const DIGEST_OPEN = '\u0000x';
const DIGEST_CLOSE = '\u0000';

function identifierDigest(body: string): string {
  return crypto
    .createHmac('sha256', IDENTIFIER_DIGEST_KEY)
    .update(body, 'utf8')
    .digest('hex')
    .slice(0, 16);
}

/**
 * The fingerprint input for a lexed statement: literal bodies become `?`,
 * because a value is not part of a statement's identity, while quoted
 * identifiers become a keyed digest.
 *
 * Identifiers must be distinguished even though they are redacted in the
 * preview: `SELECT * FROM "alpha"` and `SELECT * FROM "beta"` are different
 * statements, and collapsing them onto one fingerprint would hide a table
 * change behind a shared id. The digest is non-invertible and process-keyed, so
 * distinguishing them costs nothing.
 */
function fingerprintTokens(tokens: LexToken[]): string {
  let out = '';
  for (const t of tokens) {
    if (t.kind === 'text') {
      out += t.value;
      continue;
    }
    if (t.form === 'identifier') {
      out += `"${DIGEST_OPEN}${identifierDigest(t.value.slice(t.open, -1))}${DIGEST_CLOSE}"`;
      continue;
    }
    const close =
      t.form === 'dollar' ? t.value.slice(t.value.length - t.open) : t.value[t.value.length - 1];
    out += t.value.slice(0, t.open) + '?' + close;
  }
  return out;
}

/**
 * Stable id for "the same statement, whatever values were passed".
 *
 * Whitespace, letter case, comments and literal values are not part of a
 * statement's identity, so they are normalised away. Quoted identifiers are
 * *not* — they are structure, and see {@link fingerprintTokens}.
 *
 * A statement that cannot be redacted shares one fingerprint with every other
 * unredactable statement. That is deliberate: deriving the id from raw text
 * would put attacker-chosen bytes into a value that leaves the process.
 */
export function fingerprintStatement(sql: string): string {
  const lexed =
    typeof sql === 'string' && Buffer.byteLength(sql, 'utf8') <= MAX_SQL_SCAN_BYTES
      ? lexSql(sql)
      : { safe: false, tokens: [] as LexToken[] };
  const normalized = (
    lexed.safe ? redactNumbers(fingerprintTokens(lexed.tokens)) : UNREDACTABLE
  )
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/;\s*$/, '')
    .trim();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Redacted, character- and byte-capped preview for the audit record. Capping
 * happens after redaction so the cap can never split a redaction marker, and an
 * unredactable statement collapses to a fixed placeholder rather than any of its
 * text.
 */
export function previewStatement(sql: string): string {
  const redacted = redactSqlLiterals(typeof sql === 'string' ? sql.trim() : sql);
  if (redacted === UNREDACTABLE) return UNREDACTABLE;

  let out = sliceCodeUnits(redacted, PREVIEW_MAX_LENGTH);
  const buf = Buffer.from(out, 'utf8');
  if (buf.length > PREVIEW_MAX_BYTES) {
    let end = PREVIEW_MAX_BYTES;
    // Never split a UTF-8 sequence.
    while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
    out = sliceCodeUnits(buf.subarray(0, end).toString('utf8'), out.length);
  }
  return out === redacted ? out : out + '…';
}

/** Slice by UTF-16 code units without splitting a surrogate pair. */
function sliceCodeUnits(text: string, max: number): string {
  if (text.length <= max) return text;
  let end = max;
  if (end > 0) {
    const code = text.charCodeAt(end - 1);
    // A high surrogate at the cut means the pair is half-taken.
    if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  }
  return text.slice(0, end);
}
