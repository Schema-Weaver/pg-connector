/**
 * Config errors and hand-rolled validators for machine and database config files.
 */

import { atomicWriteFile } from './atomic-write';

export class ConfigError extends Error {
  constructor(
    public code: 'not_found' | 'invalid' | 'write_failed',
    message: string,
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

export class ConfigInvalidError extends ConfigError {
  constructor(message: string) {
    super('invalid', message);
    this.name = 'ConfigInvalidError';
  }
}

export class ConfigNotFoundError extends ConfigError {
  constructor(path: string) {
    super('not_found', `Config file not found: ${path}`);
    this.name = 'ConfigNotFoundError';
  }
}

/**
 * Checks if a string is a valid hostname.
 */
export function isValidHostname(s: string): boolean {
  if (typeof s !== 'string') return false;
  if (s.length === 0 || s.length > 253) return false;
  const labelRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
  if (!s.includes('.')) {
    return labelRegex.test(s);
  }
  const labels = s.split('.');
  return labels.every((label) => labelRegex.test(label));
}

/**
 * Checks if a string is a valid IPv4 address.
 */
export function isValidIpv4(s: string): boolean {
  if (typeof s !== 'string') return false;
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255 && String(num) === part;
  });
}

/**
 * Checks if a string is a valid IPv6 address.
 */
export function isValidIpv6(s: string): boolean {
  if (typeof s !== 'string') return false;
  const ipv6Regex =
    /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,3}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,2}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Regex.test(s);
}

/**
 * Checks if a string is a valid environment variable name.
 */
export function isValidEnvVarName(s: string): boolean {
  if (typeof s !== 'string') return false;
  return /^[A-Z][A-Z0-9_]*$/.test(s);
}

/**
 * Checks if a string is a valid ISO 8601 timestamp.
 */
export function isValidIso8601(s: string): boolean {
  if (typeof s !== 'string') return false;
  const iso8601Regex = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
  if (!iso8601Regex.test(s)) return false;
  const d = new Date(s);
  return !isNaN(d.getTime());
}

/**
 * Checks if a string contains only letters, numbers, hyphens, and underscores, up to maxLen.
 */
export function isValidIdentifier(s: string, maxLen: number): boolean {
  if (typeof s !== 'string') return false;
  if (s.length === 0 || s.length > maxLen) return false;
  return /^[a-zA-Z0-9_-]+$/.test(s);
}

/** URL schemes accepted for transport that carries a bearer token. */
export type SecureScheme = 'wss:' | 'https:';

/** Schemes a cloud_url may use: wss anywhere, ws only on loopback. */
export type CloudScheme = 'wss:' | 'ws:';

/** Schemes a telemetry ingest URL may use: https anywhere, http only on loopback. */
export type IngestScheme = 'https:' | 'http:';

/** Longest cloud/telemetry URL accepted. */
const MAX_URL_LENGTH = 2048;

function hasControlOrSpace(raw: string): boolean {
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * True only for a loopback host literal.
 *
 * This is the gate that makes plaintext `ws://`/`http://` acceptable for a
 * local development relay without weakening the rule for anything reachable
 * over a network. `localhost` is included because that is how a developer
 * names the loopback interface; `127.0.0.0/8` and IPv6 `::1` are the literal
 * forms. A hostname that merely *resolves* to loopback is not accepted: DNS
 * can be changed after validation, so only literals are trusted.
 */
export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true;
  const match = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return false;
  return match.slice(1).every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

/**
 * Strictly parses a URL that is required to use `scheme` with an explicit
 * "//" authority separator.
 *
 * The scheme is matched against the raw string with a case-sensitive prefix
 * check *and* against the parsed URL, because the WHATWG parser normalises
 * several downgrade shapes that must be rejected: "WSS://host" lower-cases to
 * the "wss:" scheme, and "wss:/host" (single slash) is happily parsed as the
 * host. Either one alone would be a bypassable transport check.
 */
function parseUrlWithScheme(
  raw: unknown,
  scheme: SecureScheme | CloudScheme | IngestScheme,
): URL | null {
  if (typeof raw !== 'string') return null;
  const prefix = `${scheme}//`;
  if (raw.length < prefix.length + 1 || raw.length > MAX_URL_LENGTH) return null;
  if (hasControlOrSpace(raw)) return null;
  if (!raw.startsWith(prefix)) return null;
  // "wss:///host" parses as host "host": the authority must start immediately.
  if (raw[prefix.length] === '/') return null;

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }

  if (url.protocol !== scheme) return null;
  if (url.hostname.length === 0) return null;
  if (url.username.length > 0 || url.password.length > 0) return null;
  if (url.hostname.includes('..')) return null;
  return url;
}

export function parseSecureUrl(raw: unknown, scheme: SecureScheme): URL | null {
  return parseUrlWithScheme(raw, scheme);
}

/**
 * Parse a `cloud_url`.
 *
 * TLS is the default and the only thing accepted for a remote host. A plaintext
 * `ws://` URL is accepted only when its host is a loopback literal, so a local
 * backend on `ws://localhost:3000` works without a flag while a production
 * relay still cannot be downgraded.
 */
export function parseCloudUrl(raw: unknown): URL | null {
  const secure = parseUrlWithScheme(raw, 'wss:');
  if (secure) return secure;
  const plain = parseUrlWithScheme(raw, 'ws:');
  return plain && isLoopbackHost(plain.hostname) ? plain : null;
}

/**
 * Parse a telemetry ingest URL, with the same loopback-only plaintext exception
 * as {@link parseCloudUrl}.
 */
export function parseIngestUrl(raw: unknown): URL | null {
  const secure = parseUrlWithScheme(raw, 'https:');
  if (secure) return secure;
  const plain = parseUrlWithScheme(raw, 'http:');
  return plain && isLoopbackHost(plain.hostname) ? plain : null;
}

/**
 * True only for a wss: URL with an explicit lowercase "//" authority.
 * ws:, http:, WSS: and "wss:/x" are all rejected.
 */
export function isSecureCloudUrl(raw: unknown): boolean {
  return parseSecureUrl(raw, 'wss:') !== null;
}

/**
 * True for a wss:// URL, or a ws:// URL whose host is a loopback literal.
 */
export function isValidCloudUrl(raw: unknown): boolean {
  return parseCloudUrl(raw) !== null;
}

/**
 * True only for an https: URL with an explicit lowercase "//" authority.
 * http: is rejected.
 */
export function isSecureIngestUrl(raw: unknown): boolean {
  return parseSecureUrl(raw, 'https:') !== null;
}

/**
 * True for an https:// URL, or an http:// URL whose host is a loopback literal.
 */
export function isValidIngestUrl(raw: unknown): boolean {
  return parseIngestUrl(raw) !== null;
}

/**
 * Writes a config file atomically with the given owner-only mode: a
 * create-only mode option is not a control, so the mode is applied explicitly
 * to both the temporary file and, through the rename, the final file.
 */
export function writeConfigFileAtomic(filePath: string, contents: string, mode: number): void {
  atomicWriteFile(filePath, contents, mode);
}

/**
 * Redacts secret material from text that is about to be printed or logged.
 * Replaces each known secret and any URL userinfo password with "***".
 */
export function redactSecrets(text: string, ...secrets: (string | undefined)[]): string {
  let out = text.replace(/([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:@/\s]*:)[^@/\s]*@/g, '$1***@');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length > 0) {
      out = out.split(secret).join('***');
    }
  }
  return out;
}
