/**
 * Config errors and hand-rolled validators for machine and database config files.
 */

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
