import * as crypto from 'crypto';

const BASE62_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * Generates a cryptographically random agent token starting with swagt_ followed by 32 base62 characters.
 */
export function generateAgentToken(): string {
  let result = '';
  while (result.length < 32) {
    const bytes = crypto.randomBytes(1);
    const val = bytes[0];
    if (val < 248) {
      result += BASE62_CHARS[val % 62];
    }
  }
  return `swagt_${result}`;
}

/**
 * Validates the format of an agent token.
 * Returns true if it starts with "swagt_" and the body contains exactly 32 base62 characters.
 */
export function validateAgentTokenFormat(token: string): boolean {
  if (typeof token !== 'string') return false;
  if (!token.startsWith('swagt_')) return false;
  const body = token.slice(6);
  if (body.length !== 32) return false;
  return /^[a-zA-Z0-9]+$/.test(body);
}

/**
 * Generates an agent ID from the machine label and a random 8 hex char suffix.
 */
export function generateAgentId(machineLabel: string): string {
  const cleaned = machineLabel.replace(/[^a-zA-Z0-9_-]/g, '');
  const hex = crypto.randomBytes(4).toString('hex');
  return `agt_${cleaned}_${hex}`;
}

/**
 * Checks if the token is a special dev-mode token.
 */
export function isDevToken(token: string): boolean {
  return token === 'swagt_DEV_LOCAL_ONLY';
}
