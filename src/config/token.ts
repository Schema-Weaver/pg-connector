import * as crypto from 'crypto';
const { createHmac, timingSafeEqual } = crypto;

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
 * The only token accepted in place of a generated one, for local development
 * against a dev relay. It is not a credential: every caller must refuse to ship
 * it to the cloud (see {@link isDevToken}), because it authenticates nothing.
 */
export const DEV_TOKEN = 'swagt_DEV_LOCAL_ONLY';

/**
 * True when `token` is the local development token.
 *
 * Contract: accepts `unknown` so call sites reading a token out of a config
 * file, an env var or a cloud payload cannot pass a value the type system
 * claims is a string when it is not; anything that is not exactly
 * {@link DEV_TOKEN} — including an empty or absent token — is not a dev token.
 * This deliberately fails closed: a truthy answer must never mean "treat this
 * as authenticated".
 */
export function isDevToken(token: unknown): token is typeof DEV_TOKEN {
  return typeof token === 'string' && token === DEV_TOKEN;
}

/**
 * Domain-separation label for the relay-facing credential.
 *
 * Bumping this invalidates every derived credential, so it must stay stable
 * across releases and must never be reused for another purpose.
 */
export const RELAY_CREDENTIAL_LABEL = 'sw-agent/relay-auth/v1';

/**
 * Derive the credential actually transmitted to the relay.
 *
 * The agent keeps its `swagt_…` token locally and never puts it on the wire.
 * What travels is this derived value, so the long-lived master token does not
 * appear in proxy logs, TLS-terminating middleboxes, or `ps` output. The relay
 * derives the same value from the token it holds at pairing time and compares
 * digests, so it never needs to store a second secret.
 *
 * This is a transmission-hygiene measure, NOT an additional authentication
 * factor. The derived value is itself a bearer credential with the same
 * authority as the token it came from: anyone who captures it can
 * authenticate. Its value is that a leaked relay-side credential is scoped to
 * the relay and does not also yield the agent's master token for reuse against
 * other endpoints.
 *
 * @param token the locally-held agent token
 * @returns a lowercase hex digest, 64 characters
 */
export function deriveRelayCredential(token: string): string {
  return createHmac('sha256', token).update(RELAY_CREDENTIAL_LABEL, 'utf8').digest('hex');
}

/**
 * Constant-time comparison of two derived relay credentials.
 * Returns false rather than throwing on malformed input.
 */
export function relayCredentialsMatch(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length || bufA.length === 0) {
    // Still do the work so timing does not depend on which branch was taken.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}
