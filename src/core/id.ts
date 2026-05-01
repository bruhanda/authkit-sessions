import { randomBytes } from '../crypto/random.js';
import { base64urlEncode } from '../utils/base64url.js';

/** Session id length in bytes — 256 bits of randomness. */
const SESSION_ID_BYTES = 32;
/** Length of the encoded id (base64url, no padding) — 43 characters. */
export const SESSION_ID_LENGTH = 43;

/**
 * Generate a fresh, opaque session id — 32 cryptographically random
 * bytes encoded as a 43-character base64url string. Collision probability
 * is negligible (≈10⁻⁷⁰ at 1 billion sessions); the store still throws
 * `CONFLICT` on the off chance an id collides, so the manager falls back
 * to a single retry.
 *
 * @returns 43-character base64url session id.
 *
 * @example
 *   const id = generateSessionId();
 */
export function generateSessionId(): string {
  return base64urlEncode(randomBytes(SESSION_ID_BYTES));
}

/**
 * Generate a CSRF token. Same shape as a session id but with its own
 * random bytes so the two cannot be confused. Rotated alongside the
 * session id whenever `rotate()` runs.
 *
 * @returns 43-character base64url CSRF token.
 *
 * @example
 *   const token = generateCsrfToken();
 */
export function generateCsrfToken(): string {
  return base64urlEncode(randomBytes(SESSION_ID_BYTES));
}
