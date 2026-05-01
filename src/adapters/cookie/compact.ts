import { SessionError } from '../../errors/base.js';

/**
 * Hard ceiling on the encoded cookie value for browser-safe operation.
 *
 * Browser cookies have a per-cookie 4096-byte ceiling. We aim for a
 * conservative 3072 bytes by default, leaving headroom for cookie
 * attributes (`Path=/; Domain=...; Secure; HttpOnly; SameSite=Lax;
 * Max-Age=...`). The default can be overridden via `createCookieStore`
 * options, but increasing it past 4096 will break in real browsers.
 */
export const DEFAULT_COOKIE_MAX_BYTES = 3072;

/**
 * Validate a cookie envelope length. Throws `PAYLOAD_TOO_LARGE` rather
 * than silently truncating — a typo `data: { x: hugeBlob }` should fail
 * loudly, not wedge the user out.
 *
 * @param value     Encoded cookie envelope (base64url string).
 * @param maxBytes  Hard ceiling.
 * @throws {SessionError} `PAYLOAD_TOO_LARGE` when over the ceiling.
 *
 * @example
 *   guardCookieSize(sealed, 3072);
 */
export function guardCookieSize(value: string, maxBytes: number): void {
  if (value.length > maxBytes) {
    throw new SessionError(
      'PAYLOAD_TOO_LARGE',
      `cookie envelope is ${value.length} bytes; ceiling is ${maxBytes}`,
    );
  }
}
