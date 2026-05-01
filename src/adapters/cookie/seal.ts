import { open, seal } from '../../crypto/aead.js';
import { decodeRecord, encodeRecord } from '../../core/encoder.js';
import { base64urlDecode, base64urlEncode } from '../../utils/base64url.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

/**
 * AEAD-seal a session record into a cookie-safe string.
 *
 * The plaintext is the JSON+base64url envelope (`encodeRecord`); the
 * sealed output is `base64url(nonce || ciphertext-with-tag)`. The GCM
 * tag IS the authentication — there is no separate HMAC layer.
 *
 * @param record  Record to seal.
 * @param key     32-byte AES-256-GCM key (from `deriveEncKey`).
 * @returns base64url-encoded sealed envelope.
 *
 * @example
 *   const cookieValue = sealRecord(record, encKey);
 */
export function sealRecord<T extends SessionData>(
  record: SessionRecord<T>,
  key: Uint8Array,
): string {
  const plaintext = new TextEncoder().encode(encodeRecord(record));
  const sealed = seal(key, plaintext);
  return base64urlEncode(sealed);
}

/**
 * Reverse of `sealRecord`. Tries each candidate key in turn so that
 * secret rotation is non-disruptive — new cookies are sealed with the
 * active key, old cookies remain decryptable until they age out.
 *
 * @typeParam T  Expected payload shape.
 * @param value  Cookie value as produced by `sealRecord`.
 * @param keys   Candidate keys, freshest first.
 * @returns Decoded record, or `null` on any failure.
 *
 * @example
 *   const record = openRecord<MySession>(cookie, [activeKey, ...rotated]);
 */
export function openRecord<T extends SessionData>(
  value: string,
  keys: readonly Uint8Array[],
): SessionRecord<T> | null {
  let raw: Uint8Array;
  try {
    raw = base64urlDecode(value);
  } catch {
    return null;
  }
  for (const key of keys) {
    const plaintext = open(key, raw);
    if (!plaintext) continue;
    const decoded = decodeRecord<T>(new TextDecoder().decode(plaintext));
    if (decoded) return decoded;
  }
  return null;
}
