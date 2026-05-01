import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { timingSafeEqual } from './timing.js';

/**
 * HMAC-SHA256 over `data` with `key`. Returns a fresh 32-byte digest.
 *
 * @param key   Signing key (32 bytes recommended).
 * @param data  Bytes to authenticate.
 * @returns 32-byte HMAC digest.
 *
 * @example
 *   const tag = sign(sigKey, new TextEncoder().encode(sessionId));
 */
export function sign(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/**
 * Constant-time HMAC-SHA256 verification.
 *
 * @param key   Signing key.
 * @param data  Authenticated data.
 * @param tag   Tag to verify.
 * @returns `true` iff `tag` is the HMAC of `data` under `key`.
 *
 * @example
 *   if (!verify(sigKey, idBytes, tagBytes)) return null;
 */
export function verify(key: Uint8Array, data: Uint8Array, tag: Uint8Array): boolean {
  const expected = sign(key, data);
  return timingSafeEqual(expected, tag);
}

/**
 * Try every key in turn until one verifies the tag, or none does. Used
 * during secret rotation: new tags are signed with `keys[0]`, but old
 * tags signed with `keys[1..]` keep verifying for one expiration window.
 *
 * @param keys  Candidate keys, freshest first.
 * @param data  Authenticated data.
 * @param tag   Tag to verify.
 * @returns `true` iff any key verifies the tag.
 *
 * @example
 *   if (!verifyAny(allSigKeys, idBytes, tagBytes)) return null;
 */
export function verifyAny(
  keys: readonly Uint8Array[],
  data: Uint8Array,
  tag: Uint8Array,
): boolean {
  // Iterate every key for constant-time-ish behaviour: never short-circuit
  // on the first match, so timing does not reveal which key matched.
  let ok = false;
  for (const key of keys) {
    if (verify(key, data, tag)) ok = true;
  }
  return ok;
}
