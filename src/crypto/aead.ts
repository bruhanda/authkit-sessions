import { gcm } from '@noble/ciphers/aes';
import { SessionError } from '../errors/base.js';
import { randomBytes } from './random.js';

/** AES-GCM nonce length (12 bytes / 96 bits — NIST-recommended for GCM). */
const NONCE_LEN = 12;

/**
 * Authenticated encryption with associated data (AEAD) using AES-256-GCM.
 *
 * The GCM tag IS the authentication — there is no separate HMAC layer.
 * `open` returns `null` on any failure (tampered ciphertext, wrong key,
 * invalid nonce); the constant-time path treats all failures
 * indistinguishably so an attacker cannot probe key state via timing.
 *
 * @param key        32-byte AES-256 key (from `deriveEncKey`).
 * @param plaintext  Bytes to encrypt.
 * @param aad        Optional associated data — authenticated but not encrypted.
 * @returns Concatenation of `nonce || ciphertext-with-tag`.
 *
 * @example
 *   const sealed = seal(encKey, new TextEncoder().encode('hello'));
 */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = aad ? gcm(key, nonce, aad) : gcm(key, nonce);
  const ciphertext = cipher.encrypt(plaintext);
  const out = new Uint8Array(NONCE_LEN + ciphertext.length);
  out.set(nonce, 0);
  out.set(ciphertext, NONCE_LEN);
  return out;
}

/**
 * Reverse of `seal`. Returns `null` on any authentication / decryption
 * failure — the manager treats that indistinguishably from a missing
 * cookie.
 *
 * @param key      32-byte AES-256 key.
 * @param sealed   Output of `seal` (nonce || ciphertext).
 * @param aad      Same `aad` as `seal`, or `undefined`.
 * @returns Decrypted plaintext, or `null` on tag mismatch.
 *
 * @example
 *   const pt = open(encKey, sealed);
 *   if (!pt) return null;
 */
export function open(key: Uint8Array, sealed: Uint8Array, aad?: Uint8Array): Uint8Array | null {
  if (sealed.length <= NONCE_LEN) return null;
  const nonce = sealed.subarray(0, NONCE_LEN);
  const ciphertext = sealed.subarray(NONCE_LEN);
  try {
    const cipher = aad ? gcm(key, nonce, aad) : gcm(key, nonce);
    return cipher.decrypt(ciphertext);
  } catch {
    return null;
  }
}

/**
 * Wrap any unexpected encryption failure as a typed `SessionError`. Used
 * by callers that want a stable error code; `seal` itself does not throw
 * because it controls every input.
 *
 * @internal
 */
export function wrapCryptoError(err: unknown): never {
  throw new SessionError('CONFIG_INVALID', 'AEAD operation failed', err);
}
