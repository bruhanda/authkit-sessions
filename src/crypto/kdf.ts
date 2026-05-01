import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { SessionError } from '../errors/base.js';

/** Versioned `info` strings — bumping the suffix invalidates derived keys. */
const ENC_INFO = new TextEncoder().encode('sessions:enc:v1');
const SIG_INFO = new TextEncoder().encode('sessions:sig:v1');
const FP_INFO = new TextEncoder().encode('sessions:fingerprint:v1');

/** AES-256-GCM key length (32 bytes). */
const ENC_KEY_LEN = 32;
/** HMAC-SHA256 key length (32 bytes — full block). */
const SIG_KEY_LEN = 32;

/**
 * Validate a single secret carries ≥256 bits of entropy. The byte length
 * is a stand-in for entropy: a 32-byte random secret is the documented
 * minimum, anything shorter is rejected at construction time.
 *
 * @param secret  Secret to validate.
 * @throws {SessionError} `SECRET_TOO_SHORT` when below the floor.
 */
export function validateSecret(secret: Uint8Array): void {
  if (secret.length < 32) {
    throw new SessionError(
      'SECRET_TOO_SHORT',
      `secrets must carry >=256 bits of entropy; got ${secret.length} bytes after decoding`,
    );
  }
}

/**
 * Derive an AES-256-GCM key from the user secret using HKDF-SHA256.
 *
 * @param secret  Raw secret bytes (≥32 bytes).
 * @returns 32-byte AES-256 key.
 *
 * @example
 *   const encKey = deriveEncKey(secret);
 */
export function deriveEncKey(secret: Uint8Array): Uint8Array {
  return hkdf(sha256, secret, undefined, ENC_INFO, ENC_KEY_LEN);
}

/**
 * Derive an HMAC-SHA256 signing key for opaque session-id authentication
 * on stateful stores.
 *
 * @param secret  Raw secret bytes (≥32 bytes).
 * @returns 32-byte HMAC key.
 *
 * @example
 *   const sigKey = deriveSigKey(secret);
 */
export function deriveSigKey(secret: Uint8Array): Uint8Array {
  return hkdf(sha256, secret, undefined, SIG_INFO, SIG_KEY_LEN);
}

/**
 * Derive a fingerprint key — separate from the signing key so the
 * fingerprint device hash and the session-id signature never share the
 * same key schedule.
 *
 * @param secret  Raw secret bytes (≥32 bytes).
 * @returns 32-byte HMAC key.
 *
 * @example
 *   const fpKey = deriveFingerprintKey(secret);
 */
export function deriveFingerprintKey(secret: Uint8Array): Uint8Array {
  return hkdf(sha256, secret, undefined, FP_INFO, SIG_KEY_LEN);
}

/**
 * Coerce a string-or-bytes secret to its raw byte representation.
 * Strings are encoded as UTF-8 — entropy comes from the caller, not the
 * encoding.
 *
 * @param secret  String or `Uint8Array`.
 * @returns Raw bytes.
 *
 * @example
 *   const bytes = coerceSecret(process.env.SESSION_SECRET!);
 */
export function coerceSecret(secret: string | Uint8Array): Uint8Array {
  if (typeof secret === 'string') return new TextEncoder().encode(secret);
  return secret;
}
