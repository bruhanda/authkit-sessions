/**
 * Power-user re-exports of the crypto primitives backing the manager.
 * The session manager itself imports these files directly — this barrel
 * exists for advanced consumers who want to reuse the same audited
 * primitives (e.g. signing API tokens with the same secret).
 */
export { seal, open } from './aead.js';
export { sign, verify, verifyAny } from './hmac.js';
export {
  coerceSecret,
  deriveEncKey,
  deriveFingerprintKey,
  deriveSigKey,
  validateSecret,
} from './kdf.js';
export { randomBytes } from './random.js';
export { timingSafeEqual, timingSafeEqualString } from './timing.js';
