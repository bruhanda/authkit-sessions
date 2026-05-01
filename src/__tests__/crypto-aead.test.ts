import { describe, expect, it } from 'vitest';
import { open, seal, wrapCryptoError } from '../crypto/aead.js';
import { deriveEncKey } from '../crypto/kdf.js';
import { randomBytes } from '../crypto/random.js';
import { SessionError } from '../errors/base.js';

const KEY = deriveEncKey(new Uint8Array(32).fill(7));

describe('seal', () => {
  it('should produce ciphertext that round-trips through open', () => {
    const plaintext = new TextEncoder().encode('hello world');
    const sealed = seal(KEY, plaintext);
    expect(open(KEY, sealed)).toEqual(plaintext);
  });

  it('should prepend a fresh 12-byte nonce so two seals of the same input differ', () => {
    const plaintext = new TextEncoder().encode('same input');
    const a = seal(KEY, plaintext);
    const b = seal(KEY, plaintext);
    expect(a).not.toEqual(b);
    expect(a.subarray(0, 12)).not.toEqual(b.subarray(0, 12));
  });

  it('should authenticate associated data when provided', () => {
    const plaintext = new TextEncoder().encode('payload');
    const aad = new TextEncoder().encode('auth-tag-context');
    const sealed = seal(KEY, plaintext, aad);
    expect(open(KEY, sealed, aad)).toEqual(plaintext);
  });

  it('should produce ciphertext longer than the plaintext (nonce + tag overhead)', () => {
    const plaintext = new Uint8Array(8);
    const sealed = seal(KEY, plaintext);
    expect(sealed.length).toBeGreaterThan(plaintext.length + 12);
  });
});

describe('open', () => {
  it('should return null for input shorter than the nonce', () => {
    expect(open(KEY, new Uint8Array(11))).toBeNull();
  });

  it('should return null when the wrong key is used', () => {
    const sealed = seal(KEY, new TextEncoder().encode('secret'));
    const wrongKey = deriveEncKey(new Uint8Array(32).fill(8));
    expect(open(wrongKey, sealed)).toBeNull();
  });

  it('should return null when the ciphertext is tampered with', () => {
    const sealed = seal(KEY, new TextEncoder().encode('secret'));
    const tampered = new Uint8Array(sealed);
    tampered[tampered.length - 1] ^= 1;
    expect(open(KEY, tampered)).toBeNull();
  });

  it('should return null when AAD is missing on open', () => {
    const aad = new TextEncoder().encode('aad');
    const sealed = seal(KEY, new TextEncoder().encode('payload'), aad);
    expect(open(KEY, sealed)).toBeNull();
  });

  it('should return null when AAD differs between seal and open', () => {
    const sealed = seal(KEY, new TextEncoder().encode('payload'), new TextEncoder().encode('a'));
    expect(open(KEY, sealed, new TextEncoder().encode('b'))).toBeNull();
  });

  it('should return null when the nonce is corrupted', () => {
    const sealed = seal(KEY, new TextEncoder().encode('secret'));
    const bad = new Uint8Array(sealed);
    bad[0] ^= 1;
    expect(open(KEY, bad)).toBeNull();
  });

  it('should return null on exactly-nonce-length input (no ciphertext)', () => {
    expect(open(KEY, new Uint8Array(12))).toBeNull();
  });

  it('should round-trip a payload of varied sizes', () => {
    for (const len of [1, 16, 64, 256, 1024, 4096]) {
      const pt = randomBytes(len);
      const sealed = seal(KEY, pt);
      expect(open(KEY, sealed)).toEqual(pt);
    }
  });
});

describe('wrapCryptoError', () => {
  it('should always throw a SessionError of code CONFIG_INVALID', () => {
    expect(() => wrapCryptoError(new Error('boom'))).toThrowError(SessionError);
    try {
      wrapCryptoError(new Error('boom'));
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
      expect((err as SessionError).code).toBe('CONFIG_INVALID');
      expect((err as SessionError).cause).toBeInstanceOf(Error);
    }
  });
});
