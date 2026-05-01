import { describe, expect, it } from 'vitest';
import {
  coerceSecret,
  deriveEncKey,
  deriveFingerprintKey,
  deriveSigKey,
  validateSecret,
} from '../crypto/kdf.js';
import { SessionError } from '../errors/base.js';

describe('validateSecret', () => {
  it('should not throw for secrets >=32 bytes', () => {
    expect(() => validateSecret(new Uint8Array(32))).not.toThrow();
    expect(() => validateSecret(new Uint8Array(64))).not.toThrow();
  });

  it('should throw SECRET_TOO_SHORT for fewer than 32 bytes', () => {
    expect(() => validateSecret(new Uint8Array(31))).toThrowError(SessionError);
    try {
      validateSecret(new Uint8Array(0));
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
      expect((err as SessionError).code).toBe('SECRET_TOO_SHORT');
    }
  });

  it('should mention the byte count in the error message', () => {
    try {
      validateSecret(new Uint8Array(16));
    } catch (err) {
      expect((err as SessionError).message).toContain('16');
    }
  });
});

describe('deriveEncKey', () => {
  it('should produce a deterministic 32-byte key for a given secret', () => {
    const secret = new Uint8Array(32).fill(5);
    const a = deriveEncKey(secret);
    const b = deriveEncKey(secret);
    expect(a.length).toBe(32);
    expect(a).toEqual(b);
  });

  it('should produce a different key for a different secret', () => {
    const a = deriveEncKey(new Uint8Array(32).fill(1));
    const b = deriveEncKey(new Uint8Array(32).fill(2));
    expect(a).not.toEqual(b);
  });
});

describe('deriveSigKey', () => {
  it('should produce a 32-byte key', () => {
    const key = deriveSigKey(new Uint8Array(32).fill(9));
    expect(key.length).toBe(32);
  });

  it('should differ from the encryption key derived from the same secret', () => {
    const secret = new Uint8Array(32).fill(9);
    expect(deriveSigKey(secret)).not.toEqual(deriveEncKey(secret));
  });
});

describe('deriveFingerprintKey', () => {
  it('should produce a 32-byte key', () => {
    expect(deriveFingerprintKey(new Uint8Array(32)).length).toBe(32);
  });

  it('should differ from the signing key derived from the same secret', () => {
    const secret = new Uint8Array(32).fill(9);
    expect(deriveFingerprintKey(secret)).not.toEqual(deriveSigKey(secret));
  });

  it('should differ from the encryption key derived from the same secret', () => {
    const secret = new Uint8Array(32).fill(9);
    expect(deriveFingerprintKey(secret)).not.toEqual(deriveEncKey(secret));
  });
});

describe('coerceSecret', () => {
  it('should pass Uint8Array inputs through unchanged', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(coerceSecret(bytes)).toBe(bytes);
  });

  it('should encode a string secret as UTF-8 bytes', () => {
    const out = coerceSecret('hello');
    expect(out).toBeInstanceOf(Uint8Array);
    expect([...out]).toEqual([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
  });

  it('should encode unicode strings correctly', () => {
    expect(coerceSecret('é').length).toBe(2);
  });
});
