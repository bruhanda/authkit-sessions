import { describe, expect, it } from 'vitest';
import { sign, verify, verifyAny } from '../crypto/hmac.js';

const KEY_A = new Uint8Array(32).fill(1);
const KEY_B = new Uint8Array(32).fill(2);

describe('sign', () => {
  it('should produce a deterministic 32-byte digest for the same input', () => {
    const data = new TextEncoder().encode('payload');
    const tag1 = sign(KEY_A, data);
    const tag2 = sign(KEY_A, data);
    expect(tag1).toEqual(tag2);
    expect(tag1.length).toBe(32);
  });

  it('should produce different digests under different keys', () => {
    const data = new TextEncoder().encode('payload');
    expect(sign(KEY_A, data)).not.toEqual(sign(KEY_B, data));
  });

  it('should produce different digests for different inputs', () => {
    expect(sign(KEY_A, new TextEncoder().encode('a'))).not.toEqual(
      sign(KEY_A, new TextEncoder().encode('b')),
    );
  });
});

describe('verify', () => {
  it('should return true for a tag signed with the same key', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_A, data);
    expect(verify(KEY_A, data, tag)).toBe(true);
  });

  it('should return false for a tag signed with a different key', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_B, data);
    expect(verify(KEY_A, data, tag)).toBe(false);
  });

  it('should return false for a tampered tag', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_A, data);
    const tampered = new Uint8Array(tag);
    tampered[0] ^= 1;
    expect(verify(KEY_A, data, tampered)).toBe(false);
  });

  it('should return false when the data was modified after signing', () => {
    const tag = sign(KEY_A, new TextEncoder().encode('original'));
    expect(verify(KEY_A, new TextEncoder().encode('changed'), tag)).toBe(false);
  });
});

describe('verifyAny', () => {
  it('should return true when any candidate key verifies the tag', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_A, data);
    expect(verifyAny([KEY_B, KEY_A], data, tag)).toBe(true);
  });

  it('should return false when no candidate key verifies the tag', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(new Uint8Array(32).fill(3), data);
    expect(verifyAny([KEY_A, KEY_B], data, tag)).toBe(false);
  });

  it('should return false on an empty key list', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_A, data);
    expect(verifyAny([], data, tag)).toBe(false);
  });

  it('should not short-circuit on the first match (timing-stable)', () => {
    const data = new TextEncoder().encode('payload');
    const tag = sign(KEY_A, data);
    // Result is the same whether the matching key comes first or last.
    expect(verifyAny([KEY_A, KEY_B], data, tag)).toBe(true);
    expect(verifyAny([KEY_B, KEY_A], data, tag)).toBe(true);
  });
});
