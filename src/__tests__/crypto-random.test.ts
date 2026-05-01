import { describe, expect, it } from 'vitest';
import { randomBytes } from '../crypto/random.js';

describe('randomBytes', () => {
  it('should return a Uint8Array of the requested length', () => {
    expect(randomBytes(16)).toBeInstanceOf(Uint8Array);
    expect(randomBytes(16).length).toBe(16);
  });

  it('should return zero-length when length=0', () => {
    expect(randomBytes(0).length).toBe(0);
  });

  it('should return distinct outputs across two calls (probabilistically certain)', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(a).not.toEqual(b);
  });

  it('should return a fresh buffer each call (not a shared reference)', () => {
    const a = randomBytes(8);
    const b = randomBytes(8);
    expect(a).not.toBe(b);
  });
});
