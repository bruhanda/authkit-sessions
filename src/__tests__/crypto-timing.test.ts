import { describe, expect, it } from 'vitest';
import { timingSafeEqual, timingSafeEqualString } from '../crypto/timing.js';

describe('timingSafeEqual', () => {
  it('should return true for two identical buffers', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('should return false for buffers of different length', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('should return false for buffers with the same length but different bytes', () => {
    expect(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it('should return true for two empty buffers', () => {
    expect(timingSafeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });

  it('should return false for buffers that differ in the first byte', () => {
    expect(timingSafeEqual(new Uint8Array([0, 0, 0]), new Uint8Array([1, 0, 0]))).toBe(false);
  });

  it('should return false for buffers that differ only in the last byte', () => {
    expect(timingSafeEqual(new Uint8Array([0, 0, 0]), new Uint8Array([0, 0, 1]))).toBe(false);
  });
});

describe('timingSafeEqualString', () => {
  it('should return true for identical strings', () => {
    expect(timingSafeEqualString('abc', 'abc')).toBe(true);
  });

  it('should return false for strings of different length', () => {
    expect(timingSafeEqualString('abc', 'abcd')).toBe(false);
  });

  it('should return false for same-length strings that differ', () => {
    expect(timingSafeEqualString('abc', 'abd')).toBe(false);
  });

  it('should treat unicode-canonical inputs identically', () => {
    expect(timingSafeEqualString('café', 'café')).toBe(true);
  });

  it('should return true for two empty strings', () => {
    expect(timingSafeEqualString('', '')).toBe(true);
  });
});
