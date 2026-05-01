import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { isDev } from '../utils/env.js';

const ORIGINAL_NODE_ENV = process.env['NODE_ENV'];

describe('isDev', () => {
  afterEach(() => {
    if (ORIGINAL_NODE_ENV === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = ORIGINAL_NODE_ENV;
  });

  it('should return true when NODE_ENV is undefined', () => {
    delete process.env['NODE_ENV'];
    expect(isDev()).toBe(true);
  });

  it("should return false when NODE_ENV is 'production'", () => {
    process.env['NODE_ENV'] = 'production';
    expect(isDev()).toBe(false);
  });

  it("should return true when NODE_ENV is 'development'", () => {
    process.env['NODE_ENV'] = 'development';
    expect(isDev()).toBe(true);
  });

  it("should return true when NODE_ENV is 'test'", () => {
    process.env['NODE_ENV'] = 'test';
    expect(isDev()).toBe(true);
  });
});

describe('isDev runtime guards', () => {
  let original: typeof globalThis.process | undefined;

  beforeEach(() => {
    original = globalThis.process;
  });

  afterEach(() => {
    if (original) {
      Object.defineProperty(globalThis, 'process', {
        value: original,
        configurable: true,
        writable: true,
      });
    }
  });

  it('should return false when process is undefined (Workers/Deno-like runtime)', () => {
    Object.defineProperty(globalThis, 'process', {
      value: undefined,
      configurable: true,
      writable: true,
    });
    expect(isDev()).toBe(false);
  });
});
