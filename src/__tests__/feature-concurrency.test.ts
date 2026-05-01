import { describe, expect, it } from 'vitest';
import { concurrency } from '../features/concurrency/index.js';
import { SessionError } from '../errors/base.js';

describe('concurrency factory', () => {
  it('should expose a feature handle with default LRU strategy', () => {
    const f = concurrency({ max: 5 }) as { __feature: string; max: number; strategy: string };
    expect(f.__feature).toBe('concurrency');
    expect(f.max).toBe(5);
    expect(f.strategy).toBe('lru');
  });

  it('should accept fifo and deny-new strategies', () => {
    expect((concurrency({ max: 1, strategy: 'fifo' }) as { strategy: string }).strategy).toBe('fifo');
    expect((concurrency({ max: 1, strategy: 'deny-new' }) as { strategy: string }).strategy).toBe('deny-new');
  });

  it('should throw CONFIG_INVALID for non-positive max', () => {
    expect(() => concurrency({ max: 0 })).toThrowError(SessionError);
    expect(() => concurrency({ max: -1 })).toThrowError(SessionError);
  });

  it('should throw CONFIG_INVALID for fractional max', () => {
    expect(() => concurrency({ max: 1.5 })).toThrowError(/max must be a positive integer/);
  });

  it('should throw CONFIG_INVALID for non-numeric max', () => {
    // biome-ignore lint/suspicious/noExplicitAny: testing runtime guard
    expect(() => concurrency({ max: 'three' as any })).toThrowError(SessionError);
  });
});
