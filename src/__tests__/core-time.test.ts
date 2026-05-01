import { describe, expect, it } from 'vitest';
import { nowSeconds } from '../core/time.js';

describe('nowSeconds', () => {
  it('should return an integer Unix timestamp', () => {
    const t = nowSeconds();
    expect(Number.isInteger(t)).toBe(true);
    expect(t).toBeGreaterThan(0);
  });

  it('should match Math.floor(Date.now() / 1000) within a one-second window', () => {
    const before = Math.floor(Date.now() / 1000);
    const t = nowSeconds();
    const after = Math.floor(Date.now() / 1000);
    expect(t).toBeGreaterThanOrEqual(before);
    expect(t).toBeLessThanOrEqual(after);
  });
});
