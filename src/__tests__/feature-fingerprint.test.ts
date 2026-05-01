import { describe, expect, it } from 'vitest';
import { fingerprint } from '../features/fingerprint/index.js';

describe('fingerprint factory', () => {
  it('should expose a feature with default include components', () => {
    const f = fingerprint() as {
      __feature: string;
      include: readonly string[];
      onMismatch: string;
      ipExtractor: unknown;
    };
    expect(f.__feature).toBe('fingerprint');
    expect(f.include).toContain('user-agent');
    expect(f.include).toContain('accept-language');
    expect(f.include).toContain('sec-ch-ua');
    expect(f.onMismatch).toBe('rotate');
    expect(f.ipExtractor).toBeUndefined();
  });

  it('should accept overrides for include and onMismatch', () => {
    const f = fingerprint({
      include: ['user-agent', 'ip'],
      ip: () => '1.1.1.1',
      onMismatch: 'destroy',
    }) as { include: readonly string[]; onMismatch: string; ipExtractor: unknown };
    expect(f.include).toEqual(['user-agent', 'ip']);
    expect(f.onMismatch).toBe('destroy');
    expect(typeof f.ipExtractor).toBe('function');
  });

  it("should accept onMismatch='ignore'", () => {
    const f = fingerprint({ onMismatch: 'ignore' }) as { onMismatch: string };
    expect(f.onMismatch).toBe('ignore');
  });

  it('should freeze include into a fresh array (no mutation of caller input)', () => {
    const list: ('user-agent' | 'ip')[] = ['user-agent', 'ip'];
    const f = fingerprint({ include: list }) as { include: readonly string[] };
    expect(f.include).not.toBe(list);
  });
});
