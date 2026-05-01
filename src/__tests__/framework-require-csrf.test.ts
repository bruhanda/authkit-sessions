import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { assertCsrfReady } from '../frameworks/require-csrf.js';
import { SessionError } from '../errors/base.js';
import { buildManager } from './_helpers.js';

describe('assertCsrfReady', () => {
  it("should return 'enabled' when the manager has the csrf feature", () => {
    const mgr = buildManager({ csrf: csrf({}) });
    expect(assertCsrfReady(mgr)).toBe('enabled');
  });

  it("should return 'opted-out' when csrf is explicitly false", () => {
    const mgr = buildManager({ csrf: false });
    expect(assertCsrfReady(mgr)).toBe('opted-out');
  });

  it('should throw CONFIG_INVALID when csrf was forgotten', () => {
    const mgr = buildManager();
    expect(() => assertCsrfReady(mgr)).toThrowError(SessionError);
    try {
      assertCsrfReady(mgr);
    } catch (err) {
      expect((err as SessionError).code).toBe('CONFIG_INVALID');
    }
  });

  it('should mention the fix in the thrown error message', () => {
    const mgr = buildManager();
    try {
      assertCsrfReady(mgr);
    } catch (err) {
      expect((err as SessionError).message).toContain('csrf');
    }
  });
});
