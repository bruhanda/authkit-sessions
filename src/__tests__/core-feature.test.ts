import { describe, expect, it } from 'vitest';
import { resolveFeature } from '../core/feature.js';
import { audit } from '../features/audit/index.js';
import { concurrency } from '../features/concurrency/index.js';
import { csrf } from '../features/csrf/index.js';
import { fingerprint } from '../features/fingerprint/index.js';

describe('resolveFeature', () => {
  it('should return the impl when the discriminator matches', () => {
    const feat = csrf({});
    const out = resolveFeature('csrf', feat);
    expect(out?.__feature).toBe('csrf');
    expect(out?.cookieName).toBe('csrf');
  });

  it('should return undefined when value is undefined', () => {
    expect(resolveFeature('csrf', undefined)).toBeUndefined();
  });

  it('should return undefined when value is false', () => {
    expect(resolveFeature('csrf', false)).toBeUndefined();
  });

  it('should return undefined when the discriminator does not match', () => {
    expect(resolveFeature('audit', csrf({}))).toBeUndefined();
  });

  it('should narrow to the right impl shape per kind', () => {
    expect(resolveFeature('audit', audit(() => undefined))?.__feature).toBe('audit');
    expect(resolveFeature('fingerprint', fingerprint())?.__feature).toBe('fingerprint');
    expect(resolveFeature('concurrency', concurrency({ max: 3 }))?.__feature).toBe('concurrency');
  });
});
