import { describe, expect, it } from 'vitest';
import {
  cookieMaxAge,
  DEFAULT_EXPIRATION,
  evaluate,
  extendExpiry,
  resolveExpiration,
} from '../core/expiration.js';
import type { SessionMetadata } from '../types/session.js';

const baseMeta = (overrides: Partial<SessionMetadata> = {}): SessionMetadata => ({
  id: 'a'.repeat(43),
  createdAt: 1_000,
  lastSeenAt: 1_000,
  expiresAt: 8_000,
  csrf: 'b'.repeat(43),
  v: 1,
  ...overrides,
});

describe('resolveExpiration', () => {
  it('should fill in defaults when called with undefined', () => {
    expect(resolveExpiration(undefined)).toEqual(DEFAULT_EXPIRATION);
  });

  it('should override individual fields', () => {
    const out = resolveExpiration({ slidingSeconds: 0 });
    expect(out.slidingSeconds).toBe(0);
    expect(out.absoluteSeconds).toBe(DEFAULT_EXPIRATION.absoluteSeconds);
  });

  it('should return all five canonical defaults verbatim', () => {
    expect(DEFAULT_EXPIRATION.absoluteSeconds).toBe(60 * 60 * 24 * 30);
    expect(DEFAULT_EXPIRATION.slidingSeconds).toBe(60 * 60 * 24 * 7);
    expect(DEFAULT_EXPIRATION.rotateAfterSeconds).toBe(60 * 60 * 24);
    expect(DEFAULT_EXPIRATION.touchThrottleSeconds).toBe(60);
  });
});

describe('evaluate', () => {
  const policy = resolveExpiration(undefined);

  it("should return alive when now < expiresAt and within touch throttle", () => {
    const meta = baseMeta({ lastSeenAt: 1_000, expiresAt: 10_000 });
    const out = evaluate(meta, 1_005, policy);
    expect(out.state).toBe('alive');
    if (out.state === 'alive') {
      expect(out.touch).toBe(false);
      expect(out.rotate).toBe(false);
    }
  });

  it('should return alive with touch=true once the throttle elapses', () => {
    const meta = baseMeta({ lastSeenAt: 1_000, expiresAt: 100_000 });
    const out = evaluate(meta, 1_000 + policy.touchThrottleSeconds + 1, policy);
    expect(out.state).toBe('alive');
    if (out.state === 'alive') expect(out.touch).toBe(true);
  });

  it('should return alive with rotate=true once rotateAfterSeconds elapses', () => {
    const meta = baseMeta({ createdAt: 0, expiresAt: policy.absoluteSeconds });
    const out = evaluate(meta, policy.rotateAfterSeconds + 5, policy);
    expect(out.state).toBe('alive');
    if (out.state === 'alive') expect(out.rotate).toBe(true);
  });

  it('should return expired when now > expiresAt + skew leeway', () => {
    const meta = baseMeta({ expiresAt: 1_000 });
    expect(evaluate(meta, 1_500, policy).state).toBe('expired');
  });

  it('should NOT return expired when now is within the 60s skew window', () => {
    const meta = baseMeta({ expiresAt: 1_000 });
    expect(evaluate(meta, 1_059, policy).state).toBe('alive');
  });

  it('should respect rotateAfterSeconds=0 (rotation disabled)', () => {
    const policyNoRotate = resolveExpiration({ rotateAfterSeconds: 0 });
    const meta = baseMeta({ createdAt: 0, expiresAt: 1_000_000 });
    const out = evaluate(meta, 999_999, policyNoRotate);
    expect(out.state).toBe('alive');
    if (out.state === 'alive') expect(out.rotate).toBe(false);
  });

  it('should respect slidingSeconds=0 (no touch)', () => {
    const policyNoSlide = resolveExpiration({ slidingSeconds: 0 });
    const meta = baseMeta({ lastSeenAt: 0, expiresAt: 1_000_000 });
    const out = evaluate(meta, 999_999, policyNoSlide);
    expect(out.state).toBe('alive');
    if (out.state === 'alive') expect(out.touch).toBe(false);
  });
});

describe('extendExpiry', () => {
  const policy = resolveExpiration(undefined);

  it('should extend expiry by slidingSeconds from now', () => {
    const meta = baseMeta({ createdAt: 1_000, expiresAt: 2_000 });
    const out = extendExpiry(meta, 1_500, policy);
    expect(out).toBe(1_500 + policy.slidingSeconds);
  });

  it('should clamp to the absolute cap', () => {
    const meta = baseMeta({ createdAt: 0, expiresAt: 100 });
    const out = extendExpiry(meta, policy.absoluteSeconds - 10, policy);
    expect(out).toBe(policy.absoluteSeconds);
  });

  it('should return min(expiresAt, cap) when sliding is disabled', () => {
    const policyNoSlide = resolveExpiration({ slidingSeconds: 0 });
    const meta = baseMeta({ createdAt: 0, expiresAt: 2_000 });
    expect(extendExpiry(meta, 1_500, policyNoSlide)).toBe(2_000);
  });
});

describe('cookieMaxAge', () => {
  it('should return seconds until expiresAt', () => {
    expect(cookieMaxAge(baseMeta({ expiresAt: 2_000 }), 1_000)).toBe(1_000);
  });

  it('should return 0 for a record already expired', () => {
    expect(cookieMaxAge(baseMeta({ expiresAt: 1_000 }), 2_000)).toBe(0);
  });
});
