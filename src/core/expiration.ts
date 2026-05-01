import type { ExpirationPolicy } from '../types/policy.js';
import type { SessionMetadata } from '../types/session.js';

/** Default policy values — sliding 7d, absolute 30d, rotation 24h. */
export const DEFAULT_EXPIRATION: Required<ExpirationPolicy> = {
  absoluteSeconds: 60 * 60 * 24 * 30,
  slidingSeconds: 60 * 60 * 24 * 7,
  rotateAfterSeconds: 60 * 60 * 24,
  touchThrottleSeconds: 60,
};

/** Clock-skew tolerance — accept expiration timestamps within ±60 s of `now`. */
const SKEW_LEEWAY = 60;

/**
 * Outcome of evaluating a session record against the current clock.
 *
 *   - `alive`: record is still valid; `touch` indicates whether
 *     `lastSeenAt` should be persisted (subject to throttle), and
 *     `rotate` indicates whether the id should be rotated.
 *   - `expired`: record's absolute or sliding window has elapsed.
 */
export type ExpirationOutcome =
  | { readonly state: 'alive'; readonly touch: boolean; readonly rotate: boolean }
  | { readonly state: 'expired' };

/**
 * Resolve a partial policy against the documented defaults.
 *
 * @param policy  User-supplied overrides.
 * @returns Fully populated policy.
 *
 * @example
 *   const p = resolveExpiration({ slidingSeconds: 0 });
 */
export function resolveExpiration(policy: ExpirationPolicy | undefined): Required<ExpirationPolicy> {
  return { ...DEFAULT_EXPIRATION, ...policy };
}

/**
 * Decide whether a record is still alive, and whether the manager should
 * touch / rotate it on this read.
 *
 * @param meta    Record metadata.
 * @param now     Current Unix seconds.
 * @param policy  Resolved expiration policy.
 * @returns Decision union.
 *
 * @example
 *   const outcome = evaluate(record.meta, nowSeconds(), resolveExpiration(policy));
 *   if (outcome.state === 'expired') return null;
 */
export function evaluate(
  meta: SessionMetadata,
  now: number,
  policy: Required<ExpirationPolicy>,
): ExpirationOutcome {
  if (now > meta.expiresAt + SKEW_LEEWAY) return { state: 'expired' };

  const age = now - meta.createdAt;
  const rotate = policy.rotateAfterSeconds > 0 && age >= policy.rotateAfterSeconds;
  const touch =
    policy.slidingSeconds > 0 && now - meta.lastSeenAt >= policy.touchThrottleSeconds;
  return { state: 'alive', touch, rotate };
}

/**
 * Compute the next `expiresAt` after a sliding-window touch. Bounded by
 * the absolute window: a sliding extension can never push past
 * `createdAt + absoluteSeconds`.
 *
 * @param meta    Current metadata.
 * @param now     Current Unix seconds.
 * @param policy  Resolved expiration policy.
 * @returns The next `expiresAt`.
 *
 * @example
 *   const nextExp = extendExpiry(meta, nowSeconds(), resolved);
 */
export function extendExpiry(
  meta: SessionMetadata,
  now: number,
  policy: Required<ExpirationPolicy>,
): number {
  const absoluteCap = meta.createdAt + policy.absoluteSeconds;
  if (policy.slidingSeconds <= 0) return Math.min(meta.expiresAt, absoluteCap);
  return Math.min(now + policy.slidingSeconds, absoluteCap);
}

/**
 * Compute the cookie `Max-Age` for a freshly-minted record. Mirrors the
 * sliding window so the browser drops the cookie shortly after the
 * server forgets the session.
 *
 * @param meta    Current metadata.
 * @param now     Current Unix seconds.
 * @returns Seconds until the cookie should expire (≥ 0).
 *
 * @example
 *   const maxAge = cookieMaxAge(meta, nowSeconds());
 */
export function cookieMaxAge(meta: SessionMetadata, now: number): number {
  return Math.max(0, meta.expiresAt - now);
}
