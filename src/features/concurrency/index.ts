import type { ConcurrencyFeatureImpl } from '../../core/feature.js';
import { SessionError } from '../../errors/base.js';
import type { SessionFeature } from '../../types/feature.js';
import type { ConcurrencyPolicy } from '../../types/policy.js';

/**
 * Construct a concurrency feature handle that enforces a per-user limit
 * on simultaneous active sessions.
 *
 * Eviction strategy:
 *   - `'lru'` (default): drop the least-recently-used session when the
 *     limit is hit.
 *   - `'fifo'`: drop the oldest by `createdAt`.
 *   - `'deny-new'`: refuse the new session, throw `CONCURRENCY_DENIED`.
 *
 * **Best-effort concurrency** (current implementation): the manager
 * queries `listByUser`, evicts overflow, then `create`s the new
 * record. Two parallel `create` calls can both observe `count < max`
 * before either inserts, briefly admitting `max + 1` concurrent
 * sessions. The cookie-only adapter has no cross-device index at all,
 * so concurrency becomes a no-op there (the manager emits a one-shot
 * dev warning when wired against `cookieCodec`). Atomic primitives
 * (Redis Lua, Postgres CTE) are planned (see `lua.ts` placeholder)
 * but not implemented in the current cut — production code that needs
 * a hard cap should add a downstream check (e.g. token-revocation
 * list keyed on `meta.id`).
 *
 * @param policy  Required limit + optional eviction strategy.
 * @returns A `SessionFeature` ready to assign to `SessionConfig.concurrency`.
 * @throws {SessionError} `CONFIG_INVALID` when `max` is not a positive integer.
 *
 * @example
 *   import { concurrency } from '@authkit/sessions/concurrency';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store,
 *     concurrency: concurrency({ max: 5, strategy: 'lru' }),
 *   });
 */
export function concurrency(policy: ConcurrencyPolicy): SessionFeature {
  if (!Number.isInteger(policy.max) || policy.max <= 0) {
    throw new SessionError(
      'CONFIG_INVALID',
      `concurrency.max must be a positive integer; got ${policy.max}`,
    );
  }
  const impl: ConcurrencyFeatureImpl = {
    __feature: 'concurrency',
    max: policy.max,
    strategy: policy.strategy ?? 'lru',
  };
  return impl;
}
