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
 * Race-condition behaviour: the manager queries `listByUser` then writes
 * with a single round-trip. Stores that expose atomic primitives (Redis
 * Lua, Postgres CTE, Durable Objects) close the N+1 race entirely; KV
 * and Upstash adapters tolerate a documented worst-case overshoot of 1.
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
