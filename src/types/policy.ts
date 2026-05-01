/**
 * Sliding + absolute expiration windows. The manager owns the arithmetic;
 * stores never extend TTL on read.
 */
export interface ExpirationPolicy {
  /** Absolute lifetime cap from creation. Default 30 days. */
  absoluteSeconds?: number;
  /**
   * Sliding window — extend `expiresAt` by N seconds on every successful
   * read, up to `absoluteSeconds`. Set to `0` to disable sliding. Default
   * 7 days.
   */
  slidingSeconds?: number;
  /**
   * Force id rotation when a session is older than this. Mitigates
   * fixation. Default `86_400` (24 h). Set to `0` to disable.
   */
  rotateAfterSeconds?: number;
  /**
   * Throttle for sliding-expiration writes — only persist a new
   * `lastSeenAt` when the delta exceeds this many seconds. Default `60`.
   */
  touchThrottleSeconds?: number;
}

/**
 * Eviction strategy when concurrency limit is hit.
 *
 *   - `'lru'`: drop least-recently-used (default).
 *   - `'fifo'`: drop oldest by `createdAt`.
 *   - `'deny-new'`: refuse the new session, throw `CONCURRENCY_DENIED`.
 */
export type EvictionStrategy = 'lru' | 'fifo' | 'deny-new';

/** Concurrent-session-limit policy. */
export interface ConcurrencyPolicy {
  /** Max concurrent active sessions per user. */
  max: number;
  /** Eviction strategy when the limit is hit. Default `'lru'`. */
  strategy?: EvictionStrategy;
}
