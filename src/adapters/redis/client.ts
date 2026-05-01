/**
 * Narrow Redis client shape — duck-typed so the adapter accepts ioredis,
 * node-redis 4+, the Bun-native client, and any wrapper that exposes
 * the same operations.
 *
 * Optional methods (`expire`, `eval`, `smembers`, `sadd`, `srem`,
 * `multi`) enable richer behaviour where available; the adapter
 * gracefully degrades when they are absent.
 */
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: { ex?: number }): Promise<unknown>;
  del(key: string | readonly string[]): Promise<number>;
  expire?(key: string, seconds: number): Promise<number>;
  eval?(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown>;
  smembers?(key: string): Promise<readonly string[]>;
  sadd?(key: string, ...members: readonly string[]): Promise<number>;
  srem?(key: string, ...members: readonly string[]): Promise<number>;
}
