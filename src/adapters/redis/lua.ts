/**
 * Lua scripts evaluated server-side via `EVAL` on Redis ≥2.6 / Valkey.
 *
 * Atomic concurrency enforcement: `LRANGE` (or `SMEMBERS`) → check
 * count → optionally evict → `LPUSH` (or `SADD`) → set TTL — all in one
 * round-trip so two parallel `create()` calls cannot exceed the limit.
 *
 * Stored as inlined string constants (rather than as separate `.lua`
 * files) so the bundler keeps everything in one chunk and the size
 * budget is observable.
 */

/**
 * Atomically register a session id under a user index set with TTL.
 *
 *  KEYS[1]  user index set key (e.g. `sess:user:42`)
 *  ARGV[1]  new session id
 *  ARGV[2]  TTL seconds
 *
 * Returns `1` on success.
 */
export const ADD_TO_USER_INDEX = `
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return 1
`.trim();

/**
 * Atomically remove a session id from a user index set.
 *
 *  KEYS[1]  user index set key
 *  ARGV[1]  session id to remove
 *
 * Returns the number of elements actually removed.
 */
export const REMOVE_FROM_USER_INDEX = `
return redis.call('SREM', KEYS[1], ARGV[1])
`.trim();
