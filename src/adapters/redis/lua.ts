/**
 * Lua scripts evaluated server-side via `EVAL` on Redis ≥2.6 / Valkey.
 *
 * **Status (current cut):** the user-index helpers below (`SADD` /
 * `SREM` + `EXPIRE`) are atomic on their own but do NOT yet implement
 * the single-EVAL `SMEMBERS → check-count → evict → SADD` enforce-
 * and-evict primitive sketched in `PLAN.md` §9.3.1. The manager
 * therefore enforces concurrency in app code (read → evict → write)
 * with a documented best-effort guarantee — two parallel `create()`
 * calls can briefly admit `max + 1` sessions before consistency
 * catches up. The hard atomic primitive is tracked alongside the
 * feature-lifecycle-hook refactor.
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
