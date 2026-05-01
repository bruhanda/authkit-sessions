import { SessionError } from '../errors/base.js';
import type { SessionData } from '../types/session.js';
import type { SessionStore } from '../types/store.js';

/**
 * Free-standing helpers for revoking sessions without going through a
 * `SessionManager`. Useful in admin tooling and migration scripts that
 * have direct access to the store but no `Request` to bind to.
 */

/**
 * Delete a single session by id, wrapping infrastructure errors in
 * `STORE_UNAVAILABLE`.
 *
 * @param store  Session store.
 * @param id     Opaque session id.
 * @returns `true` iff the store removed something.
 * @throws {SessionError} `STORE_UNAVAILABLE` when the store fails.
 *
 * @example
 *   await revokeBySessionId(store, 'abc...');
 */
export async function revokeBySessionId<T extends SessionData>(
  store: SessionStore<T>,
  id: string,
): Promise<boolean> {
  try {
    return await store.delete(id);
  } catch (err) {
    if (SessionError.is(err)) throw err;
    throw new SessionError('STORE_UNAVAILABLE', 'store.delete failed', err);
  }
}

/**
 * Revoke every session for a user — "log out everywhere".
 *
 * @param store   Session store.
 * @param userId  User identifier.
 * @returns Number of sessions removed.
 * @throws {SessionError} `STORE_UNAVAILABLE` when the store fails.
 *
 * @example
 *   await revokeByUser(store, 'user_42');
 */
export async function revokeByUser<T extends SessionData>(
  store: SessionStore<T>,
  userId: string,
): Promise<number> {
  try {
    return await store.deleteByUser(userId);
  } catch (err) {
    if (SessionError.is(err)) throw err;
    throw new SessionError('STORE_UNAVAILABLE', 'store.deleteByUser failed', err);
  }
}
