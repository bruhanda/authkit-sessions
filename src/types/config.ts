import type { CookieOptions } from './cookie.js';
import type { SessionFeature } from './feature.js';
import type { ExpirationPolicy } from './policy.js';
import type { SessionData } from './session.js';
import type { SessionStore } from './store.js';

/**
 * Configuration object handed to `createSessionManager`. Every field has
 * a documented default except `secrets` and `store`, which are required.
 *
 * @typeParam T  Shape of the session payload, propagated to the store and
 *               the returned manager.
 */
export interface SessionConfig<T extends SessionData = SessionData> {
  /**
   * One or more secrets carrying ≥256 bits of entropy each (32 random
   * bytes, or a base64url-encoded equivalent). The first is the active
   * key (used for new cookies / signatures); the rest are accepted on
   * read for zero-downtime rotation. Strings are interpreted as UTF-8 and
   * HKDF-stretched — HKDF itself works on any input length, but anything
   * with less than 256 bits of entropy is below our security floor.
   *
   * Throws `SessionError('SECRET_TOO_SHORT')` at construction time with
   * a message naming the entropy threshold (not just the byte count) so
   * users with a short hex key understand they didn't pick a weak
   * primitive, they picked a weak input.
   */
  secrets: string | Uint8Array | readonly (string | Uint8Array)[];

  /**
   * Storage adapter. **Required** — there is no default. The TypeScript
   * compiler forces the choice; consumers wanting a dev/test in-memory
   * store must explicitly `import { createMemoryStore } from
   * '@authkit/sessions/adapters/memory'`. This avoids the express-session
   * footgun where an unconfigured production deployment silently
   * accumulates state in a leaky `Map`.
   */
  store: SessionStore<T>;

  /**
   * Single source of truth for "which user owns this session". Runs on
   * `create()` and after every `update()` mutator; the result is stored
   * in `meta.userId` and consumed by `revokeByUser` / concurrency /
   * `listByUser`. Return `undefined` for anonymous / pre-auth sessions.
   *
   * @example
   *   getUserId: (data) => data.userId
   */
  getUserId?: (data: T) => string | undefined;

  /** Cookie name for the session id. Default `'sid'`. */
  cookieName?: string;

  /** Cookie attributes applied to every Set-Cookie. */
  cookie?: Partial<CookieOptions>;

  /** Expiration policy — sliding + absolute. */
  expiration?: ExpirationPolicy;

  /**
   * CSRF protection. Constructed from `@authkit/sessions/csrf`.
   *
   * Framework adapters (`/frameworks/*`) import and enable CSRF by
   * default. Pure API services pass `csrf: false` to opt out. Raw
   * `createSessionManager` users opt in by importing `csrf` from the
   * subpath and assigning it here.
   */
  csrf?: SessionFeature | false;

  /**
   * Concurrent session limits. Constructed from
   * `@authkit/sessions/concurrency`. Off when omitted.
   */
  concurrency?: SessionFeature;

  /**
   * Device fingerprinting. Constructed from
   * `@authkit/sessions/fingerprint`. Off when omitted.
   */
  fingerprint?: SessionFeature;

  /**
   * Audit hooks. Constructed from `@authkit/sessions/audit`. Off when
   * omitted.
   */
  audit?: SessionFeature;

  /**
   * Clock injector for tests. Returns Unix seconds. Defaults to
   * `() => Math.floor(Date.now() / 1000)`. Replacing it lets the test
   * suite fast-forward through expiration without fake timers.
   */
  clock?: () => number;
}
