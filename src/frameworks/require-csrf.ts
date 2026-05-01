import { SessionError } from '../errors/base.js';
import type { SessionManager } from '../types/manager.js';
import type { SessionData } from '../types/session.js';

/**
 * Framework adapters enforce CSRF on protected methods by default —
 * but they delegate cookie issuance and token comparison to the
 * manager. If the manager was constructed without `csrf` configured,
 * the middleware would require an `X-CSRF-Token` header on every
 * mutation while the manager never emits the mirror cookie, breaking
 * the happy path 100% of the time.
 *
 * This helper bites at boot: every framework integration calls it on
 * the manager handed in. The user gets a clear, code-prefixed error
 * naming the fix instead of debugging silent 403s in production.
 *
 * Opt out by passing `csrf: false` in `createSessionManager` — useful
 * for pure-API services that authenticate via bearer tokens. The
 * helper returns `'opted-out'` in that case so the middleware skips
 * its CSRF enforcement on protected methods too.
 *
 * @param manager  Manager handed to the framework integration.
 * @returns `'enabled'` when csrf is configured, `'opted-out'` when
 *          the user passed `csrf: false`.
 * @throws {SessionError} `CONFIG_INVALID` when neither was supplied.
 *
 * @internal
 */
export function assertCsrfReady<T extends SessionData>(
  manager: SessionManager<T>,
): 'enabled' | 'opted-out' {
  if (manager.__features.has('csrf')) return 'enabled';
  if (manager.__csrfOptedOut) return 'opted-out';
  throw new SessionError(
    'CONFIG_INVALID',
    "framework adapters require CSRF protection. Pass `csrf: csrf({...})` from '@authkit/sessions/csrf' (default-on for the framework path) or `csrf: false` in createSessionManager config to opt out.",
  );
}
