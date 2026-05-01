import type { CsrfFeatureImpl } from '../../core/feature.js';
import { SessionError } from '../../errors/base.js';
import type { CsrfConfig } from '../../types/csrf.js';
import type { SessionFeature } from '../../types/feature.js';

const DEFAULT_PROTECTED_METHODS: readonly ('POST' | 'PUT' | 'PATCH' | 'DELETE')[] = [
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
];

/** Mirrors `COOKIE_NAME_RE` in `core/cookie.ts` — RFC 6265 token chars. */
const COOKIE_NAME_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;
/** Header field-name token charset (RFC 7230). */
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * Construct a CSRF feature handle. The session manager invokes the
 * feature internally — pass the result to `SessionConfig.csrf`. Framework
 * adapters import this factory and enable CSRF by default; pure API
 * services pass `csrf: false` to opt out.
 *
 * The feature implements the OWASP-recommended **double-submit cookie**
 * pattern: a non-`HttpOnly` mirror cookie carries the token, the client
 * echoes it back in `X-CSRF-Token` (or a hidden form field), the server
 * compares it against `meta.csrf` in constant time. When `enforceOrigin`
 * is set (default), the manager additionally checks that `Origin` /
 * `Referer` matches `Host` for protected methods — a second layer for
 * browsers that mishandle `SameSite`.
 *
 * @param config  Optional CSRF tuning. Every field has a documented default.
 * @returns A `SessionFeature` ready to assign to `SessionConfig.csrf`.
 *
 * @example
 *   import { csrf } from '@authkit/sessions/csrf';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store,
 *     csrf: csrf({ enforceOrigin: true }),
 *   });
 */
export function csrf(config: CsrfConfig = {}): SessionFeature {
  const cookieName = config.cookieName ?? 'csrf';
  if (!COOKIE_NAME_RE.test(cookieName)) {
    throw new SessionError('CONFIG_INVALID', `invalid csrf cookieName: ${JSON.stringify(cookieName)}`);
  }
  const headerName = (config.headerName ?? 'x-csrf-token').toLowerCase();
  if (!HEADER_NAME_RE.test(headerName)) {
    throw new SessionError('CONFIG_INVALID', `invalid csrf headerName: ${JSON.stringify(config.headerName)}`);
  }
  const impl: CsrfFeatureImpl = {
    __feature: 'csrf',
    cookieName,
    headerName,
    protectedMethods: new Set(config.protectedMethods ?? DEFAULT_PROTECTED_METHODS),
    enforceOrigin: config.enforceOrigin ?? true,
  };
  return impl;
}

/**
 * Reconcile the request `Origin` (or fallback `Referer`) against `Host`
 * for a protected method. Used by framework adapters that auto-enforce
 * CSRF before invoking the handler.
 *
 * @param req  Standard `Request`.
 * @returns `true` iff the origin matches host (or no enforcement is needed).
 *
 * @example
 *   if (!isOriginAllowed(req)) return new Response('csrf', { status: 403 });
 */
export function isOriginAllowed(req: Request): boolean {
  const host = req.headers.get('host');
  if (!host) return false;
  const origin = req.headers.get('origin');
  if (origin) {
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  }
  const referer = req.headers.get('referer');
  if (!referer) return false;
  try {
    return new URL(referer).host === host;
  } catch {
    return false;
  }
}
