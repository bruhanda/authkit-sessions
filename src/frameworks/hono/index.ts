import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';
import { assertCsrfReady } from '../require-csrf.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Hono middleware that exposes the session manager and the active
 * session on `c.var`. CSRF is enforced by default for `POST` / `PUT` /
 * `PATCH` / `DELETE` — pass `csrf: false` in the manager config to
 * disable.
 *
 * Manager-as-input pattern: the user constructs `SessionManager<T>` and
 * hands it in; the returned middleware preserves `T` through inference
 * so handlers see `c.var.session` typed as `SessionRecord<T> | null`
 * with no `declare module 'hono'` ritual.
 *
 * @typeParam T  Session payload shape, inferred from the manager.
 * @param manager  Manager instance from `createSessionManager`.
 * @returns Hono `MiddlewareHandler` typed via `Variables` so handlers
 *          read `c.var.sessions` / `c.var.session` directly.
 *
 * @example
 *   import { honoSessions } from '@authkit/sessions/frameworks/hono';
 *   app.use('*', honoSessions(manager));
 *   app.get('/me', (c) => c.json(c.var.session?.data ?? { anon: true }));
 */
export function honoSessions<T extends SessionData>(
  manager: SessionManager<T>,
): import('hono').MiddlewareHandler<{
  Variables: { sessions: SessionManager<T>; session: SessionRecord<T> | null };
}> {
  const csrfMode = assertCsrfReady(manager);
  return async (c, next) => {
    const req = c.req.raw;
    const session = await manager.get(req);

    // CSRF only enforces when a session is active — pre-auth requests
    // (e.g. login submission) have nothing to protect.
    if (csrfMode === 'enabled' && session && PROTECTED.has(req.method)) {
      if (!isOriginAllowed(req)) {
        return c.text('forbidden', 403);
      }
      const token = req.headers.get('x-csrf-token') ?? '';
      const ok = await manager.verifyCsrf(req, token);
      if (!ok) return c.text('csrf', 403);
    }

    c.set('sessions', manager);
    c.set('session', session);
    await next();
  };
}
