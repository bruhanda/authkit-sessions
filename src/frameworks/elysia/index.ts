import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData } from '../../types/session.js';
import { assertCsrfReady } from '../require-csrf.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Elysia plugin factory.
 *
 * Returns a derived store with `sessions` (the manager) and `session`
 * (current `SessionRecord<T> | null`). CSRF is enforced by default on
 * mutating methods.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance from `createSessionManager`.
 * @returns A plugin function compatible with Elysia's `.use(...)`.
 *
 * @example
 *   import { Elysia } from 'elysia';
 *   import { elysiaSessions } from '@authkit/sessions/frameworks/elysia';
 *   const app = new Elysia()
 *     .use(elysiaSessions(manager))
 *     .get('/me', ({ session }) => session?.data ?? null);
 */
export function elysiaSessions<T extends SessionData>(manager: SessionManager<T>) {
  const csrfMode = assertCsrfReady(manager);
  return (app: import('elysia').Elysia) =>
    app.derive(async ({ request }) => {
      const session = await manager.get(request);
      if (csrfMode === 'enabled' && session && PROTECTED.has(request.method)) {
        if (!isOriginAllowed(request)) {
          throw new Response('forbidden', { status: 403 });
        }
        const token = request.headers.get('x-csrf-token') ?? '';
        const ok = await manager.verifyCsrf(request, token);
        if (!ok) throw new Response('csrf', { status: 403 });
      }
      return {
        sessions: manager,
        session,
      };
    });
}
