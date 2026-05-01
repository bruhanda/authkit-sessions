import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Build a SvelteKit `Handle` that pre-loads the session, enforces CSRF
 * on protected methods, and exposes the manager + session on
 * `event.locals`. Type augmentation in `src/app.d.ts` is **not**
 * required — `T` flows from `createSessionManager` through inference,
 * and the types here are typed as `SessionManager<T>` /
 * `SessionRecord<T> | null`.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns A SvelteKit `Handle`.
 *
 * @example
 *   // src/hooks.server.ts
 *   import { createSessionHandle } from '@authkit/sessions/frameworks/sveltekit';
 *   export const handle = createSessionHandle(manager);
 */
export function createSessionHandle<T extends SessionData>(
  manager: SessionManager<T>,
): import('@sveltejs/kit').Handle {
  return async ({ event, resolve }) => {
    const req = event.request;
    const session = await manager.get(req);
    if (session && PROTECTED.has(req.method)) {
      if (!isOriginAllowed(req)) {
        return new Response('forbidden', { status: 403 });
      }
      const token = req.headers.get('x-csrf-token') ?? '';
      const ok = await manager.verifyCsrf(req, token);
      if (!ok) return new Response('csrf', { status: 403 });
    }
    // SvelteKit's `Locals` is augmented by the user; we set non-typed
    // properties — handlers narrow via the imported types below.
    (event.locals as Record<string, unknown>)['sessions'] = manager;
    (event.locals as Record<string, unknown>)['session'] = session;
    return resolve(event);
  };
}

/**
 * Helper type users can spread into their `App.Locals` augmentation:
 *
 *     declare global {
 *       namespace App {
 *         interface Locals extends SvelteKitSessionLocals<MySession> {}
 *       }
 *     }
 *
 * Optional — works without it; this is purely for first-class typed
 * access to `event.locals.session`.
 */
export interface SvelteKitSessionLocals<T extends SessionData> {
  sessions: SessionManager<T>;
  session: SessionRecord<T> | null;
}
