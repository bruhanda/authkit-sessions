import { SessionError } from '../../errors/base.js';
import type { SessionManager, SessionAttachment } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

/**
 * Bind a `SessionManager<T>` to the Remix / React Router 7 request
 * lifecycle.
 *
 * Returns three helpers shaped after the framework's own
 * `createSessionStorage()` API:
 *
 *   - `getSession(request)` — read the active record, or `null`.
 *   - `commitSession(request, data)` — create / update the session and
 *     return a `Set-Cookie` string for `loader` / `action` responses.
 *   - `destroySession(request)` — sign-out + an expiring `Set-Cookie`.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns The three Remix-shaped helpers.
 *
 * @example
 *   // app/lib/session.server.ts
 *   import { createRemixSession } from '@authkit/sessions/frameworks/remix';
 *   export const { getSession, commitSession, destroySession } = createRemixSession(manager);
 *
 *   // app/routes/profile.tsx
 *   export async function loader({ request }: LoaderArgs) {
 *     const session = await getSession(request);
 *     if (!session) throw redirect('/login');
 *     return json({ user: session.data });
 *   }
 */
export function createRemixSession<T extends SessionData>(manager: SessionManager<T>): {
  getSession: (request: Request) => Promise<SessionRecord<T> | null>;
  commitSession: (request: Request, data: T) => Promise<string>;
  destroySession: (request: Request) => Promise<string>;
} {
  return {
    async getSession(request) {
      return manager.get(request);
    },
    async commitSession(request, data) {
      const existing = await manager.get(request);
      const attachment: SessionAttachment<T> = existing
        ? await manager.update(request, () => data)
        : await manager.create(request, data);
      return attachment.cookie;
    },
    async destroySession(request) {
      try {
        const attachment = await manager.signOut(request);
        return attachment.cookie;
      } catch (err) {
        if (SessionError.is(err)) throw err;
        throw new SessionError('STORE_UNAVAILABLE', 'destroySession failed', err);
      }
    },
  };
}
