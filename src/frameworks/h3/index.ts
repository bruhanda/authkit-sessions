import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Build an h3 / Nitro event handler that pre-loads the session,
 * enforces CSRF on protected methods, and attaches the manager + the
 * active session onto `event.context.sessions` /
 * `event.context.session`.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns h3-style event handler — chain via `useSession` or call
 *          inside another handler.
 *
 * @example
 *   import { createApp, eventHandler } from 'h3';
 *   import { h3Sessions } from '@authkit/sessions/frameworks/h3';
 *   const app = createApp();
 *   app.use(h3Sessions(manager));
 *   app.use('/me', eventHandler((event) => event.context.session?.data ?? null));
 */
export function h3Sessions<T extends SessionData>(manager: SessionManager<T>) {
  return async (event: import('h3').H3Event): Promise<void | Response> => {
    const req = await toStandardRequest(event);
    const session = await manager.get(req);
    if (session && PROTECTED.has(req.method)) {
      if (!isOriginAllowed(req)) {
        return new Response('forbidden', { status: 403 });
      }
      const token = req.headers.get('x-csrf-token') ?? '';
      const ok = await manager.verifyCsrf(req, token);
      if (!ok) return new Response('csrf', { status: 403 });
    }
    event.context['sessions'] = manager;
    event.context['session'] = session;
    return undefined;
  };
}

async function toStandardRequest(event: import('h3').H3Event): Promise<Request> {
  const ev = event as unknown as {
    method?: string;
    path?: string;
    node?: { req: { headers: Record<string, string | string[] | undefined>; url?: string } };
  };
  const method = ev.method ?? ev.node?.req.headers['x-http-method-override'] ?? 'GET';
  const path = ev.path ?? ev.node?.req.url ?? '/';
  const headers = new Headers();
  const rawHeaders = ev.node?.req.headers ?? {};
  for (const [k, v] of Object.entries(rawHeaders)) {
    if (Array.isArray(v)) for (const item of v) headers.append(k, item);
    else if (typeof v === 'string') headers.set(k, v);
  }
  const host = headers.get('host') ?? 'localhost';
  return new Request(`http://${host}${path}`, {
    method: typeof method === 'string' ? method : 'GET',
    headers,
  });
}

/** Type helper for accessing the manager + session via `event.context`. */
export interface H3SessionContext<T extends SessionData> {
  sessions: SessionManager<T>;
  session: SessionRecord<T> | null;
}
