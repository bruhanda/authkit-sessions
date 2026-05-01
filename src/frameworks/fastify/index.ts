import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Build a Fastify plugin function. Returns a function shaped for
 * `fastify.register(...)` that decorates the app with `sessions`
 * (the manager) and adds an `onRequest` hook materialising
 * `request.session`.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns Async plugin function — register via `fastify.register(plugin)`.
 *
 * @example
 *   import Fastify from 'fastify';
 *   import { fastifySessions } from '@authkit/sessions/frameworks/fastify';
 *   const app = Fastify();
 *   await app.register(fastifySessions(manager));
 */
export function fastifySessions<T extends SessionData>(manager: SessionManager<T>) {
  return async (
    fastify: import('fastify').FastifyInstance,
  ): Promise<void> => {
    fastify.decorate('sessions', manager);

    fastify.addHook('onRequest', async (request, reply) => {
      const standardReq = toStandardRequest(request);
      const session = await manager.get(standardReq);
      if (session && PROTECTED.has(request.method)) {
        if (!isOriginAllowed(standardReq)) {
          reply.code(403).send('forbidden');
          return;
        }
        const token = (request.headers['x-csrf-token'] as string | undefined) ?? '';
        const ok = await manager.verifyCsrf(standardReq, token);
        if (!ok) {
          reply.code(403).send('csrf');
          return;
        }
      }
      (request as unknown as Record<string, unknown>)['sessions'] = manager;
      (request as unknown as Record<string, unknown>)['session'] = session;
    });
  };
}

function toStandardRequest(req: import('fastify').FastifyRequest): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else if (typeof value === 'string') headers.set(key, value);
  }
  const host = (req.headers.host as string | undefined) ?? 'localhost';
  const url = `${req.protocol}://${host}${req.url}`;
  return new Request(url, { method: req.method, headers });
}

/**
 * Helper type for module-augmenting `fastify.FastifyRequest` with the
 * manager and active session.
 *
 * @example
 *   declare module 'fastify' {
 *     interface FastifyRequest extends FastifySessionRequest<MySession> {}
 *   }
 */
export interface FastifySessionRequest<T extends SessionData> {
  sessions: SessionManager<T>;
  session: SessionRecord<T> | null;
}
