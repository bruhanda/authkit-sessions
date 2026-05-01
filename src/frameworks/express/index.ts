import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';
import { assertCsrfReady } from '../require-csrf.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Express compatibility middleware. Translates between the
 * `(req, res, next)` flow Express expects and the Web Standards
 * `Request` the manager wants.
 *
 * Sets `req.sessions` (the manager) and `req.session`
 * (`SessionRecord<T> | null`) for handlers. Mutating session helpers
 * append `Set-Cookie` to `res` directly.
 *
 * Body parsers (`express.json()` / `express.urlencoded()`) MUST be
 * mounted before this middleware for protected methods.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns Express middleware function.
 *
 * @example
 *   import express from 'express';
 *   import { expressSessions } from '@authkit/sessions/frameworks/express';
 *   const app = express();
 *   app.use(express.json());
 *   app.use(expressSessions(manager));
 */
export function expressSessions<T extends SessionData>(manager: SessionManager<T>) {
  const csrfMode = assertCsrfReady(manager);
  return async (
    req: import('express').Request,
    res: import('express').Response,
    next: import('express').NextFunction,
  ): Promise<void> => {
    try {
      const standardReq = toStandardRequest(req);
      const session = await manager.get(standardReq);

      if (csrfMode === 'enabled' && session && PROTECTED.has(req.method)) {
        if (!isOriginAllowed(standardReq)) {
          res.status(403).send('forbidden');
          return;
        }
        const token = (req.headers['x-csrf-token'] as string | undefined) ?? '';
        const ok = await manager.verifyCsrf(standardReq, token);
        if (!ok) {
          res.status(403).send('csrf');
          return;
        }
      }
      // Augment the request without typing: consumers either declare
      // their own augmentation or destructure these fields explicitly.
      (req as unknown as Record<string, unknown>)['sessions'] = manager;
      (req as unknown as Record<string, unknown>)['session'] = session;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Build a synthetic Web Standards `Request` from an Express request.
 * Body is intentionally not piped through — session reads only need
 * headers + URL.
 */
function toStandardRequest(req: import('express').Request): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else if (typeof value === 'string') headers.set(key, value);
  }
  const protocol = req.protocol || 'http';
  const host = req.headers.host ?? 'localhost';
  const url = `${protocol}://${host}${req.originalUrl ?? req.url}`;
  return new Request(url, { method: req.method, headers });
}

/**
 * Helper type for module-augmenting `express.Request` with the manager
 * and the active session. Optional — works without it.
 *
 * @example
 *   declare global {
 *     namespace Express {
 *       interface Request extends ExpressSessionRequest<MySession> {}
 *     }
 *   }
 */
export interface ExpressSessionRequest<T extends SessionData> {
  sessions: SessionManager<T>;
  session: SessionRecord<T> | null;
}
