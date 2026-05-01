import { isOriginAllowed } from '../../features/csrf/index.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData } from '../../types/session.js';
import { assertCsrfReady } from '../require-csrf.js';

const PROTECTED = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Build a Next.js middleware that pre-loads the session, enforces CSRF
 * on protected methods, and propagates `Set-Cookie` mutations through
 * `NextResponse.cookies`. The middleware does NOT mutate `req` — Next
 * forbids that — instead it returns a `NextResponse` whose cookies the
 * downstream handler inherits.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns Function with the Next middleware signature.
 *
 * @example
 *   // app/middleware.ts
 *   import { createSessionMiddleware } from '@authkit/sessions/frameworks/next';
 *   export default createSessionMiddleware(manager);
 *   export const config = { matcher: ['/((?!_next).*)'] };
 */
export function createSessionMiddleware<T extends SessionData>(
  manager: SessionManager<T>,
): (
  req: import('next/server').NextRequest,
) => Promise<import('next/server').NextResponse> {
  const csrfMode = assertCsrfReady(manager);
  return async (req) => {
    // Lazy-load to avoid pulling next/server into the package bundle
    // when consumers do not import this entry point.
    const { NextResponse } = await import('next/server');
    const standardReq = req as unknown as Request;

    if (csrfMode === 'enabled' && PROTECTED.has(req.method)) {
      const session = await manager.get(standardReq);
      // CSRF only enforces when a session is active — pre-auth requests
      // (e.g. login submission) have nothing to protect.
      if (session) {
        if (!isOriginAllowed(standardReq)) {
          return new NextResponse('forbidden', { status: 403 });
        }
        const token = req.headers.get('x-csrf-token') ?? '';
        const ok = await manager.verifyCsrf(standardReq, token);
        if (!ok) return new NextResponse('csrf', { status: 403 });
      }
    }

    return NextResponse.next();
  };
}
