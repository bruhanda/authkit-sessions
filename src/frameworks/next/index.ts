import { SessionError } from '../../errors/base.js';
import type { SessionManager } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

export { createSessionMiddleware } from './middleware.js';
export { withSession } from './route-handler.js';

/**
 * Read the active session from inside a Next.js Server Component, Route
 * Handler, or Server Action. Internally calls `next/headers#cookies()`
 * to construct a synthetic `Request` carrying the cookie header.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @returns The current `SessionRecord<T>`, or `null` if none.
 * @throws {SessionError} `CONFIG_INVALID` when called outside a Next
 *                        server context (e.g. from a Client Component).
 *
 * @example
 *   // app/dashboard/page.tsx
 *   import { getServerSession } from '@authkit/sessions/frameworks/next';
 *   const session = await getServerSession(manager);
 */
export async function getServerSession<T extends SessionData>(
  manager: SessionManager<T>,
): Promise<SessionRecord<T> | null> {
  const cookieHeader = await readCookieHeader();
  const synthetic = new Request('https://next.local', {
    headers: cookieHeader ? { cookie: cookieHeader } : {},
  });
  return manager.get(synthetic);
}

/**
 * Persist a fresh session from a Server Action. The Set-Cookie is
 * piped through `next/headers#cookies()` so the framework writes them
 * to the outgoing response automatically.
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @param data     Initial session payload.
 * @returns The created `SessionRecord<T>`.
 * @throws {SessionError} `CONFIG_INVALID` when called outside a Next
 *                        server context.
 *
 * @example
 *   'use server';
 *   import { setServerSession } from '@authkit/sessions/frameworks/next';
 *   export async function login(formData: FormData) {
 *     await setServerSession(manager, { userId: ... });
 *   }
 */
export async function setServerSession<T extends SessionData>(
  manager: SessionManager<T>,
  data: T,
): Promise<SessionRecord<T>> {
  const cookieHeader = await readCookieHeader();
  const synthetic = new Request('https://next.local', {
    headers: cookieHeader ? { cookie: cookieHeader } : {},
  });
  const attachment = await manager.create(synthetic, data);
  await applyCookies(attachment.headers);
  return attachment.record;
}

async function readCookieHeader(): Promise<string | null> {
  try {
    const mod = await import('next/headers');
    const cookieJar = await mod.cookies();
    const all = cookieJar.getAll();
    if (all.length === 0) return null;
    return all.map((c) => `${c.name}=${c.value}`).join('; ');
  } catch (err) {
    throw new SessionError(
      'CONFIG_INVALID',
      'getServerSession/setServerSession must be called from a Next.js server context',
      err,
    );
  }
}

async function applyCookies(headers: Headers): Promise<void> {
  try {
    const mod = await import('next/headers');
    const cookieJar = await mod.cookies();
    for (const [name, value] of headers.entries()) {
      if (name.toLowerCase() !== 'set-cookie') continue;
      const eq = value.indexOf('=');
      if (eq === -1) continue;
      const cookieName = value.slice(0, eq);
      const rest = value.slice(eq + 1);
      const semi = rest.indexOf(';');
      const cookieValue = semi === -1 ? rest : rest.slice(0, semi);
      cookieJar.set(cookieName, cookieValue);
    }
  } catch (err) {
    throw new SessionError(
      'CONFIG_INVALID',
      'setServerSession must be called from a Next.js server context',
      err,
    );
  }
}
