import type { SessionManager, SessionAttachment } from '../../types/manager.js';
import type { SessionData, SessionRecord } from '../../types/session.js';

/**
 * Wrap a Next.js Route Handler so it receives the active session and
 * automatically merges any attachment headers (Set-Cookie) into the
 * outgoing `Response`.
 *
 * The wrapper passes through the handler's normal return value but
 * appends every `Set-Cookie` produced by the wrapped session helpers
 * (you call them via the `attach` callback).
 *
 * @typeParam T  Session payload shape.
 * @param manager  Manager instance.
 * @param handler  Async function receiving `(req, ctx)` where `ctx`
 *                 carries `session` and an `attach(att)` helper that
 *                 schedules an attachment to be merged into the
 *                 outgoing response.
 * @returns A function with the App Router Route Handler signature.
 *
 * @example
 *   export const POST = withSession(manager, async (req, { session, attach }) => {
 *     if (!session) return new Response('unauthorized', { status: 401 });
 *     const att = await manager.update(req, (d) => ({ ...d, lastAction: 'update' }));
 *     attach(att);
 *     return new Response(JSON.stringify(att.record.data), { status: 200 });
 *   });
 */
export function withSession<T extends SessionData>(
  manager: SessionManager<T>,
  handler: (
    req: Request,
    ctx: {
      session: SessionRecord<T> | null;
      attach: (attachment: SessionAttachment<T> | SessionAttachment<null>) => void;
    },
  ) => Promise<Response>,
): (req: Request) => Promise<Response> {
  return async (req) => {
    const session = await manager.get(req);
    const pending: (SessionAttachment<T> | SessionAttachment<null>)[] = [];
    const response = await handler(req, {
      session,
      attach: (a) => {
        pending.push(a);
      },
    });
    if (pending.length === 0) return response;
    const headers = new Headers(response.headers);
    for (const a of pending) a.attachTo(headers);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  };
}
