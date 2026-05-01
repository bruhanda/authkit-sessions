import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { withSession } from '../frameworks/next/route-handler.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('withSession (Next.js route handler wrapper)', () => {
  it('should populate ctx.session from the active cookie', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const created = await mgr.create(new Request('https://example.com'), { userId: 'u' });
    const handler = withSession<Data>(mgr, async (_req, { session }) => {
      return new Response(session ? `user:${session.data.userId ?? 'anon'}` : 'none');
    });
    const res = await handler(reqWithCookies(created.headers));
    expect(await res.text()).toBe('user:u');
  });

  it('should pass through the original Response when no attachment is scheduled', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const handler = withSession<Data>(mgr, async () => new Response('ok', { status: 201 }));
    const res = await handler(new Request('https://example.com'));
    expect(res.status).toBe(201);
    expect(res.headers.getSetCookie().length).toBe(0);
  });

  it('should merge attached Set-Cookie headers into the outgoing Response', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const handler = withSession<Data>(mgr, async (req, { attach }) => {
      const att = await mgr.create(req, { userId: 'u' });
      attach(att);
      return new Response('created', { status: 201 });
    });
    const res = await handler(new Request('https://example.com'));
    expect(res.status).toBe(201);
    expect(res.headers.getSetCookie().length).toBeGreaterThan(0);
  });

  it('should preserve content-type and other response headers when attaching cookies', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const handler = withSession<Data>(mgr, async (req, { attach }) => {
      const att = await mgr.create(req, {});
      attach(att);
      return new Response('{}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const res = await handler(new Request('https://example.com'));
    expect(res.headers.get('content-type')).toBe('application/json');
  });

  it('should handle multiple sequential attachments', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const handler = withSession<Data>(mgr, async (req, { attach }) => {
      const a = await mgr.create(req, { userId: 'u' });
      attach(a);
      const b = await mgr.signOut(reqWithCookies(a.headers));
      attach(b);
      return new Response('done');
    });
    const res = await handler(new Request('https://example.com'));
    expect(res.headers.getSetCookie().length).toBeGreaterThanOrEqual(2);
  });
});
