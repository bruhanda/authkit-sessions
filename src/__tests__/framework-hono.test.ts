import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { honoSessions } from '../frameworks/hono/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('honoSessions middleware', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => honoSessions(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should set c.var.session and c.var.sessions', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.get('/me', (c) => {
      const sess = c.var.session;
      return c.text(sess ? `user:${sess.data.userId ?? 'anon'}` : 'none');
    });
    const created = await mgr.create(new Request('https://example.com/me'), { userId: 'u' });
    const res = await app.fetch(reqWithCookies(created.headers, { method: 'GET', url: 'https://example.com/me' }));
    expect(await res.text()).toBe('user:u');
  });

  it('should return 403 on a missing CSRF token for a protected method', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.post('/post', (c) => c.text('ok'));
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.fetch(
      reqWithCookies(created.headers, {
        url: 'https://example.com/post',
        method: 'POST',
        headers: { origin: 'https://example.com', host: 'example.com' },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('should accept a matching CSRF token + Origin', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.post('/post', (c) => c.text('ok'));
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.fetch(
      reqWithCookies(created.headers, {
        url: 'https://example.com/post',
        method: 'POST',
        headers: {
          origin: 'https://example.com',
          host: 'example.com',
          'x-csrf-token': created.record.meta.csrf,
        },
      }),
    );
    expect(res.status).toBe(200);
  });

  it('should reject mismatched Origin', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.post('/post', (c) => c.text('ok'));
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.fetch(
      reqWithCookies(created.headers, {
        url: 'https://example.com/post',
        method: 'POST',
        headers: {
          origin: 'https://evil.com',
          host: 'example.com',
          'x-csrf-token': created.record.meta.csrf,
        },
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.text()).toBe('forbidden');
  });

  it('should bypass CSRF enforcement for safe methods', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.get('/ok', (c) => c.text('ok'));
    const created = await mgr.create(new Request('https://example.com/ok'), {});
    const res = await app.fetch(reqWithCookies(created.headers, { method: 'GET', url: 'https://example.com/ok' }));
    expect(res.status).toBe(200);
  });

  it('should bypass CSRF when the manager opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const app = new Hono();
    app.use('*', honoSessions(mgr));
    app.post('/post', (c) => c.text('ok'));
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.fetch(reqWithCookies(created.headers, { method: 'POST', url: 'https://example.com/post' }));
    expect(res.status).toBe(200);
  });
});
