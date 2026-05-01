import { Elysia } from 'elysia';
import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { elysiaSessions } from '../frameworks/elysia/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('elysiaSessions plugin', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => elysiaSessions(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should expose session on derive', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const app = new Elysia()
      .use(elysiaSessions(mgr))
      .get('/me', ({ session }) => {
        const s = session as { data: Data } | null;
        return s ? `user:${s.data.userId ?? 'anon'}` : 'none';
      });
    const created = await mgr.create(new Request('https://example.com/me'), { userId: 'u' });
    const res = await app.handle(reqWithCookies(created.headers, { method: 'GET', url: 'https://example.com/me' }));
    expect(await res.text()).toBe('user:u');
  });

  it('should reject a POST without csrf', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Elysia().use(elysiaSessions(mgr)).post('/post', () => 'ok');
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.handle(
      reqWithCookies(created.headers, {
        url: 'https://example.com/post',
        method: 'POST',
        headers: { origin: 'https://example.com', host: 'example.com' },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('should accept a POST with valid csrf token', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = new Elysia().use(elysiaSessions(mgr)).post('/post', () => 'ok');
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.handle(
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

  it('should bypass csrf when opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const app = new Elysia().use(elysiaSessions(mgr)).post('/post', () => 'ok');
    const created = await mgr.create(new Request('https://example.com/post'), {});
    const res = await app.handle(reqWithCookies(created.headers, { method: 'POST', url: 'https://example.com/post' }));
    expect(res.status).toBe(200);
  });
});
