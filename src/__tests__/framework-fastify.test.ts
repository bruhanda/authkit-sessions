import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { fastifySessions } from '../frameworks/fastify/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

const cookieHeaderFor = (att: { headers: Headers }): string =>
  att.headers
    .getSetCookie()
    .map((line) => line.split(';')[0])
    .join('; ');

describe('fastifySessions plugin', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => fastifySessions(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should expose request.session for handlers', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const app = Fastify();
    await app.register(fastifySessions(mgr));
    app.get('/me', async (req) => {
      const session = (req as unknown as { session: { data: Data } | null }).session;
      return session ? `user:${session.data.userId ?? 'anon'}` : 'none';
    });
    const created = await mgr.create(new Request('https://example.com/me'), { userId: 'u' });
    const res = await app.inject({
      method: 'GET',
      url: '/me',
      headers: { cookie: cookieHeaderFor(created) },
    });
    expect(res.body).toBe('user:u');
    await app.close();
  });

  it('should return 403 on a missing csrf token for protected method', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = Fastify();
    await app.register(fastifySessions(mgr));
    app.post('/x', async () => 'ok');
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const res = await app.inject({
      method: 'POST',
      url: '/x',
      headers: { cookie: cookieHeaderFor(created), origin: 'https://example.com', host: 'example.com' },
    });
    expect(res.statusCode).toBe(403);
    await app.close();
  });

  it('should accept a valid csrf token + Origin', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = Fastify();
    await app.register(fastifySessions(mgr));
    app.post('/x', async () => 'ok');
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const res = await app.inject({
      method: 'POST',
      url: '/x',
      headers: {
        cookie: cookieHeaderFor(created),
        origin: 'https://example.com',
        host: 'example.com',
        'x-csrf-token': created.record.meta.csrf,
      },
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it('should bypass csrf when opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const app = Fastify();
    await app.register(fastifySessions(mgr));
    app.post('/x', async () => 'ok');
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const res = await app.inject({
      method: 'POST',
      url: '/x',
      headers: { cookie: cookieHeaderFor(created) },
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });
});
