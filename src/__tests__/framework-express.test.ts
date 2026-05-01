import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { expressSessions } from '../frameworks/express/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('expressSessions middleware', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => expressSessions(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should expose req.session for handlers', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const app = express();
    app.use(expressSessions(mgr));
    app.get('/me', (req, res) => {
      const session = (req as unknown as { session: { data: Data } | null }).session;
      res.send(session ? `user:${session.data.userId ?? 'anon'}` : 'none');
    });
    const created = await mgr.create(new Request('https://example.com/me'), { userId: 'u' });
    const cookieHeader = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const res = await request(app).get('/me').set('Cookie', cookieHeader);
    expect(res.text).toBe('user:u');
  });

  it('should return 403 on missing csrf', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = express();
    app.use(expressSessions(mgr));
    app.post('/x', (_req, res) => res.send('ok'));
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const cookieHeader = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const res = await request(app)
      .post('/x')
      .set('Cookie', cookieHeader)
      .set('origin', 'https://example.com')
      .set('host', 'example.com');
    expect(res.status).toBe(403);
  });

  it('should allow safe GETs without csrf token', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = express();
    app.use(expressSessions(mgr));
    app.get('/x', (_req, res) => res.send('ok'));
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const cookieHeader = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const res = await request(app).get('/x').set('Cookie', cookieHeader);
    expect(res.status).toBe(200);
  });

  it('should accept a valid csrf token + Origin', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const app = express();
    app.use(expressSessions(mgr));
    app.post('/x', (_req, res) => res.send('ok'));
    const created = await mgr.create(new Request('https://example.com/x'), {});
    const cookieHeader = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const res = await request(app)
      .post('/x')
      .set('Cookie', cookieHeader)
      .set('origin', 'https://example.com')
      .set('host', 'example.com')
      .set('x-csrf-token', created.record.meta.csrf);
    expect(res.status).toBe(200);
  });
});

void reqWithCookies;
