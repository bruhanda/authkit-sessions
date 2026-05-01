import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { createSessionMiddleware } from '../frameworks/next/middleware.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('createSessionMiddleware', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => createSessionMiddleware(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should pass through safe methods without enforcement', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const mw = createSessionMiddleware<Data>(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    // Use a Request as the NextRequest stand-in; cast at call site.
    const res = await mw(reqWithCookies(created.headers, { method: 'GET' }) as unknown as import('next/server').NextRequest);
    expect(res.status).toBe(200);
  });

  it('should return 403 on missing csrf for protected method', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const mw = createSessionMiddleware<Data>(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const res = await mw(
      reqWithCookies(created.headers, {
        method: 'POST',
        headers: { origin: 'https://example.com', host: 'example.com' },
      }) as unknown as import('next/server').NextRequest,
    );
    expect(res.status).toBe(403);
  });

  it('should accept a valid csrf token', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const mw = createSessionMiddleware<Data>(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const res = await mw(
      reqWithCookies(created.headers, {
        method: 'POST',
        headers: {
          origin: 'https://example.com',
          host: 'example.com',
          'x-csrf-token': created.record.meta.csrf,
        },
      }) as unknown as import('next/server').NextRequest,
    );
    expect(res.status).toBe(200);
  });

  it('should bypass csrf when opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const mw = createSessionMiddleware<Data>(mgr);
    const res = await mw(new Request('https://example.com', { method: 'POST' }) as unknown as import('next/server').NextRequest);
    expect(res.status).toBe(200);
  });

  it('should not enforce csrf for unauthenticated POST (no session)', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const mw = createSessionMiddleware<Data>(mgr);
    const res = await mw(new Request('https://example.com', { method: 'POST' }) as unknown as import('next/server').NextRequest);
    expect(res.status).toBe(200);
  });
});
