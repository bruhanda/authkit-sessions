import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { h3Sessions } from '../frameworks/h3/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

interface FakeH3Event {
  context: Record<string, unknown>;
  method: string;
  path: string;
  node: { req: { headers: Record<string, string | string[] | undefined>; url: string } };
}

const buildFakeEvent = (overrides: Partial<FakeH3Event> = {}): FakeH3Event => ({
  method: 'GET',
  path: '/',
  context: {},
  node: { req: { headers: {}, url: '/' } },
  ...overrides,
});

describe('h3Sessions handler', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => h3Sessions(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should populate event.context.session', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const created = await mgr.create(new Request('https://example.com/'), { userId: 'u' });
    const cookie = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const handler = h3Sessions(mgr);
    const event = buildFakeEvent({
      node: { req: { headers: { cookie, host: 'example.com' }, url: '/me' } },
    });
    const res = await handler(event as unknown as import('h3').H3Event);
    expect(res).toBeUndefined();
    expect(event.context['session']).toBeDefined();
    expect((event.context['session'] as { data: Data }).data.userId).toBe('u');
  });

  it('should return 403 on missing csrf', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const created = await mgr.create(new Request('https://example.com/'), {});
    const cookie = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const handler = h3Sessions(mgr);
    const event = buildFakeEvent({
      method: 'POST',
      path: '/x',
      node: {
        req: {
          headers: { cookie, host: 'example.com', origin: 'https://example.com' },
          url: '/x',
        },
      },
    });
    const res = await handler(event as unknown as import('h3').H3Event);
    expect(res).toBeInstanceOf(Response);
    expect((res as Response).status).toBe(403);
  });

  it('should accept a valid csrf token + Origin', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const created = await mgr.create(new Request('https://example.com/'), {});
    const cookie = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const handler = h3Sessions(mgr);
    const event = buildFakeEvent({
      method: 'POST',
      path: '/x',
      node: {
        req: {
          headers: {
            cookie,
            host: 'example.com',
            origin: 'https://example.com',
            'x-csrf-token': created.record.meta.csrf,
          },
          url: '/x',
        },
      },
    });
    const res = await handler(event as unknown as import('h3').H3Event);
    expect(res).toBeUndefined();
  });

  it('should bypass csrf when opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const created = await mgr.create(new Request('https://example.com/'), {});
    const cookie = created.headers
      .getSetCookie()
      .map((line) => line.split(';')[0])
      .join('; ');
    const handler = h3Sessions(mgr);
    const event = buildFakeEvent({
      method: 'POST',
      path: '/x',
      node: { req: { headers: { cookie, host: 'example.com' }, url: '/x' } },
    });
    const res = await handler(event as unknown as import('h3').H3Event);
    expect(res).toBeUndefined();
  });
});
