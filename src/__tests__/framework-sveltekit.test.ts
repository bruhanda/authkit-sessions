import { describe, expect, it } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { createSessionHandle } from '../frameworks/sveltekit/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

const buildEvent = (request: Request) => ({
  request,
  locals: {} as Record<string, unknown>,
});

describe('createSessionHandle', () => {
  it('should refuse to construct without csrf configured', () => {
    expect(() => createSessionHandle(buildManager<Data>())).toThrowError(SessionError);
  });

  it('should populate locals.session and call resolve', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const handle = createSessionHandle(mgr);
    const created = await mgr.create(new Request('https://example.com'), { userId: 'u' });
    const event = buildEvent(reqWithCookies(created.headers));
    const out = await handle({
      // biome-ignore lint/suspicious/noExplicitAny: SvelteKit's event type
      event: event as any,
      resolve: async () => new Response('ok'),
    });
    expect(await out.text()).toBe('ok');
    expect(event.locals['session']).toBeDefined();
    expect(event.locals['sessions']).toBe(mgr);
  });

  it('should return 403 on missing csrf for protected method', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const handle = createSessionHandle(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const event = buildEvent(
      reqWithCookies(created.headers, {
        method: 'POST',
        headers: { origin: 'https://example.com', host: 'example.com' },
      }),
    );
    const out = await handle({
      // biome-ignore lint/suspicious/noExplicitAny: SvelteKit's event type
      event: event as any,
      resolve: async () => new Response('ok'),
    });
    expect(out.status).toBe(403);
  });

  it('should accept a valid csrf token', async () => {
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    const handle = createSessionHandle(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const event = buildEvent(
      reqWithCookies(created.headers, {
        method: 'POST',
        headers: {
          origin: 'https://example.com',
          host: 'example.com',
          'x-csrf-token': created.record.meta.csrf,
        },
      }),
    );
    const out = await handle({
      // biome-ignore lint/suspicious/noExplicitAny: SvelteKit's event type
      event: event as any,
      resolve: async () => new Response('ok'),
    });
    expect(out.status).toBe(200);
  });

  it('should bypass csrf when opted out', async () => {
    const mgr = buildManager<Data>({ csrf: false });
    const handle = createSessionHandle(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const event = buildEvent(reqWithCookies(created.headers, { method: 'POST' }));
    const out = await handle({
      // biome-ignore lint/suspicious/noExplicitAny: SvelteKit's event type
      event: event as any,
      resolve: async () => new Response('ok'),
    });
    expect(out.status).toBe(200);
  });
});
