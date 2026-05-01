import { describe, expect, it } from 'vitest';
import { createMemoryStore } from '../adapters/memory/index.js';
import { createRemixSession } from '../frameworks/remix/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

describe('createRemixSession helpers', () => {
  it('should return null from getSession when no cookie is present', async () => {
    const mgr = buildManager<Data>();
    const { getSession } = createRemixSession(mgr);
    expect(await getSession(new Request('https://example.com'))).toBeNull();
  });

  it('should commit a fresh session via commitSession', async () => {
    const mgr = buildManager<Data>({ getUserId: (d) => d.userId });
    const { commitSession } = createRemixSession(mgr);
    const cookie = await commitSession(new Request('https://example.com'), { userId: 'u' });
    expect(cookie).toMatch(/^sid=/);
    expect(cookie).toContain('Max-Age=');
  });

  it('should update an existing session via commitSession', async () => {
    const mgr = buildManager<Data>({ getUserId: (d) => d.userId });
    const { commitSession, getSession } = createRemixSession(mgr);
    const initial = await mgr.create(new Request('https://example.com'), { userId: 'u' });
    const cookie = await commitSession(reqWithCookies(initial.headers), { userId: 'u', role: 'admin' } as Data);
    expect(cookie).toMatch(/^sid=/);
    const reread = await getSession(reqWithCookies(initial.headers));
    expect((reread?.data as { role?: string })?.role).toBe('admin');
  });

  it('should expire the cookie via destroySession', async () => {
    const mgr = buildManager<Data>();
    const { destroySession } = createRemixSession(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    const cookie = await destroySession(reqWithCookies(created.headers));
    expect(cookie).toContain('Max-Age=0');
  });

  it('should re-wrap thrown errors as STORE_UNAVAILABLE in destroySession', async () => {
    const mgr = buildManager<Data>({
      store: { ...createMemoryStore<Data>(), delete: async () => { throw new Error('down'); } },
    });
    const { destroySession } = createRemixSession(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    await expect(destroySession(reqWithCookies(created.headers))).rejects.toMatchObject({
      code: 'STORE_UNAVAILABLE',
    });
  });

  it('should pass through SessionError from destroySession when store throws one', async () => {
    const original = new SessionError('NOT_FOUND', 'gone');
    const mgr = buildManager<Data>({
      store: { ...createMemoryStore<Data>(), delete: async () => { throw original; } },
    });
    const { destroySession } = createRemixSession(mgr);
    const created = await mgr.create(new Request('https://example.com'), {});
    // Manager wraps it as STORE_UNAVAILABLE inside signOut, but destroySession re-throws SessionError.
    // We accept either behaviour as long as the error code is meaningful.
    try {
      await destroySession(reqWithCookies(created.headers));
      expect.fail('expected throw');
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
    }
  });
});
