import { describe, expect, it, vi } from 'vitest';
import { createCookieCodec, createCookieStore } from '../adapters/cookie/index.js';
import { createMemoryStore } from '../adapters/memory/index.js';
import { audit } from '../features/audit/index.js';
import { concurrency } from '../features/concurrency/index.js';
import { csrf } from '../features/csrf/index.js';
import { fingerprint } from '../features/fingerprint/index.js';
import { createSessionManager } from '../core/manager.js';
import type { AuditEvent } from '../types/audit.js';
import { ALT_SECRET, makeClock, reqWithCookies, SECRET } from './_helpers.js';

interface UserData extends Record<string, unknown> {
  userId?: string;
  role?: string;
}

describe('integration: full lifecycle (memory store, all features)', () => {
  it('should support create → read → update → rotate → signOut', async () => {
    const events: AuditEvent[] = [];
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>(),
      getUserId: (d) => d.userId,
      csrf: csrf({}),
      fingerprint: fingerprint(),
      concurrency: concurrency({ max: 5 }),
      audit: audit((e) => {
        events.push(e);
      }),
    });
    const ua = { 'user-agent': 'TestBrowser/1.0', 'accept-language': 'en' };
    const r0 = new Request('https://example.com', { headers: ua });
    const created = await sessions.create(r0, { userId: 'alice' });
    expect(created.record.data.userId).toBe('alice');

    // Read on a fresh request with the same cookies/UA.
    const session = await sessions.get(reqWithCookies(created.headers, { headers: ua }));
    expect(session?.meta.id).toBe(created.record.meta.id);

    // Update.
    const updated = await sessions.update(
      reqWithCookies(created.headers, { headers: ua }),
      (d) => ({ ...d, role: 'admin' }),
    );
    expect(updated.record.data.role).toBe('admin');

    // Rotate.
    const rotated = await sessions.rotate(
      reqWithCookies(updated.headers, { headers: ua }),
    );
    expect(rotated.record.meta.id).not.toBe(updated.record.meta.id);

    // SignOut.
    const out = await sessions.signOut(reqWithCookies(rotated.headers, { headers: ua }));
    expect(out.record).toBeNull();

    // Audit events.
    const types = events.map((e) => e.type);
    expect(types).toContain('session.created');
    expect(types).toContain('session.read');
    expect(types).toContain('session.updated');
    expect(types).toContain('session.rotated');
    expect(types).toContain('session.destroyed');
  });
});

describe('integration: concurrency eviction', () => {
  it('should evict the LRU session when max is exceeded', async () => {
    const clock = makeClock();
    const events: AuditEvent[] = [];
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>({ clock }),
      clock,
      getUserId: (d) => d.userId,
      concurrency: concurrency({ max: 2, strategy: 'lru' }),
      audit: audit((e) => {
        events.push(e);
      }),
    });
    const a = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    clock.advance(5);
    const b = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    clock.advance(5);
    const c = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const ids = (await sessions.listByUser('u')).map((m) => m.id);
    expect(ids).toContain(b.record.meta.id);
    expect(ids).toContain(c.record.meta.id);
    expect(ids).not.toContain(a.record.meta.id);
    expect(events.some((e) => e.type === 'session.evicted')).toBe(true);
  });
});

describe('integration: cookie codec stateless mode', () => {
  it('should keep round-trip behaviour identical to stateful mode', async () => {
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createCookieStore<UserData>(),
      cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
      getUserId: (d) => d.userId,
      csrf: csrf({}),
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const session = await sessions.get(reqWithCookies(created.headers));
    expect(session?.data.userId).toBe('u');
    const out = await sessions.signOut(reqWithCookies(created.headers));
    expect(out.headers.getSetCookie()[0]).toContain('Max-Age=0');
  });

  it('should round-trip the new rotatePending field through the cookie codec', async () => {
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createCookieStore<UserData>(),
      cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
      fingerprint: fingerprint({ onMismatch: 'rotate' }),
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      { userId: 'u' },
    );
    const next = reqWithCookies(created.headers, { headers: { 'user-agent': 'B' } });
    const after = await sessions.get(next);
    expect(after?.meta.rotatePending).toBe(true);
    // The next mutation consumes rotatePending and rotates the id.
    const updated = await sessions.update(reqWithCookies(after ? created.headers : created.headers, { headers: { 'user-agent': 'B' } }), (d) => d);
    expect(updated.record.meta.id).not.toBe(created.record.meta.id);
  });
});

describe('integration: secret rotation', () => {
  it('should accept cookies signed with an old secret after rotation', async () => {
    const store = createMemoryStore<UserData>();
    const oldMgr = createSessionManager<UserData>({
      secrets: ALT_SECRET,
      store,
    });
    const created = await oldMgr.create(new Request('https://example.com'), {});
    const newMgr = createSessionManager<UserData>({
      secrets: [SECRET, ALT_SECRET],
      store,
    });
    const session = await newMgr.get(reqWithCookies(created.headers));
    expect(session?.meta.id).toBe(created.record.meta.id);
  });

  it('should rotate stateless cookies when both old and new secrets are listed', async () => {
    const oldCodec = createCookieCodec<UserData>({ secrets: ALT_SECRET });
    const newCodec = createCookieCodec<UserData>({ secrets: [SECRET, ALT_SECRET] });
    const oldMgr = createSessionManager<UserData>({
      secrets: ALT_SECRET,
      store: createCookieStore<UserData>(),
      cookieCodec: oldCodec,
    });
    const created = await oldMgr.create(new Request('https://example.com'), {});
    const newMgr = createSessionManager<UserData>({
      secrets: [SECRET, ALT_SECRET],
      store: createCookieStore<UserData>(),
      cookieCodec: newCodec,
    });
    expect(await newMgr.get(reqWithCookies(created.headers))).not.toBeNull();
  });
});

describe('integration: expiration and clock plumbing', () => {
  it('should null out a read past expiresAt + skew leeway', async () => {
    const clock = makeClock();
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>({ clock }),
      clock,
      expiration: { absoluteSeconds: 100, slidingSeconds: 0 },
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    clock.advance(200);
    expect(await sessions.get(reqWithCookies(created.headers))).toBeNull();
  });

  it('should slide expiration on read past the touch throttle', async () => {
    const clock = makeClock();
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>({ clock }),
      clock,
      expiration: {
        absoluteSeconds: 100_000,
        slidingSeconds: 10_000,
        rotateAfterSeconds: 0,
        touchThrottleSeconds: 1,
      },
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    clock.advance(100);
    const session = await sessions.get(reqWithCookies(created.headers));
    expect(session?.meta.expiresAt).toBeGreaterThan(created.record.meta.expiresAt);
  });
});

describe('integration: revoke flows', () => {
  it('should revoke every session for a user via revokeByUser', async () => {
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>(),
      getUserId: (d) => d.userId,
    });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect(await sessions.revokeByUser('u')).toBe(2);
    expect((await sessions.listByUser('u')).length).toBe(0);
  });

  it('should revoke a single session via revokeBySessionId', async () => {
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store: createMemoryStore<UserData>(),
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect(await sessions.revokeBySessionId(created.record.meta.id)).toBe(true);
    expect(await sessions.get(reqWithCookies(created.headers))).toBeNull();
  });
});

describe('integration: cookie + concurrency dev warning', () => {
  it('should warn once when concurrency is wired against the cookie codec', () => {
    const ENV = process.env['NODE_ENV'];
    delete process.env['NODE_ENV'];
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      createSessionManager<UserData>({
        secrets: SECRET,
        store: createCookieStore<UserData>(),
        cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
        concurrency: concurrency({ max: 5 }),
      });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0]?.[0]).toMatch(/concurrency feature/);
    } finally {
      warn.mockRestore();
      if (ENV === undefined) delete process.env['NODE_ENV'];
      else process.env['NODE_ENV'] = ENV;
    }
  });
});

describe('integration: rotatePending round-trip through stateful store', () => {
  it('should persist rotatePending in the metadata blob', async () => {
    const store = createMemoryStore<UserData>();
    const sessions = createSessionManager<UserData>({
      secrets: SECRET,
      store,
      fingerprint: fingerprint({ onMismatch: 'rotate' }),
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      { userId: 'u' },
    );
    await sessions.get(
      reqWithCookies(created.headers, { headers: { 'user-agent': 'B' } }),
    );
    const stored = await store.read(created.record.meta.id);
    expect(stored?.meta.rotatePending).toBe(true);
  });
});
