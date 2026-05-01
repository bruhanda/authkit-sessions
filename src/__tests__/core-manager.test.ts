import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCookieCodec, createCookieStore } from '../adapters/cookie/index.js';
import { createMemoryStore } from '../adapters/memory/index.js';
import { createSessionManager, defaultIpExtractor } from '../core/manager.js';
import { SessionError } from '../errors/base.js';
import { audit } from '../features/audit/index.js';
import { concurrency } from '../features/concurrency/index.js';
import { csrf } from '../features/csrf/index.js';
import { fingerprint } from '../features/fingerprint/index.js';
import type { AuditEvent } from '../types/audit.js';
import { ALT_SECRET, buildManager, makeClock, readCookie, reqWithCookies, SECRET } from './_helpers.js';

interface UserData extends Record<string, unknown> {
  userId?: string;
  role?: string;
}

describe('createSessionManager — config validation', () => {
  it('should throw CONFIG_INVALID when secrets is undefined', () => {
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: testing runtime guards
      buildManager({ secrets: undefined as any }),
    ).toThrowError(/secrets is required/);
  });

  it('should throw CONFIG_INVALID when store is undefined', () => {
    // Bypass `buildManager`'s default-store fallback by calling the factory directly.
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: testing runtime guards
      createSessionManager({ secrets: SECRET, store: undefined as any }),
    ).toThrowError(/store is required/);
  });

  it('should throw CONFIG_INVALID when secrets is an empty array', () => {
    expect(() => buildManager({ secrets: [] })).toThrowError(/at least one secret/);
  });

  it('should throw SECRET_TOO_SHORT for secrets <32 bytes', () => {
    expect(() => buildManager({ secrets: 'tooshort' })).toThrowError(SessionError);
    try {
      buildManager({ secrets: 'tooshort' });
    } catch (err) {
      expect((err as SessionError).code).toBe('SECRET_TOO_SHORT');
    }
  });

  it('should accept a single string secret of >=32 bytes', () => {
    expect(() => buildManager({ secrets: SECRET })).not.toThrow();
  });

  it('should accept a single Uint8Array secret', () => {
    expect(() => buildManager({ secrets: new Uint8Array(32) })).not.toThrow();
  });

  it('should accept an array of secrets for rotation', () => {
    expect(() => buildManager({ secrets: [SECRET, ALT_SECRET] })).not.toThrow();
  });
});

describe('SessionManager.create / get', () => {
  it('should create a session and emit a Set-Cookie carrying it', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const att = await sessions.create(new Request('https://example.com'), { userId: 'user_1' });
    expect(att.record).not.toBeNull();
    expect(att.record.meta.userId).toBe('user_1');
    expect(att.record.meta.id.length).toBe(43);
    expect(att.record.meta.csrf.length).toBe(43);
    expect(att.headers.getSetCookie().length).toBeGreaterThan(0);
  });

  it('should make the new session readable via get() on a follow-up request', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'user_1' });
    const next = reqWithCookies(created.headers);
    const session = await sessions.get(next);
    expect(session?.meta.id).toBe(created.record.meta.id);
    expect(session?.data.userId).toBe('user_1');
  });

  it('should return null from get() when no cookie is present', async () => {
    const sessions = buildManager<UserData>();
    expect(await sessions.get(new Request('https://example.com'))).toBeNull();
  });

  it('should return null from get() on a tampered cookie', async () => {
    const sessions = buildManager<UserData>();
    const att = await sessions.create(new Request('https://example.com'), {});
    const cookie = att.headers.getSetCookie()[0]?.split(';')[0]?.split('=')[1];
    // Tamper with the tag portion.
    const tampered = `${cookie?.slice(0, 43)}.AAAAAAAAAAAAAA`;
    const req = new Request('https://example.com', {
      headers: { cookie: `sid=${tampered}` },
    });
    expect(await sessions.get(req)).toBeNull();
  });
});

describe('SessionManager.update', () => {
  it('should replace the data via the mutator', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const updated = await sessions.update(reqWithCookies(created.headers), (d) => ({
      ...d,
      role: 'admin',
    }));
    expect(updated.record.data.role).toBe('admin');
    expect(updated.record.meta.id).toBe(created.record.meta.id);
  });

  it('should throw NOT_FOUND when there is no active session', async () => {
    const sessions = buildManager<UserData>();
    await expect(
      sessions.update(new Request('https://example.com'), (d) => d),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('should rotate id+csrf when rotatePending is set on metadata', async () => {
    const clock = makeClock();
    const fp = fingerprint({ onMismatch: 'rotate' });
    const sessions = buildManager<UserData>({
      clock,
      fingerprint: fp,
      getUserId: (d) => d.userId,
    });
    const reqA = new Request('https://example.com', {
      headers: { 'user-agent': 'Browser-A', 'accept-language': 'en' },
    });
    const created = await sessions.create(reqA, { userId: 'u' });
    // Same cookie, different fingerprint → readActive flags rotatePending.
    const reqB = reqWithCookies(created.headers, {
      headers: { 'user-agent': 'Browser-B', 'accept-language': 'en' },
    });
    await sessions.get(reqB); // Triggers rotatePending=true.
    const reqC = reqWithCookies(created.headers, {
      headers: { 'user-agent': 'Browser-B', 'accept-language': 'en' },
    });
    const updated = await sessions.update(reqC, (d) => d);
    expect(updated.record.meta.id).not.toBe(created.record.meta.id);
    expect(updated.record.meta.csrf).not.toBe(created.record.meta.csrf);
  });

  it('should throw CONFLICT after two store.update failures', async () => {
    const real = createMemoryStore<UserData>();
    const failingStore = {
      ...real,
      update: async () => false,
    };
    const sessions = buildManager<UserData>({ store: failingStore, getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await expect(
      sessions.update(reqWithCookies(created.headers), (d) => d),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should retry once and succeed when update succeeds the second time', async () => {
    const real = createMemoryStore<UserData>();
    let calls = 0;
    const flakyStore = {
      ...real,
      update: async (r: Parameters<typeof real.update>[0]) => {
        calls++;
        if (calls === 1) return false;
        return real.update(r);
      },
    };
    const sessions = buildManager<UserData>({ store: flakyStore, getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const att = await sessions.update(reqWithCookies(created.headers), (d) => ({
      ...d,
      role: 'admin',
    }));
    expect(att.record.data.role).toBe('admin');
    expect(calls).toBeGreaterThanOrEqual(2);
  });
});

describe('SessionManager.rotate', () => {
  it('should mint a fresh id+csrf and delete the old record', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const rotated = await sessions.rotate(reqWithCookies(created.headers));
    expect(rotated.record.meta.id).not.toBe(created.record.meta.id);
    expect(rotated.record.meta.csrf).not.toBe(created.record.meta.csrf);
    // Old cookie no longer reads — store no longer has the old id.
    const stale = reqWithCookies(created.headers);
    expect(await sessions.get(stale)).toBeNull();
  });

  it('should throw NOT_FOUND when called without an active session', async () => {
    const sessions = buildManager<UserData>();
    await expect(sessions.rotate(new Request('https://example.com'))).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('should re-wrap a delete-failure as STORE_UNAVAILABLE', async () => {
    const real = createMemoryStore<UserData>();
    const sessions = buildManager<UserData>({
      store: {
        ...real,
        delete: async () => {
          throw new Error('redis down');
        },
      },
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await expect(sessions.rotate(reqWithCookies(created.headers))).rejects.toMatchObject({
      code: 'STORE_UNAVAILABLE',
    });
  });
});

describe('SessionManager.signOut', () => {
  it('should expire the cookie and delete the record', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const out = await sessions.signOut(reqWithCookies(created.headers));
    expect(out.record).toBeNull();
    expect(out.headers.getSetCookie()[0]).toContain('Max-Age=0');
    expect(await sessions.get(reqWithCookies(created.headers))).toBeNull();
  });

  it('should be idempotent when called without an active session', async () => {
    const sessions = buildManager<UserData>();
    const out = await sessions.signOut(new Request('https://example.com'));
    expect(out.record).toBeNull();
    expect(out.headers.getSetCookie()[0]).toContain('Max-Age=0');
  });

  it('should propagate STORE_UNAVAILABLE when the store fails to delete', async () => {
    const real = createMemoryStore<UserData>();
    const sessions = buildManager<UserData>({
      store: {
        ...real,
        delete: async () => {
          throw new Error('redis down');
        },
      },
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    await expect(sessions.signOut(reqWithCookies(created.headers))).rejects.toMatchObject({
      code: 'STORE_UNAVAILABLE',
    });
  });

  it('should also expire the CSRF mirror cookie when csrf is enabled', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const created = await sessions.create(new Request('https://example.com'), {});
    const out = await sessions.signOut(reqWithCookies(created.headers));
    const lines = out.headers.getSetCookie();
    expect(lines.length).toBe(2);
    for (const line of lines) expect(line).toContain('Max-Age=0');
  });
});

describe('SessionManager.revokeBySessionId / revokeByUser / listByUser', () => {
  it('should revoke a single session by id', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    const att = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect(await sessions.revokeBySessionId(att.record.meta.id)).toBe(true);
    expect(await sessions.revokeBySessionId(att.record.meta.id)).toBe(false);
  });

  it('should revoke every session for a user', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect(await sessions.revokeByUser('u')).toBe(2);
  });

  it('should list active sessions for a user', async () => {
    const sessions = buildManager<UserData>({ getUserId: (d) => d.userId });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect((await sessions.listByUser('u')).length).toBe(2);
  });
});

describe('CSRF', () => {
  it('should emit a non-HttpOnly mirror cookie when the feature is enabled', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const att = await sessions.create(new Request('https://example.com'), {});
    const lines = att.headers.getSetCookie();
    const mirror = lines.find((l) => l.startsWith('csrf='));
    expect(mirror).toBeDefined();
    expect(mirror).not.toContain('HttpOnly');
  });

  it('should verify a matching token for an active session', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const created = await sessions.create(new Request('https://example.com'), {});
    expect(await sessions.verifyCsrf(reqWithCookies(created.headers), created.record.meta.csrf)).toBe(true);
  });

  it('should reject a mismatched token', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const created = await sessions.create(new Request('https://example.com'), {});
    expect(await sessions.verifyCsrf(reqWithCookies(created.headers), 'nope')).toBe(false);
  });

  it('should return false from verifyCsrf when no session exists', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    expect(await sessions.verifyCsrf(new Request('https://example.com'), 'token')).toBe(false);
  });

  it('should return false from verifyCsrf when token is empty', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const created = await sessions.create(new Request('https://example.com'), {});
    expect(await sessions.verifyCsrf(reqWithCookies(created.headers), '')).toBe(false);
  });

  it('should expose the active CSRF token via getCsrfToken', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const created = await sessions.create(new Request('https://example.com'), {});
    expect(await sessions.getCsrfToken(reqWithCookies(created.headers))).toBe(created.record.meta.csrf);
  });

  it('should return null from getCsrfToken when no session exists', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    expect(await sessions.getCsrfToken(new Request('https://example.com'))).toBeNull();
  });
});

describe('Fingerprint feature', () => {
  it('should attach a device hash to created sessions', async () => {
    const sessions = buildManager<UserData>({ fingerprint: fingerprint() });
    const att = await sessions.create(
      new Request('https://example.com', {
        headers: { 'user-agent': 'A', 'accept-language': 'en' },
      }),
      {},
    );
    expect(att.record.meta.device?.hash).toBeDefined();
    expect(att.record.meta.device?.userAgent).toBe('A');
  });

  it("should destroy the session when onMismatch='destroy' and fingerprint differs", async () => {
    const sessions = buildManager<UserData>({
      fingerprint: fingerprint({ onMismatch: 'destroy' }),
    });
    const created = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      {},
    );
    const next = reqWithCookies(created.headers, { headers: { 'user-agent': 'B' } });
    expect(await sessions.get(next)).toBeNull();
  });

  it("should ignore a fingerprint mismatch when onMismatch='ignore'", async () => {
    const sessions = buildManager<UserData>({
      fingerprint: fingerprint({ onMismatch: 'ignore' }),
    });
    const created = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      {},
    );
    const next = reqWithCookies(created.headers, { headers: { 'user-agent': 'B' } });
    expect(await sessions.get(next)).not.toBeNull();
  });

  it('should refresh meta.device on rotate-mismatch so subsequent reads do not loop', async () => {
    const sessions = buildManager<UserData>({
      fingerprint: fingerprint({ onMismatch: 'rotate' }),
    });
    const created = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      {},
    );
    // First get on Browser-B sets rotatePending and refreshes device.hash.
    const reqB1 = reqWithCookies(created.headers, { headers: { 'user-agent': 'B' } });
    const after = await sessions.get(reqB1);
    expect(after?.meta.rotatePending).toBe(true);
    expect(after?.meta.device?.hash).not.toBe(created.record.meta.device?.hash);
  });

  it('should accept ip in the include set and call the IP extractor', async () => {
    const sessions = buildManager<UserData>({
      fingerprint: fingerprint({
        include: ['user-agent', 'ip'],
        ip: () => '203.0.113.1',
      }),
    });
    const att = await sessions.create(
      new Request('https://example.com', { headers: { 'user-agent': 'A' } }),
      {},
    );
    expect(att.record.meta.device?.ip).toBeDefined();
  });

  it('should pick up sec-ch-ua-platform when sec-ch-ua is included', async () => {
    const sessions = buildManager<UserData>({
      fingerprint: fingerprint({ include: ['sec-ch-ua'] }),
    });
    const att = await sessions.create(
      new Request('https://example.com', {
        headers: { 'sec-ch-ua': '"Chromium";v="120"', 'sec-ch-ua-platform': 'Windows' },
      }),
      {},
    );
    expect(att.record.meta.device?.platform).toBe('Windows');
  });
});

describe('Concurrency feature', () => {
  it('should evict LRU sessions when the limit is hit', async () => {
    const sessions = buildManager<UserData>({
      concurrency: concurrency({ max: 2 }),
      getUserId: (d) => d.userId,
    });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await new Promise((r) => setTimeout(r, 10));
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await new Promise((r) => setTimeout(r, 10));
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    expect((await sessions.listByUser('u')).length).toBe(2);
  });

  it("should throw CONCURRENCY_DENIED with strategy 'deny-new'", async () => {
    const sessions = buildManager<UserData>({
      concurrency: concurrency({ max: 1, strategy: 'deny-new' }),
      getUserId: (d) => d.userId,
    });
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await expect(
      sessions.create(new Request('https://example.com'), { userId: 'u' }),
    ).rejects.toMatchObject({ code: 'CONCURRENCY_DENIED' });
  });

  it("should evict the oldest session under fifo strategy", async () => {
    const clock = makeClock();
    const sessions = buildManager<UserData>({
      clock,
      concurrency: concurrency({ max: 2, strategy: 'fifo' }),
      getUserId: (d) => d.userId,
    });
    const a = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    clock.advance(5);
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    clock.advance(5);
    await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const all = await sessions.listByUser('u');
    expect(all.find((m) => m.id === a.record.meta.id)).toBeUndefined();
  });

  it('should be a no-op when the user is anonymous (no userId)', async () => {
    const sessions = buildManager<UserData>({
      concurrency: concurrency({ max: 1 }),
      getUserId: () => undefined,
    });
    await sessions.create(new Request('https://example.com'), {});
    await sessions.create(new Request('https://example.com'), {});
    // Both should succeed; no userId means concurrency does not apply.
  });
});

describe('Audit feature', () => {
  it('should emit lifecycle events through the hook', async () => {
    const events: AuditEvent[] = [];
    const sessions = buildManager<UserData>({
      audit: audit((e) => {
        events.push(e);
      }),
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    await sessions.get(reqWithCookies(created.headers));
    await sessions.signOut(reqWithCookies(created.headers));
    const types = events.map((e) => e.type);
    expect(types).toContain('session.created');
    expect(types).toContain('session.read');
    expect(types).toContain('session.destroyed');
  });

  it('should swallow audit hook errors silently', async () => {
    const sessions = buildManager<UserData>({
      audit: audit(() => {
        throw new Error('hook broken');
      }),
    });
    await expect(sessions.create(new Request('https://example.com'), {})).resolves.toBeDefined();
  });

  it('should emit session.destroyed and session.read.failed on EXPIRED reads', async () => {
    // Use a store that does not auto-clean expired records, so the manager's
    // own expiration path fires (memory store wipes on read otherwise).
    const events: AuditEvent[] = [];
    const clock = makeClock();
    const real = createMemoryStore<UserData>({ clock: () => clock() - 10_000 }); // store sees "earlier" → never auto-cleans.
    const sessions = buildManager<UserData>({
      store: real,
      audit: audit((e) => {
        events.push(e);
      }),
      clock,
      expiration: { absoluteSeconds: 100, slidingSeconds: 0 },
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    clock.advance(1_000); // Manager sees expired; store still treats record as alive.
    await sessions.get(reqWithCookies(created.headers));
    const types = events.map((e) => e.type);
    expect(types).toContain('session.read.failed');
    expect(types).toContain('session.destroyed');
    const destroyedReason = events.find((e) => e.type === 'session.destroyed');
    expect(destroyedReason && 'reason' in destroyedReason ? destroyedReason.reason : null).toBe('expired');
  });

  it('should emit csrf.failed events with reasons', async () => {
    const events: AuditEvent[] = [];
    const sessions = buildManager<UserData>({
      audit: audit((e) => {
        events.push(e);
      }),
      csrf: csrf({}),
    });
    // No session at all → 'no-session'.
    await sessions.verifyCsrf(new Request('https://example.com'), 'tok');
    const created = await sessions.create(new Request('https://example.com'), {});
    // Token missing → 'missing'.
    await sessions.verifyCsrf(reqWithCookies(created.headers), '');
    // Token mismatch → 'mismatch'.
    await sessions.verifyCsrf(reqWithCookies(created.headers), 'wrong');
    const reasons = events.filter((e) => e.type === 'csrf.failed').map((e) => e.type === 'csrf.failed' ? e.reason : null);
    expect(reasons).toContain('no-session');
    expect(reasons).toContain('missing');
    expect(reasons).toContain('mismatch');
  });
});

describe('Expiration / clock plumbing', () => {
  it('should return null after the absolute window elapses', async () => {
    const clock = makeClock();
    const sessions = buildManager<UserData>({
      clock,
      expiration: { absoluteSeconds: 100, slidingSeconds: 0 },
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    clock.advance(200);
    expect(await sessions.get(reqWithCookies(created.headers))).toBeNull();
  });

  it('should slide expiration on read when sliding > 0', async () => {
    const clock = makeClock();
    const sessions = buildManager<UserData>({
      clock,
      expiration: {
        absoluteSeconds: 100_000,
        slidingSeconds: 1_000,
        rotateAfterSeconds: 0,
        touchThrottleSeconds: 0,
      },
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    clock.advance(500);
    const r1 = await sessions.get(reqWithCookies(created.headers));
    expect(r1?.meta.expiresAt).toBeGreaterThan(created.record.meta.expiresAt);
  });
});

describe('SessionAttachment.attachTo', () => {
  it('should append Set-Cookie entries onto the supplied Headers', async () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    const att = await sessions.create(new Request('https://example.com'), {});
    const target = new Headers();
    target.append('content-type', 'application/json');
    att.attachTo(target);
    expect(target.getSetCookie().length).toBe(2);
    expect(target.get('content-type')).toBe('application/json');
  });

  it('should not duplicate entries already on the target', async () => {
    const sessions = buildManager<UserData>();
    const att = await sessions.create(new Request('https://example.com'), {});
    const target = new Headers();
    target.append('Set-Cookie', 'pre=existing; Path=/');
    att.attachTo(target);
    expect(target.getSetCookie().length).toBe(2);
  });
});

describe('Cookie codec mode', () => {
  it('should round-trip a session using the cookie codec', async () => {
    const sessions = buildManager<UserData>({
      store: createCookieStore<UserData>(),
      cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
      getUserId: (d) => d.userId,
    });
    const created = await sessions.create(new Request('https://example.com'), { userId: 'u' });
    const session = await sessions.get(reqWithCookies(created.headers));
    expect(session?.data.userId).toBe('u');
  });

  it('should sign-out by emitting an expiring cookie even with codec', async () => {
    const sessions = buildManager<UserData>({
      store: createCookieStore<UserData>(),
      cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
    });
    const created = await sessions.create(new Request('https://example.com'), {});
    const out = await sessions.signOut(reqWithCookies(created.headers));
    expect(out.headers.getSetCookie()[0]).toContain('Max-Age=0');
  });

  it('should emit a one-shot dev warning when concurrency is wired against codec', async () => {
    const NODE_ENV = process.env['NODE_ENV'];
    delete process.env['NODE_ENV'];
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    try {
      buildManager<UserData>({
        store: createCookieStore<UserData>(),
        cookieCodec: createCookieCodec<UserData>({ secrets: SECRET }),
        concurrency: concurrency({ max: 5 }),
      });
      expect(warn).toHaveBeenCalled();
      expect(warn.mock.calls[0]?.[0]).toContain('concurrency feature');
    } finally {
      warn.mockRestore();
      if (NODE_ENV === undefined) delete process.env['NODE_ENV'];
      else process.env['NODE_ENV'] = NODE_ENV;
    }
  });
});

describe('defaultIpExtractor', () => {
  it('should pick the first hop in X-Forwarded-For', () => {
    const req = new Request('https://example.com', {
      headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2' },
    });
    expect(defaultIpExtractor(req)).toBe('1.1.1.1');
  });

  it('should fall back to CF-Connecting-IP when XFF is absent', () => {
    const req = new Request('https://example.com', {
      headers: { 'cf-connecting-ip': '203.0.113.5' },
    });
    expect(defaultIpExtractor(req)).toBe('203.0.113.5');
  });

  it('should fall back to True-Client-IP when XFF and CF are absent', () => {
    const req = new Request('https://example.com', {
      headers: { 'true-client-ip': '198.51.100.1' },
    });
    expect(defaultIpExtractor(req)).toBe('198.51.100.1');
  });

  it('should return undefined when no proxy header is present', () => {
    expect(defaultIpExtractor(new Request('https://example.com'))).toBeUndefined();
  });

  it('should ignore an empty X-Forwarded-For and fall through', () => {
    const req = new Request('https://example.com', {
      headers: { 'x-forwarded-for': '', 'cf-connecting-ip': 'cf-1' },
    });
    expect(defaultIpExtractor(req)).toBe('cf-1');
  });
});

describe('manager freeze', () => {
  it('should return a frozen manager', () => {
    const sessions = buildManager<UserData>();
    expect(Object.isFrozen(sessions)).toBe(true);
  });

  it('should expose __features as a Set', () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}), audit: audit(() => undefined) });
    expect(sessions.__features.has('csrf')).toBe(true);
    expect(sessions.__features.has('audit')).toBe(true);
  });

  it('should expose __csrfOptedOut=true when csrf is false', () => {
    const sessions = buildManager<UserData>({ csrf: false });
    expect(sessions.__csrfOptedOut).toBe(true);
  });

  it('should expose __csrfOptedOut=false when csrf is enabled', () => {
    const sessions = buildManager<UserData>({ csrf: csrf({}) });
    expect(sessions.__csrfOptedOut).toBe(false);
  });
});

describe('Secret rotation', () => {
  it('should accept cookies signed with a previously active secret', async () => {
    const store = createMemoryStore<UserData>();
    const oldMgr = buildManager<UserData>({ secrets: [ALT_SECRET], store });
    const created = await oldMgr.create(new Request('https://example.com'), {});
    // Construct a new manager with the new active secret first, old as fallback.
    const newMgr = buildManager<UserData>({ secrets: [SECRET, ALT_SECRET], store });
    const session = await newMgr.get(reqWithCookies(created.headers));
    expect(session?.meta.id).toBe(created.record.meta.id);
  });
});

describe('readCookie helper sanity', () => {
  it('should locate a session cookie by name in the Set-Cookie bag', () => {
    const headers = new Headers();
    headers.append('Set-Cookie', 'sid=abc; Path=/');
    expect(readCookie(headers, 'sid')).toBe('abc');
  });
});
