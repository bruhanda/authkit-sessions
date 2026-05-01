import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { csrf } from '../features/csrf/index.js';
import { getServerSession, setServerSession } from '../frameworks/next/index.js';
import { SessionError } from '../errors/base.js';
import { buildManager, reqWithCookies } from './_helpers.js';

interface Data extends Record<string, unknown> {
  userId?: string;
}

interface FakeCookieJar {
  getAll: () => readonly { name: string; value: string }[];
  set: (name: string, value: string) => void;
}

const cookieJar: { current: FakeCookieJar | null } = { current: null };

vi.mock('next/headers', () => ({
  cookies: async () => {
    if (!cookieJar.current) throw new Error('outside next ctx');
    return cookieJar.current;
  },
}));

const buildJar = (initial: { name: string; value: string }[] = []): FakeCookieJar => {
  const list = [...initial];
  return {
    getAll: () => list,
    set: (name, value) => {
      const existing = list.findIndex((c) => c.name === name);
      if (existing >= 0) list.splice(existing, 1);
      list.push({ name, value });
    },
  };
};

describe('getServerSession / setServerSession', () => {
  beforeEach(() => {
    cookieJar.current = null;
  });

  afterEach(() => {
    cookieJar.current = null;
  });

  it('should return null when no cookies are present', async () => {
    cookieJar.current = buildJar();
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    expect(await getServerSession(mgr)).toBeNull();
  });

  it('should throw CONFIG_INVALID when called outside a Next server context', async () => {
    cookieJar.current = null;
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    await expect(getServerSession(mgr)).rejects.toThrowError(SessionError);
  });

  it('should round-trip a session through setServerSession + getServerSession', async () => {
    cookieJar.current = buildJar();
    const mgr = buildManager<Data>({ csrf: csrf({}), getUserId: (d) => d.userId });
    const record = await setServerSession(mgr, { userId: 'u' });
    expect(record.meta.userId).toBe('u');
    const session = await getServerSession(mgr);
    expect(session?.meta.id).toBe(record.meta.id);
  });

  it('should throw CONFIG_INVALID from setServerSession when outside next ctx', async () => {
    cookieJar.current = null;
    const mgr = buildManager<Data>({ csrf: csrf({}) });
    await expect(setServerSession(mgr, {})).rejects.toThrowError(SessionError);
  });
});

// The reqWithCookies import is intentional but unused here.
void reqWithCookies;
