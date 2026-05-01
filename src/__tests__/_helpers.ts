import { createMemoryStore } from '../adapters/memory/index.js';
import { parseCookie } from '../core/cookie.js';
import { createSessionManager } from '../core/manager.js';
import { nowSeconds } from '../core/time.js';
import type { SessionConfig } from '../types/config.js';
import type { SessionData } from '../types/session.js';

/** A 32-byte secret used across tests. */
export const SECRET = 'a'.repeat(32);
export const ALT_SECRET = 'b'.repeat(32);

/** Build a controllable clock starting at the real current time; `advance` shifts forward. */
export function makeClock(start: number = nowSeconds()): {
  (): number;
  advance: (delta: number) => void;
  set: (value: number) => void;
} {
  let now = start;
  const fn = (() => now) as ((() => number) & {
    advance: (delta: number) => void;
    set: (value: number) => void;
  });
  fn.advance = (delta) => {
    now += delta;
  };
  fn.set = (value) => {
    now = value;
  };
  return fn;
}

/**
 * Build a manager with sensible test defaults. The `clock` (custom or real) is
 * threaded into the memory store too so manager + store agree on time —
 * otherwise records appear expired when the manager mints them with a fake
 * past clock.
 */
export function buildManager<T extends SessionData = SessionData>(
  overrides: Partial<SessionConfig<T>> = {},
): ReturnType<typeof createSessionManager<T>> {
  const clock = overrides.clock ?? nowSeconds;
  const store = overrides.store ?? createMemoryStore<T>({ clock });
  const config: SessionConfig<T> = {
    secrets: SECRET,
    ...overrides,
    store,
    clock,
  };
  return createSessionManager<T>(config);
}

/** Build a Request whose `cookie` header is the result of any prior Set-Cookies. */
export function reqWithCookies(
  headers: Headers,
  init: RequestInit & { url?: string } = {},
): Request {
  const all = headers.getSetCookie();
  // Use just the name=value portion, stripped of attributes.
  const cookieHeader = all
    .map((line) => {
      const eq = line.indexOf('=');
      if (eq === -1) return '';
      const name = line.slice(0, eq);
      const rest = line.slice(eq + 1);
      const semi = rest.indexOf(';');
      const value = semi === -1 ? rest : rest.slice(0, semi);
      return `${name}=${value}`;
    })
    .filter(Boolean)
    .join('; ');
  const { url = 'https://example.com/', ...rest } = init;
  return new Request(url, {
    ...rest,
    headers: {
      ...((init.headers as Record<string, string> | undefined) ?? {}),
      ...(cookieHeader ? { cookie: cookieHeader } : {}),
    },
  });
}

/** Read the session cookie value (post-prefix) from a Set-Cookie header bag. */
export function readCookie(headers: Headers, name: string): string | undefined {
  for (const line of headers.getSetCookie()) {
    const map = parseCookie(line.split(';')[0]);
    const v = map.get(name);
    if (v !== undefined) return v;
  }
  return undefined;
}
