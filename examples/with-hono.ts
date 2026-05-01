/**
 * with-hono.ts — Hono adapter end-to-end.
 *
 * Spins up a four-route Hono app (sign-in, me, action, sign-out) and
 * drives it with `app.fetch(req)` — no HTTP listener needed because Hono
 * speaks Web Standards natively. Every assertion is the same flow a
 * browser would walk:
 *
 *   POST /sign-in        ->  Set-Cookie: sid=…; csrf=…
 *   GET  /me             ->  authenticated read with the cookies
 *   POST /action         ->  protected by CSRF — needs x-csrf-token
 *   POST /sign-out       ->  expiring Set-Cookie
 *
 * Run:
 *   npx tsx examples/with-hono.ts
 */
import { Hono } from 'hono';
import { createSessionManager } from '@authkit/sessions';
import { createMemoryStore } from '@authkit/sessions/adapters/memory';
import { csrf } from '@authkit/sessions/csrf';
import { honoSessions } from '@authkit/sessions/frameworks/hono';

type AppSession = { userId: string; role: 'user' | 'admin' };

const SECRET = 'h'.repeat(32);

const sessions = createSessionManager<AppSession>({
  secrets: [SECRET],
  store: createMemoryStore<AppSession>(),
  getUserId: (data) => data.userId,
  cookie: { secure: false }, // demo runs over plain http
  csrf: csrf({ enforceOrigin: true }),
});

const app = new Hono();
app.use('*', honoSessions(sessions));

app.get('/me', (c) => c.json(c.var.session?.data ?? null));

app.get('/csrf', (c) => c.json({ csrf: c.var.session?.meta.csrf ?? null }));

app.post('/sign-in', async (c) => {
  // In a real app: verify credentials first, THEN call create().
  const { userId } = (await c.req.json()) as { userId: string };
  const att = await c.var.sessions.create(c.req.raw, { userId, role: 'user' });
  return new Response(JSON.stringify(att.record.data), {
    status: 201,
    headers: att.headers,
  });
});

app.post('/action', async (c) => {
  if (!c.var.session) return c.text('unauthorized', 401);
  const att = await c.var.sessions.update(c.req.raw, (d) => ({ ...d, role: 'admin' as const }));
  return new Response(JSON.stringify(att.record.data), { headers: att.headers });
});

app.post('/sign-out', async (c) => {
  const att = await c.var.sessions.signOut(c.req.raw);
  return new Response(null, { status: 204, headers: att.headers });
});

/* ────────────────────────  driver ──────────────────────── */

function pickCookies(res: Response): string {
  // Web Headers exposes a `getSetCookie` method on Node 20+ that returns
  // every Set-Cookie line as a separate string — what we want for a
  // multi-cookie response (sid + csrf).
  const lines = res.headers.getSetCookie();
  return lines
    .map((line) => line.split(';', 1)[0]) // strip attributes
    .filter((kv): kv is string => Boolean(kv && !kv.endsWith('=')))
    .join('; ');
}

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  return app.fetch(
    new Request(`https://app.example.com${path}`, {
      ...init,
      headers: {
        origin: 'https://app.example.com',
        host: 'app.example.com',
        ...(init.headers as Record<string, string> | undefined),
      },
    }),
  );
}

async function main() {
  // Anonymous read.
  const anonRes = await call('/me');
  console.log('GET /me (anon):       ', anonRes.status, await anonRes.json());

  // Sign in.
  const signedIn = await call('/sign-in', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userId: 'u_77' }),
  });
  const cookies = pickCookies(signedIn);
  console.log('POST /sign-in:        ', signedIn.status, await signedIn.json());
  console.log('  carrying cookies:   ', cookies);

  // Authenticated read.
  const me = await call('/me', { headers: { cookie: cookies } });
  console.log('GET /me (signed-in):  ', me.status, await me.json());

  // Read the CSRF token (would come from a meta tag in the rendered HTML).
  const csrfRes = await call('/csrf', { headers: { cookie: cookies } });
  const csrfBody = (await csrfRes.json()) as { csrf: string | null };
  console.log('GET /csrf:            ', csrfRes.status, csrfBody);

  // POST /action without the CSRF header → 403.
  const noToken = await call('/action', { method: 'POST', headers: { cookie: cookies } });
  console.log('POST /action no-csrf: ', noToken.status, (await noToken.text()) || '(empty)');

  // POST /action with the CSRF header → 200.
  const withToken = await call('/action', {
    method: 'POST',
    headers: { cookie: cookies, 'x-csrf-token': csrfBody.csrf ?? '' },
  });
  console.log('POST /action:         ', withToken.status, await withToken.json());

  // Sign out — the middleware enforces CSRF on every protected method
  // when a session is active, including the logout itself, so the client
  // submits the token here too.
  const out = await call('/sign-out', {
    method: 'POST',
    headers: { cookie: cookies, 'x-csrf-token': csrfBody.csrf ?? '' },
  });
  console.log('POST /sign-out:       ', out.status);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
