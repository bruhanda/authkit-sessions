/**
 * with-express.ts — Express compatibility shim end-to-end.
 *
 * Same flow as `with-hono.ts`, but driven through a real `http` listener
 * because Express expects Node `req`/`res` objects rather than Web
 * `Request`/`Response`. The middleware bridges between the two so the
 * exact same `SessionManager` runs identically here and on the edge.
 *
 * Run:
 *   npx tsx examples/with-express.ts
 */
import express, { type Request as ExpressRequest } from 'express';
import { createSessionManager } from '@authkit/sessions';
import { createMemoryStore } from '@authkit/sessions/adapters/memory';
import { csrf } from '@authkit/sessions/csrf';
import { expressSessions, type ExpressSessionRequest } from '@authkit/sessions/frameworks/express';

type AppSession = { userId: string; role: 'user' | 'admin' };

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request extends ExpressSessionRequest<AppSession> {}
  }
}

const SECRET = 'e'.repeat(32);

const sessions = createSessionManager<AppSession>({
  secrets: [SECRET],
  store: createMemoryStore<AppSession>(),
  getUserId: (data) => data.userId,
  cookie: { secure: false },
  csrf: csrf({ enforceOrigin: true }),
});

/**
 * Drain the Set-Cookie produced by a session helper into an Express
 * response without clobbering anything else the handler may set.
 */
function emit(res: express.Response, headers: Headers): void {
  for (const [name, value] of headers.entries()) {
    if (name.toLowerCase() === 'set-cookie') res.append('Set-Cookie', value);
  }
}

/** Reconstruct a Web `Request` from an Express `req` for session helpers. */
function asWebRequest(req: ExpressRequest): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) for (const x of v) headers.append(k, x);
    else if (typeof v === 'string') headers.set(k, v);
  }
  const url = `${req.protocol}://${req.headers.host}${req.originalUrl}`;
  return new Request(url, { method: req.method, headers });
}

const app = express();
app.use(express.json());
app.use(expressSessions(sessions));

app.get('/me', (req, res) => {
  res.json(req.session?.data ?? null);
});

app.get('/csrf', (req, res) => {
  res.json({ csrf: req.session?.meta.csrf ?? null });
});

app.post('/sign-in', async (req, res) => {
  const { userId } = req.body as { userId: string };
  const att = await sessions.create(asWebRequest(req), { userId, role: 'user' });
  emit(res, att.headers);
  res.status(201).json(att.record.data);
});

app.post('/action', async (req, res) => {
  if (!req.session) {
    res.status(401).send('unauthorized');
    return;
  }
  const att = await sessions.update(asWebRequest(req), (d) => ({ ...d, role: 'admin' as const }));
  emit(res, att.headers);
  res.json(att.record.data);
});

app.post('/sign-out', async (req, res) => {
  const att = await sessions.signOut(asWebRequest(req));
  emit(res, att.headers);
  res.status(204).end();
});

/* ────────────────────────  driver ──────────────────────── */

function pickCookies(res: Response): string {
  return res.headers
    .getSetCookie()
    .map((line) => line.split(';', 1)[0])
    .filter((kv): kv is string => Boolean(kv && !kv.endsWith('=')))
    .join('; ');
}

async function main(): Promise<void> {
  const server = app.listen(0); // bind a random free port
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('bind failed');
  const base = `http://127.0.0.1:${addr.port}`;
  const origin = base; // CSRF Origin must match Host

  try {
    const anon = await fetch(`${base}/me`);
    console.log('GET /me (anon):       ', anon.status, await anon.json());

    const signedIn = await fetch(`${base}/sign-in`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin },
      body: JSON.stringify({ userId: 'u_42' }),
    });
    const cookies = pickCookies(signedIn);
    console.log('POST /sign-in:        ', signedIn.status, await signedIn.json());
    console.log('  carrying cookies:   ', cookies);

    const me = await fetch(`${base}/me`, { headers: { cookie: cookies, origin } });
    console.log('GET /me (signed-in):  ', me.status, await me.json());

    const csrfRes = await fetch(`${base}/csrf`, { headers: { cookie: cookies, origin } });
    const csrfBody = (await csrfRes.json()) as { csrf: string | null };
    console.log('GET /csrf:            ', csrfRes.status, csrfBody);

    const noToken = await fetch(`${base}/action`, {
      method: 'POST',
      headers: { cookie: cookies, origin },
    });
    console.log('POST /action no-csrf: ', noToken.status, (await noToken.text()) || '(empty)');

    const withToken = await fetch(`${base}/action`, {
      method: 'POST',
      headers: { cookie: cookies, origin, 'x-csrf-token': csrfBody.csrf ?? '' },
    });
    console.log('POST /action:         ', withToken.status, await withToken.json());

    const out = await fetch(`${base}/sign-out`, {
      method: 'POST',
      headers: { cookie: cookies, origin, 'x-csrf-token': csrfBody.csrf ?? '' },
    });
    console.log('POST /sign-out:       ', out.status);
  } finally {
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
