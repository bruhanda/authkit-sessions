# @authkit/sessions

[![npm version](https://img.shields.io/npm/v/@authkit/sessions.svg)](https://www.npmjs.com/package/@authkit/sessions)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@authkit/sessions?label=core%20gzip)](https://bundlephobia.com/package/@authkit/sessions)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)

Universal, TypeScript-first, edge-runtime-native session layer with pluggable storage adapters.

`express-session` is Node-only and ships a leaky `MemoryStore` by default. `iron-session` is cookie-only — you cannot revoke a session from another device. `Lucia` was deprecated in March 2025. `better-auth` is great if you want a full auth stack, but you can't take only the session slice.

`@authkit/sessions` is the slice: a typed `SessionManager<T>` with seven storage backends, eight framework adapters, instant server-side revoke, concurrent-session limits, device fingerprinting, and CSRF — all opt-in via separate entry points so a build that never imports a feature ships zero feature code.

---

## Features

- **Web Standards core.** Built on `Request` / `Response` / `Headers` — works in Node 20+, Bun, Deno, Cloudflare Workers, Vercel Edge, Netlify Edge.
- **Typed payload.** `SessionManager<T>` propagates your shape end-to-end; no `any` casts in handlers.
- **Pluggable storage.** Memory (dev), encrypted cookie (stateless), Redis, Upstash, Cloudflare KV, Cloudflare D1, Postgres, Durable Objects.
- **Framework adapters.** Hono, Elysia, Next.js, Remix, SvelteKit, Express, Fastify, h3.
- **Instant server-side revoke** by session id, by user, or by device — works across edge regions when paired with a stateful store.
- **Concurrent session limits** with `lru` / `fifo` / `deny-new` eviction (Netflix-style).
- **CSRF** via OWASP double-submit cookie + optional `Origin` enforcement, on by default in framework adapters.
- **Device fingerprinting** with HMAC-hashed components — raw IP and UA never leave the request.
- **Audit hook** with a discriminated-union event stream — pipe to OTel, Sentry, or stdout.
- **Tree-shakable subpaths.** Each feature, adapter and framework lives at its own export; the core stays under 5 KB gzipped.
- **Zero `any`, no `unknown` leaks.** A single `SessionError` class with stable codes — branch on `error.code`, never parse messages.

---

## Quick Start

```ts
import { createSessionManager } from '@authkit/sessions';
import { createRedisStore } from '@authkit/sessions/adapters/redis';
import Redis from 'ioredis';

const sessions = createSessionManager<{ userId: string; role: 'user' | 'admin' }>({
  secrets: [process.env.SESSION_SECRET!], // >=256 bits of entropy
  store: createRedisStore(new Redis()),
  getUserId: (data) => data.userId,
});

// In a handler:
const { record, headers } = await sessions.create(req, { userId: '42', role: 'user' });
return new Response(null, { status: 204, headers });
```

That's the whole core API. Everything else — CSRF, fingerprinting, concurrency, audit, framework binding — is opt-in from a subpath.

---

## API Reference

The default export surface is intentionally tiny: one factory, one error class, the public type set.

### `createSessionManager<T>(config): SessionManager<T>`

Construct a session manager bound to a single config. The returned handle is frozen and safe to share across requests in the same runtime instance.

```ts
import { createSessionManager } from '@authkit/sessions';

const sessions = createSessionManager<{ userId: string }>({
  secrets: [process.env.SESSION_SECRET!],
  store: createRedisStore(redis),
  getUserId: (data) => data.userId,
});
```

Throws `SessionError('SECRET_TOO_SHORT')` when any secret carries less than 256 bits of entropy, or `SessionError('CONFIG_INVALID')` for any other validation failure.

### `SessionManager<T>`

Every method takes a standard `Request` (or a string id) and returns a `SessionAttachment<T>` carrying the new record plus a fresh `Set-Cookie`. Read paths never throw on user input; mutating paths throw `SessionError` for programmer / infrastructure failures only.

| Method | Returns | Description |
| --- | --- | --- |
| `get(req)` | `SessionRecord<T> \| null` | Read the active session. Never throws on missing/expired/tampered cookies. |
| `create(req, data, opts?)` | `SessionAttachment<T>` | Mint a new session. Captures device fingerprint when the feature is enabled. |
| `update(req, mutator)` | `SessionAttachment<T>` | Replace `data` via a pure mutator. Retries once on CAS conflict. |
| `rotate(req)` | `SessionAttachment<T>` | Mint a new id + CSRF token, keep the data. Call after privilege changes. |
| `signOut(req)` | `SessionAttachment<null>` | Drop the session and emit an expiring cookie. Idempotent. |
| `revokeBySessionId(id)` | `boolean` | Remove a single session — for background jobs and admin RPC. |
| `revokeByUser(userId)` | `number` | "Log out everywhere" for a user. |
| `listByUser(userId)` | `readonly SessionMetadata[]` | Active devices list. |
| `verifyCsrf(req, token)` | `boolean` | Constant-time compare token against `meta.csrf`. |
| `getCsrfToken(req)` | `string \| null` | Read the active token without mutating the session. |

```ts
// Read
const session = await sessions.get(req);
if (!session) return new Response('unauthorized', { status: 401 });

// Create
const { headers } = await sessions.create(req, { userId, role: 'user' });

// Update
await sessions.update(req, (data) => ({ ...data, lastAction: 'view' }));

// Rotate after privilege change
const { headers } = await sessions.rotate(req);

// Server-side revoke from anywhere
await sessions.revokeByUser(userId);
```

### `SessionAttachment<T>`

Returned by every mutating call. Two ways to consume it — both idiomatic for the Web Standards ecosystem:

```ts
const att = await sessions.create(req, data);

// 1. The pre-filled Headers — drop into a Response.
return new Response(body, { headers: att.headers });

// 2. The raw Set-Cookie line — for frameworks that own header composition.
return new Response(body, { headers: { 'set-cookie': att.cookie } });

// 3. Append into a caller-owned Headers without clobbering existing entries.
att.attachTo(response.headers);
```

The CSRF mirror cookie (when the feature is enabled) is appended to the same `Headers` object — one attachment carries everything.

### `SessionError`

Single error class for every public surface. Branch on `error.code`, never parse messages.

```ts
import { SessionError } from '@authkit/sessions';

try {
  await sessions.update(req, fn);
} catch (err) {
  if (SessionError.is(err) && err.code === 'NOT_FOUND') {
    return new Response('no session', { status: 401 });
  }
  throw err;
}
```

Stable codes: `INVALID_COOKIE`, `INVALID_SIGNATURE`, `EXPIRED`, `NOT_FOUND`, `CONFLICT`, `CONCURRENCY_DENIED`, `CSRF_INVALID`, `CSRF_MISSING`, `STORE_UNAVAILABLE`, `SECRET_TOO_SHORT`, `CONFIG_INVALID`, `PAYLOAD_TOO_LARGE`, `FINGERPRINT_MISMATCH`. `SessionError.is(value)` works across realm boundaries (Workers <-> Durable Objects) where `instanceof` cannot be relied on.

---

## Features (opt-in subpaths)

Each feature is a separate import. A build that never references a subpath ships zero code from it.

### CSRF — `@authkit/sessions/csrf`

OWASP-recommended double-submit cookie pattern with optional `Origin` enforcement.

```ts
import { csrf, isOriginAllowed } from '@authkit/sessions/csrf';

const sessions = createSessionManager({
  secrets: [SECRET],
  store,
  csrf: csrf({
    cookieName: 'csrf',
    headerName: 'x-csrf-token',
    protectedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
    enforceOrigin: true,
  }),
});

// Verify on protected routes
const ok = await sessions.verifyCsrf(req, req.headers.get('x-csrf-token') ?? '');
if (!ok) return new Response('csrf', { status: 403 });
```

Framework adapters enable CSRF by default. Pure JSON APIs that don't ride a browser cookie pass `csrf: false` to opt out explicitly — the manager records the opt-out so adapters can distinguish "forgot to wire it" from "intentionally off".

### Device fingerprinting — `@authkit/sessions/fingerprint`

```ts
import { fingerprint } from '@authkit/sessions/fingerprint';

const sessions = createSessionManager({
  secrets: [SECRET],
  store,
  fingerprint: fingerprint({
    include: ['user-agent', 'accept-language', 'sec-ch-ua', 'ip'],
    onMismatch: 'rotate', // 'rotate' | 'destroy' | 'ignore'
  }),
});
```

Components are HMAC-hashed before storage — raw IP / UA never leave the request. `meta.device.hash` is what `listByUser` returns, never the inputs.

### Concurrency — `@authkit/sessions/concurrency`

```ts
import { concurrency } from '@authkit/sessions/concurrency';

const sessions = createSessionManager({
  secrets: [SECRET],
  store,
  getUserId: (data) => data.userId,
  concurrency: concurrency({ max: 5, strategy: 'lru' }), // 'lru' | 'fifo' | 'deny-new'
});
```

`deny-new` throws `SessionError('CONCURRENCY_DENIED')`; `lru` / `fifo` evict the loser and emit a `session.evicted` audit event. Works against any store that indexes by user; against the cookie codec it's a no-op (a one-shot dev warning fires).

### Audit — `@authkit/sessions/audit`

```ts
import { audit, composeAuditHook, formatAuditEventJson } from '@authkit/sessions/audit';

const sessions = createSessionManager({
  secrets: [SECRET],
  store,
  audit: audit(composeAuditHook(
    (e) => process.stdout.write(formatAuditEventJson(e)),
    (e) => sentry.addBreadcrumb({ category: 'session', message: e.type, data: e }),
  )),
});
```

Discriminated-union events: `session.created`, `session.read`, `session.read.failed`, `session.updated`, `session.rotated`, `session.destroyed`, `session.evicted`, `csrf.failed`. Hook errors are caught and swallowed — audit never breaks request flow.

---

## Storage Adapters

Pick one for `config.store`. Adapters are entry points, not options — your bundle only includes the one you import.

| Adapter | Subpath | Backend | Notes |
| --- | --- | --- | --- |
| Memory | `/adapters/memory` | in-process `Map` | Test/dev only. LRU eviction past `maxRecords` (default 10 000). |
| Cookie | `/adapters/cookie` | none (stateless) | AES-256-GCM-sealed envelope inside the cookie itself. ~3 KB payload cap. |
| Redis | `/adapters/redis` | Redis | Native `EX` TTL, optional Lua for atomic user-index ops. ioredis / node-redis 4+ / Bun. |
| Upstash | `/adapters/upstash` | Upstash Redis (HTTP) | Peer dep `@upstash/redis`. No Lua dependency. |
| Cloudflare KV | `/adapters/cloudflare-kv` | KV | Eventually consistent (~60 s global). Optional companion namespace for the user index. |
| Cloudflare D1 | `/adapters/cloudflare-d1` | D1 (SQLite) | Strong per-request consistency. Ship `schema.sql` via wrangler. |
| Postgres | `/adapters/postgres` | Postgres | Strong consistency. Pass any `(sql, params) => Promise<Row[]>` (pg, postgres.js, slonik). |
| Durable Object | `/adapters/durable-object` | Cloudflare DO | Strong consistency. JSON-over-`fetch` against a DO stub you own. |

```ts
// Redis
import { createRedisStore } from '@authkit/sessions/adapters/redis';
import Redis from 'ioredis';
const store = createRedisStore(new Redis());

// Cloudflare KV (Workers)
import { createKVStore } from '@authkit/sessions/adapters/cloudflare-kv';
const store = createKVStore(env.SESSION_KV, { userIndex: env.SESSION_USER_INDEX });

// Postgres
import { createPostgresStore } from '@authkit/sessions/adapters/postgres';
const store = createPostgresStore((sql, params) => pool.query(sql, params).then((r) => r.rows));

// Stateless cookie (no server state at all)
import { createCookieCodec, createCookieStore } from '@authkit/sessions/adapters/cookie';
const sessions = createSessionManager({
  secrets: [SECRET],
  store: createCookieStore(),
  cookieCodec: createCookieCodec({ secrets: [SECRET] }),
});
```

---

## Framework Adapters

### Next.js — `@authkit/sessions/frameworks/next`

App Router + middleware support. Three entry points: a Server Component / Action helper, a `NextRequest` middleware that auto-enforces CSRF, and a Route Handler wrapper that injects the session and collects `Set-Cookie` headers.

```ts
// app/lib/sessions.ts
import { createSessionManager } from '@authkit/sessions';
import { createRedisStore } from '@authkit/sessions/adapters/redis';
import { csrf } from '@authkit/sessions/csrf';

export const sessions = createSessionManager<{ userId: string }>({
  secrets: [process.env.SESSION_SECRET!],
  store: createRedisStore(redis),
  getUserId: (d) => d.userId,
  csrf: csrf(),
});

// middleware.ts — CSRF enforcement on protected methods
import { createSessionMiddleware } from '@authkit/sessions/frameworks/next';
export default createSessionMiddleware(sessions);

// app/page.tsx — Server Component
import { getServerSession } from '@authkit/sessions/frameworks/next';
export default async function Page() {
  const session = await getServerSession(sessions);
  return <p>{session?.data.userId ?? 'anon'}</p>;
}

// app/api/me/route.ts — Route Handler
import { withSession } from '@authkit/sessions/frameworks/next';
export const POST = withSession(sessions, async (req, { session, attach }) => {
  const att = await sessions.update(req, (d) => ({ ...d, count: 1 }));
  attach(att);
  return new Response(JSON.stringify(att.record.data));
});
```

### Hono — `@authkit/sessions/frameworks/hono`

```ts
import { Hono } from 'hono';
import { honoSessions } from '@authkit/sessions/frameworks/hono';

const app = new Hono();
app.use('*', honoSessions(sessions));
app.get('/me', (c) => c.json(c.var.session?.data ?? { anon: true }));
app.post('/sign-in', async (c) => {
  const att = await c.var.sessions.create(c.req.raw, { userId: '42' });
  return new Response(JSON.stringify(att.record.data), { status: 201, headers: att.headers });
});
```

`c.var.sessions` is the manager, `c.var.session` is the active record (or `null`). CSRF runs automatically on `POST` / `PUT` / `PATCH` / `DELETE`.

### Express — `@authkit/sessions/frameworks/express`

```ts
import express from 'express';
import { expressSessions } from '@authkit/sessions/frameworks/express';

const app = express();
app.use(express.json());
app.use(expressSessions(sessions));

app.post('/api/action', (req, res) => {
  if (!req.session) return res.status(401).send('unauthorized');
  res.json(req.session.data);
});
```

The middleware bridges Node's `IncomingMessage` to a Web `Request`, so the same manager object that runs on Workers also runs on Express.

### Other frameworks

```ts
// Elysia
import { elysiaSessions } from '@authkit/sessions/frameworks/elysia';
new Elysia().use(elysiaSessions(sessions)).get('/me', ({ session }) => session?.data ?? null);

// Remix / React Router 7
import { createRemixSession } from '@authkit/sessions/frameworks/remix';
const { getSession, commitSession, destroySession } = createRemixSession(sessions);

// SvelteKit
import { createSessionHandle } from '@authkit/sessions/frameworks/sveltekit';
export const handle = createSessionHandle(sessions);

// Fastify
import { fastifySessions } from '@authkit/sessions/frameworks/fastify';
await app.register(fastifySessions(sessions));

// h3 / Nitro / Nuxt
import { h3Sessions } from '@authkit/sessions/frameworks/h3';
app.use(h3Sessions(sessions));
```

---

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| `secrets` | **required** | Single secret or rotation array. >=256 bits each (32 random bytes). First entry is active; the rest verify legacy cookies. |
| `store` | **required** | Backing `SessionStore<T>`. No default — choose explicitly to avoid `express-session`'s leaky `MemoryStore` footgun. |
| `cookieCodec` | `undefined` | Optional `StatelessCookieCodec<T>` from `/adapters/cookie`. When provided, the entire record is sealed into the cookie. |
| `getUserId` | `undefined` | `(data: T) => string \| undefined`. Required for `revokeByUser`, `listByUser`, `concurrency`. |
| `cookieName` | `'sid'` | Cookie name for the session id. |
| `cookie.secure` | `true` | `Secure` attribute. |
| `cookie.httpOnly` | `true` | `HttpOnly` attribute. |
| `cookie.sameSite` | `'Lax'` | Compatible with top-level OAuth redirects. |
| `cookie.path` | `'/'` | Cookie scope. |
| `cookie.prefix` | `false` | `'__Host-'` recommended for SPAs. `'__Secure-'` is the weaker variant. |
| `cookie.partitioned` | `undefined` | CHIPS — for embeds in third-party iframes. |
| `expiration.absoluteSeconds` | `2 592 000` (30 d) | Absolute lifetime cap from creation. |
| `expiration.slidingSeconds` | `604 800` (7 d) | Sliding window — extended on read up to the absolute cap. `0` disables. |
| `expiration.rotateAfterSeconds` | `86 400` (24 h) | Force id rotation past this age. Defence-in-depth against fixation. `0` disables. |
| `expiration.touchThrottleSeconds` | `60` | Suppress sliding-expiration writes inside this window. |
| `csrf` | `undefined` (raw core), `csrf()` (frameworks) | A `csrf()` feature handle, or `false` to opt out. |
| `concurrency` | `undefined` | A `concurrency({ max, strategy })` feature handle. |
| `fingerprint` | `undefined` | A `fingerprint({ include, ip, onMismatch })` feature handle. |
| `audit` | `undefined` | An `audit(hook)` feature handle. |
| `clock` | `() => Math.floor(Date.now() / 1000)` | Test injection for fast-forwarding without fake timers. |

---

## TypeScript

The library is TypeScript-first; types are not an afterthought.

### Typed payload through every surface

```ts
type AppSession = {
  userId: string;
  role: 'user' | 'admin';
  preferences: { theme: 'light' | 'dark' };
};

const sessions = createSessionManager<AppSession>({ /* ... */ });

const session = await sessions.get(req);
//    ^? SessionRecord<AppSession> | null

session?.data.role; // 'user' | 'admin' — no cast
session?.data.preferences.theme; // 'light' | 'dark' — no cast

await sessions.update(req, (data) => ({
  ...data,
  preferences: { theme: 'dark' as const },
}));
```

### Discriminated `AuditEvent`

Per-event fields are inferred without manual casts:

```ts
import { audit, type AuditEvent } from '@authkit/sessions/audit';

audit((event) => {
  switch (event.type) {
    case 'session.evicted':
      log.warn({ userId: event.userId, strategy: event.strategy });
      break;
    case 'csrf.failed':
      log.error({ reason: event.reason }); // 'missing' | 'mismatch' | 'origin' | 'no-session'
      break;
  }
});
```

### Result-style sum type

For non-throwing operations that need to distinguish "missing" from "store unavailable":

```ts
import type { Result } from '@authkit/sessions';
const r: Result<number> = { ok: true, value: 42 };
if (r.ok) console.log(r.value); else console.error(r.error.code);
```

### Strict module resolution

All package exports declare both `types` and `import` conditions. The package is ESM-only and ships `sideEffects: false` for full tree-shaking under bundlers that respect it (Vite, esbuild, webpack 5+, Rollup, Bun, Deno, Workers).

---

## How `@authkit/sessions` compares

| | `@authkit/sessions` | `iron-session` | `express-session` | `better-auth` | `cookie-session` | Lucia (deprecated) |
| --- | --- | --- | --- | --- | --- | --- |
| Edge-runtime | yes (Web Standards core) | yes (cookie only) | no (Node-only) | yes | no (Express-only) | yes |
| Server-side revoke | yes — instant, by id / user / device | no (stateless) | yes | yes | no (stateless) | yes |
| Pluggable storage | yes — 8 adapters | no (cookie only) | partial — separate `connect-*` packages | partial — tied to ORM | no (cookie only) | yes |
| Typed payload `<T>` | yes — end-to-end | partial | no — `any` by default | yes | no | yes |
| Concurrent session limits | yes — `lru` / `fifo` / `deny-new` | no | no | partial | no | no |
| Device tracking + listByUser | yes — HMAC-hashed components | no | no | partial | no | no |
| CSRF built-in | yes — on by default in adapters | no | no — external | yes | no | no — external |
| Bundle (core, gzipped) | ~5 KB | ~3 KB | ~30 KB (+stores) | ~55 KB | ~2 KB | retired |
| Auth-stack scope | sessions only | sessions only | sessions only | full auth + OAuth + MFA | sessions only | full auth |
| Maintenance status (May 2026) | active | active | active | active | declining | deprecated |

The slot we fill is the one Lucia left empty: **standalone, framework-neutral, edge-first, with stateful adapters and security primitives turned on by default**. If you want a full auth stack, take `better-auth`. If you only need cookie-stateless and ship Next.js, take `iron-session`. For everything in between, this is for you.

---

## Examples

Four runnable examples live in [`examples/`](./examples), each mirrored
by a StackBlitz-ready sandbox in [`examples/sandbox/`](./examples/sandbox).
Run any of them locally with `npx tsx examples/<name>.ts`, or click the
button to launch the same code in the browser.

| Example | What it covers | Sandbox |
| --- | --- | --- |
| [`basic-usage.ts`](./examples/basic-usage.ts) | `create` / `get` / `update` / `signOut` against the in-memory store. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/basic-usage) |
| [`advanced-usage.ts`](./examples/advanced-usage.ts) | Every feature on at once: typed payload, fingerprint, concurrency (lru + deny-new), CSRF, audit, rotate, listByUser, revokeByUser. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/advanced-usage) |
| [`with-hono.ts`](./examples/with-hono.ts) | `honoSessions(manager)` — CSRF-protected sign-in / me / action / sign-out, driven through `app.fetch(req)`. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/with-hono) |
| [`with-express.ts`](./examples/with-express.ts) | `expressSessions(manager)` — same flow against a real `http.Server`, showing the Node ↔ Web Standards bridge. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-sessions/tree/main/examples/sandbox/with-express) |

```bash
npm install
npx tsx examples/basic-usage.ts
npx tsx examples/advanced-usage.ts
npx tsx examples/with-hono.ts
npx tsx examples/with-express.ts
```

Each example is self-contained — no Redis, no Postgres, no Cloudflare
account required. Swap `createMemoryStore()` for any other adapter from
the table above when you wire it into a real deployment.

---

## Out of Scope

This library is sessions, full stop. The login flow itself, OAuth providers, MFA / TOTP, passkeys / WebAuthn, RBAC, rate limiting, JWT issuance, "active devices" UI components — all explicitly out of scope. Sessions consume a `userId` you produce; everything above sessions belongs in a sibling library. The audit hook is the integration point for anything you want to plug in (Sentry, OTel, your own auth metrics).

---

## Contributing

Contributions are welcome. Run the test suite before opening a PR:

```bash
npm install
npm run test
npm run test:types
npm run lint
npm run size
```

The package uses [tsup](https://tsup.egoist.dev/) for builds, [Vitest](https://vitest.dev/) for tests, [Biome](https://biomejs.dev/) for lint + format, and [size-limit](https://github.com/ai/size-limit) to enforce per-subpath bundle budgets in CI.

Open a discussion before sending non-trivial work — the surface is intentionally small, and the bar for adding to the public API is high.

---

## License

[MIT](./LICENSE) &copy; Vasyl Bruhanda
