# `@authkit/sessions` — Architecture Plan

> Universal, **TypeScript-first**, **edge-runtime-native** session layer with
> pluggable storage adapters. Targets **<6 KB gzipped** for the core engine
> (the cookie-only, zero-store path is **<4.5 KB**) and runs unmodified in
> **Node 20+, Bun 1.0+, Deno 1.40+, Cloudflare Workers, Vercel Edge, Netlify
> Edge** through Web Standards (`Request`, `Response`, `Headers`, `crypto`).
> Optional, tree-shakeable adapters for **8 stores** (cookie, memory, Redis,
> Upstash, Cloudflare KV, Cloudflare D1, Postgres, Durable Objects) and **9
> frameworks** (Hono, Elysia, Next.js App Router + middleware, Remix / React
> Router 7, SvelteKit, Express, Fastify, h3 / Nitro, raw Web Standards).
>
> Positioned to **fill the vacuum left by Lucia's deprecation (March 2025)**
> and to compete on **DX + bundle size + framework neutrality** against
> `iron-session` (cookie-only, no instant revoke), `express-session` (Node-only,
> leaky default store, weak typing) and `better-auth` (full auth stack,
> overkill when only sessions are needed). Source of truth for the market
> problem statement is `reports/05-session-vault.json` (id `05`, dated
> 2026-04-27).

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Public API Design](#2-public-api-design)
3. [Internal Architecture](#3-internal-architecture)
4. [Type System](#4-type-system)
5. [Error Handling Strategy](#5-error-handling-strategy)
6. [Bundle & Tree-shaking Plan](#6-bundle--tree-shaking-plan)
7. [Dependencies](#7-dependencies)
8. [Configuration](#8-configuration)
9. [Edge Cases](#9-edge-cases)
10. [Out of Scope (1.0)](#10-out-of-scope-10)

---

## 1. Project Structure

Every file in `src/` is single-purpose; no file imports from `dist/`, no file
imports through a sibling `index.ts` re-export (re-exports happen only at
**package boundaries** — i.e. files referenced from `package.json#exports`).
This keeps the dependency graph **acyclic**, side-effect-free and aggressively
tree-shakeable, so a consumer who imports only `@authkit/sessions/adapters/cookie`
does not pull in any framework adapter, any other store, or any
`fingerprint` / `concurrency` module that is otherwise dead code.

```
authkit-sessions/
├── PLAN.md                          # this document
├── README.md                        # 5-min getting started + API reference
├── LICENSE                          # MIT
├── CHANGELOG.md                     # changesets-managed
├── package.json                     # see §8
├── tsconfig.json                    # strict, ES2024, NodeNext, declaration
├── tsconfig.build.json              # build-only overrides (excludes test/)
├── tsup.config.ts                   # multi-entry esm+dts bundler
├── vitest.config.ts                 # workspaces incl. workers / browser pools
├── biome.json                       # lint + format (replaces eslint+prettier)
├── .size-limit.json                 # per-entry budget (CI gate)
├── .gitignore                       # see §8
├── .npmignore                       # narrows publish to dist/ + LICENSE/README
├── .changeset/
│   └── config.json
├── .github/
│   └── workflows/
│       ├── ci.yml                   # test + typecheck + size-limit + attw + publint
│       └── release.yml              # changesets publish on main
│
├── src/
│   ├── index.ts                     # core public entrypoint
│   │                                # re-exports createSessionManager,
│   │                                # SessionError, type helpers — nothing else
│   │
│   ├── core/
│   │   ├── manager.ts               # createSessionManager() — central orchestrator
│   │   │                            # - composes lifecycle, store, cookie, audit
│   │   │                            # - returns frozen manager handle
│   │   ├── lifecycle.ts             # pure get/create/update/rotate/destroy steps
│   │   │                            # - decoupled from Request/Response shape so
│   │   │                            #   framework adapters can reuse them
│   │   ├── id.ts                    # generateSessionId() — 256-bit URL-safe random
│   │   │                            # uses globalThis.crypto.getRandomValues
│   │   ├── cookie.ts                # serializeCookie / parseCookie / flag defaults
│   │   │                            # - hand-rolled (no `cookie` dep) to keep
│   │   │                            #   ESM-only + edge-safe + ~150 LOC
│   │   ├── headers.ts               # extractCookie(req) / appendSetCookie(headers)
│   │   │                            # - the only file that touches Request/Headers
│   │   ├── expiration.ts            # sliding + absolute window arithmetic
│   │   │                            # - returns ExpirationOutcome union
│   │   ├── revoke.ts                # revokeBySessionId / byUser / byDevice helpers
│   │   ├── concurrency.ts           # enforceConcurrency() — LRU / FIFO / deny-new
│   │   │                            # - delegates atomicity to the store; this
│   │   │                            #   file only orchestrates the policy
│   │   ├── fingerprint.ts           # buildFingerprint(req, cfg) — UA+IP HMAC
│   │   │                            # - never stores raw IP; always hashed
│   │   ├── csrf.ts                  # double-submit token issue + verify
│   │   ├── audit.ts                 # composeAuditHook + default JSON formatter
│   │   ├── encoder.ts               # encodeRecord / decodeRecord — JSON+base64url
│   │   │                            # - SemVer-tagged envelope for forward compat
│   │   └── time.ts                  # nowSeconds() — single time source for tests
│   │
│   ├── crypto/
│   │   ├── index.ts                 # subpath barrel — exposed for advanced users
│   │   ├── aead.ts                  # AES-256-GCM seal/open via @noble/ciphers
│   │   ├── hmac.ts                  # HMAC-SHA256 sign/verify via @noble/hashes
│   │   ├── kdf.ts                   # HKDF-SHA256 — derive enc-key + sig-key from
│   │   │                            #   user secret so they are never reused
│   │   ├── timing.ts                # timingSafeEqual portable byte compare
│   │   └── random.ts                # randomBytes(len) wrapper
│   │
│   ├── types/
│   │   ├── index.ts                 # type-only public surface, no runtime
│   │   ├── session.ts               # SessionData, SessionMetadata, SessionRecord
│   │   ├── store.ts                 # SessionStore<T> interface
│   │   ├── manager.ts               # SessionManager<T>, SessionAttachment<T>
│   │   ├── config.ts                # SessionConfig<T> + nested option types
│   │   ├── cookie.ts                # CookieOptions
│   │   ├── policy.ts                # ExpirationPolicy, ConcurrencyPolicy,
│   │   │                            # EvictionStrategy
│   │   ├── device.ts                # Device, FingerprintConfig
│   │   ├── csrf.ts                  # CsrfConfig
│   │   ├── audit.ts                 # AuditEvent union, AuditHook, DestroyReason
│   │   ├── result.ts                # Result<T, E> for non-throwing reads
│   │   └── runtime.ts               # MinimalRequest, MinimalResponseInit shims
│   │
│   ├── errors/
│   │   ├── index.ts                 # errors subpath barrel
│   │   ├── base.ts                  # SessionError extends Error + .is() guard
│   │   └── codes.ts                 # SESSION_ERROR_CODES const + type
│   │
│   ├── adapters/
│   │   ├── memory/
│   │   │   └── index.ts             # MemoryStoreAdapter — Map<string, record>
│   │   │                            # - logs a one-time warning in non-test env;
│   │   │                            #   expressly NOT recommended for prod
│   │   ├── cookie/
│   │   │   ├── index.ts             # createCookieStore() — stateless adapter
│   │   │   ├── seal.ts              # encrypt + sign payload (AEAD over JSON)
│   │   │   └── compact.ts           # base64url envelope + size guard (4 KB)
│   │   ├── redis/
│   │   │   ├── index.ts             # createRedisStore(client)
│   │   │   ├── client.ts            # RedisLike narrow interface
│   │   │   │                        #   { get, set, del, expire, eval?, multi? }
│   │   │   └── lua.ts               # Lua scripts for atomic concurrency limit
│   │   │                            #   (single-RTT enforce-and-evict)
│   │   ├── upstash/
│   │   │   └── index.ts             # createUpstashStore(redis) — uses HTTP
│   │   │                            #   pipeline; no Lua, falls back to MULTI
│   │   ├── cloudflare-kv/
│   │   │   └── index.ts             # createKVStore(KVNamespace, opts)
│   │   ├── cloudflare-d1/
│   │   │   ├── index.ts             # createD1Store(D1Database)
│   │   │   └── schema.sql           # DDL for sessions + (user_id, last_seen_at) idx
│   │   ├── postgres/
│   │   │   ├── index.ts             # createPostgresStore(query)
│   │   │   │                        # - works with pg.Pool, postgres.js, or any
│   │   │   │                        #   `(sql, params) => Promise<row[]>` shape
│   │   │   └── schema.sql           # DDL with TTL index for sweep
│   │   └── durable-object/
│   │       └── index.ts             # createDurableObjectStore(stub) — strong
│   │                                #   consistency reference impl
│   │
│   ├── frameworks/
│   │   ├── hono/
│   │   │   └── index.ts             # honoSessions<Env, T>(config) middleware
│   │   ├── elysia/
│   │   │   └── index.ts             # elysiaSessions(config) plugin
│   │   ├── next/
│   │   │   ├── index.ts             # getServerSession / setServerSession
│   │   │   ├── middleware.ts        # Next middleware integration (matcher-based)
│   │   │   └── route-handler.ts     # withSession() wrapper for App Router
│   │   ├── remix/
│   │   │   └── index.ts             # createSessionStorage()-shaped facade
│   │   ├── sveltekit/
│   │   │   └── index.ts             # handle() helper + locals.session typing
│   │   ├── express/
│   │   │   └── index.ts             # express compat — adapts (req,res,next)
│   │   ├── fastify/
│   │   │   └── index.ts             # fastify-plugin wrapping the manager
│   │   └── h3/
│   │       └── index.ts             # h3 / Nitro event handler
│   │
│   └── utils/
│       ├── env.ts                   # isDev() — single portable runtime probe
│       │                            # `typeof process !== 'undefined' &&
│       │                            #  process.env?.NODE_ENV !== 'production'`
│       │                            # banned via Biome rule from being inlined
│       │                            # anywhere else (Workers/Deno safety)
│       ├── invariant.ts             # invariant(cond, code, msg) → throws SessionError
│       ├── base64url.ts             # base64url encode/decode (Uint8Array <-> string)
│       └── freeze.ts                # deepFreeze helper for defensive copies
│
├── test/
│   ├── core/
│   │   ├── manager.test.ts          # full lifecycle matrix
│   │   ├── lifecycle.test.ts        # create/read/update/rotate/destroy edges
│   │   ├── cookie.test.ts           # serialize/parse + flag matrix
│   │   ├── expiration.test.ts       # sliding + absolute + clock skew
│   │   ├── concurrency.test.ts      # LRU / FIFO / deny-new under contention
│   │   ├── csrf.test.ts             # double-submit issue/verify + miss cases
│   │   ├── fingerprint.test.ts      # mismatch policies + privacy assertions
│   │   ├── audit.test.ts            # event ordering + composeAuditHook
│   │   └── encoder.test.ts          # forward-compat envelope tag
│   ├── crypto/
│   │   ├── aead.test.ts             # AES-GCM round-trip + tampered ciphertext
│   │   ├── hmac.test.ts             # HMAC + timing-safe compare
│   │   └── kdf.test.ts              # HKDF deterministic vector
│   ├── adapters/
│   │   ├── memory.test.ts
│   │   ├── cookie.test.ts           # 4 KB hard fail + tamper detection
│   │   ├── redis.test.ts            # ioredis-mock (in-memory)
│   │   ├── upstash.test.ts          # MSW HTTP fixture
│   │   ├── kv.test.ts               # miniflare KVNamespace
│   │   ├── d1.test.ts               # miniflare D1
│   │   ├── postgres.test.ts         # pg-mem
│   │   └── durable-object.test.ts   # miniflare DO
│   ├── frameworks/
│   │   ├── hono.test.ts
│   │   ├── elysia.test.ts
│   │   ├── next.test.ts             # uses Next test helpers (Request mock)
│   │   ├── remix.test.ts
│   │   ├── sveltekit.test.ts
│   │   ├── express.test.ts          # supertest
│   │   ├── fastify.test.ts          # fastify.inject
│   │   └── h3.test.ts
│   ├── runtime/
│   │   ├── workers.test.ts          # @cloudflare/vitest-pool-workers
│   │   └── edge.test.ts             # globalThis.process undefined check
│   ├── types/
│   │   └── inference.test-d.ts      # vitest --typecheck (generic propagation)
│   ├── security/
│   │   ├── tampered-cookie.test.ts  # full tamper / replay matrix
│   │   ├── revoke-instantly.test.ts # cross-store revoke latency assertion
│   │   └── csrf-bypass.test.ts      # method matrix + Origin header parity
│   └── bench/
│       └── manager.bench.ts         # vitest bench — get/create per RPS
│
└── examples/                        # not published — referenced from README
    ├── hono-cloudflare-kv/
    ├── nextjs-redis/
    ├── sveltekit-postgres/
    └── elysia-bun/
```

---

## 2. Public API Design

This section is a complete TypeScript surface — everything the consumer can
import. Anything **not** listed here is **internal**, may break in a patch
release, and is tagged `@internal` in TSDoc so `api-extractor` strips it from
the published `.d.ts` rollup.

### 2.1 Root entrypoint — `@authkit/sessions`

```ts
/**
 * Create a session manager bound to a single config. The returned handle is
 * frozen and safe to share across requests in the same runtime instance.
 *
 * @typeParam T  Shape of the session payload. Defaults to `Record<string, unknown>`
 *               but is intended to be supplied by the caller so handlers receive
 *               a fully typed `record.data` (no manual casts).
 *
 * @example
 *   type Session = { userId: string; role: 'admin' | 'user' };
 *   const sessions = createSessionManager<Session>({
 *     secrets: [process.env.SESSION_SECRET!],
 *     store: createRedisStore(redis),
 *     expiration: { absoluteSeconds: 60 * 60 * 24 * 30, slidingSeconds: 60 * 60 * 24 * 7 },
 *     concurrency: { max: 5, strategy: 'lru' },
 *   });
 *
 *   // Inside a Web-standard handler:
 *   const session = await sessions.get(req);
 *   if (!session) return new Response('unauthorized', { status: 401 });
 *   //  ^? SessionRecord<Session> | null   — typed via the generic
 *
 *   const { setCookie } = await sessions.create(req, { userId, role: 'user' }, { userId });
 *   return new Response('ok', { headers: { 'set-cookie': setCookie } });
 */
export function createSessionManager<T extends SessionData = SessionData>(
  config: SessionConfig<T>,
): SessionManager<T>;

export { SessionError } from './errors/index.js';
export type {
  SessionData,
  SessionMetadata,
  SessionRecord,
  SessionStore,
  SessionManager,
  SessionAttachment,
  SessionConfig,
  CookieOptions,
  ExpirationPolicy,
  ConcurrencyPolicy,
  EvictionStrategy,
  CsrfConfig,
  FingerprintConfig,
  Device,
  AuditEvent,
  AuditHook,
  DestroyReason,
  Result,
} from './types/index.js';
```

### 2.2 Core types

```ts
/**
 * Marker base for the user-supplied payload. Library-internal metadata
 * (`id`, `createdAt`, `expiresAt`, `csrf`, …) lives on `SessionMetadata`,
 * never on `SessionData`, so user code cannot accidentally clobber it.
 */
export type SessionData = Record<string, unknown>;

export interface SessionMetadata {
  /** Opaque session identifier — 32 random bytes, base64url-encoded (43 chars). */
  readonly id: string;
  /** Optional user binding. Required for `revokeByUser` and `concurrency`. */
  readonly userId?: string;
  /** Unix seconds when the session was created. Never updated — see `lastSeenAt`. */
  readonly createdAt: number;
  /** Unix seconds of the most recent successful read; drives sliding expiration. */
  readonly lastSeenAt: number;
  /** Unix seconds when the session expires (absolute cap, never extended past it). */
  readonly expiresAt: number;
  /** Captured device — present iff `fingerprint` is enabled. */
  readonly device?: Device;
  /** Per-session CSRF token; rotated together with `id` on rotate(). */
  readonly csrf: string;
  /** Envelope schema version — read-only, used for forward compatibility. */
  readonly v: 1;
}

export interface SessionRecord<T extends SessionData> {
  readonly meta: SessionMetadata;
  readonly data: T;
}
```

### 2.3 Store contract (write your own adapter)

```ts
/**
 * Storage contract every adapter implements. The contract is intentionally
 * minimal — concurrency policy, expiration arithmetic and cookie handling
 * live in the manager, NOT the store. A store needs to do four things:
 *   1. Persist a record by its id.
 *   2. Read it back atomically.
 *   3. Drop one (or all of a user's) records.
 *   4. List a user's records cheaply enough for an "active devices" UI.
 *
 * Stores SHOULD honour native TTL where the backend exposes one (Redis EXPIRE,
 * KV expirationTtl, Postgres `delete where expires_at < now()` cron). Stores
 * MUST NOT extend TTL on read — the manager owns sliding expiration.
 *
 * All methods are async even when the implementation is synchronous so that
 * adapters can be swapped without changing call sites.
 */
export interface SessionStore<T extends SessionData = SessionData> {
  /**
   * Atomically write a new session. MUST throw `SessionError('CONFLICT')` if
   * `record.meta.id` already exists. The collision probability for a 256-bit
   * random id is negligible — the throw is for defensive programming, not a
   * retry loop.
   */
  create(record: SessionRecord<T>): Promise<void>;

  /**
   * Read by id. Returns `null` for missing or expired records. If the backend
   * has lazy expiry (KV between regions), the manager will re-validate
   * `meta.expiresAt` against the configured clock.
   */
  read(id: string): Promise<SessionRecord<T> | null>;

  /**
   * Replace data and metadata of an existing session. Returns `false` if the
   * id was not found. Implementations that support CAS (Postgres, D1) SHOULD
   * use it to detect lost-update races, but the manager doesn't require it.
   */
  update(record: SessionRecord<T>): Promise<boolean>;

  /** Drop a single session. Returns `true` iff something was removed. */
  destroy(id: string): Promise<boolean>;

  /** List active sessions for a user — used by the "active devices" UI and the
   *  concurrency enforcer. Implementations MAY return an empty array if they
   *  cannot index by user (cookie-only adapter); that disables concurrency. */
  listByUser(userId: string): Promise<readonly SessionMetadata[]>;

  /** Drop every session for a user. Used on password change / suspicious activity. */
  destroyByUser(userId: string): Promise<number>;

  /**
   * Optional bulk garbage collection of expired records. Stores with native
   * TTL (Redis, KV) typically implement this as a no-op. Stores without it
   * (Postgres, in-memory) implement a `WHERE expires_at < now()` delete.
   */
  sweep?(now?: number): Promise<number>;
}
```

### 2.4 Manager surface

```ts
export interface SessionManager<T extends SessionData = SessionData> {
  /**
   * Read the session bound to `req`. Never throws on missing/expired/tampered
   * cookies — returns `null` and emits a single `'session.read.failed'` audit
   * event. The only path that throws is a hard-fail config error
   * (e.g. `secrets` shorter than 32 bytes), and that throws on `createSessionManager`,
   * not here.
   */
  get(req: Request): Promise<SessionRecord<T> | null>;

  /**
   * Create a new session. Returns the record and the `Set-Cookie` header that
   * MUST be attached to the outgoing response. `applyTo()` is a convenience
   * for callers that already have a `ResponseInit`.
   *
   * @example
   *   const { record, applyTo } = await sessions.create(req, { userId }, { userId });
   *   return new Response(JSON.stringify(record.data), applyTo({ status: 201 }));
   */
  create(
    req: Request,
    data: T,
    opts?: { userId?: string; device?: Partial<Device> },
  ): Promise<SessionAttachment<T>>;

  /**
   * Mutate the active session. The `mutator` receives the current data and
   * returns the next; replacement is intentional — there is no `set(key,
   * value)` API because partial writes complicate type inference for `T`.
   *
   * If there is no active session, throws `SessionError('NOT_FOUND')`.
   */
  update(
    req: Request,
    mutator: (data: T) => T | Promise<T>,
  ): Promise<SessionAttachment<T>>;

  /**
   * Rotate the session id while keeping the data. Defence-in-depth against
   * fixation attacks — call after privilege changes (login, password change,
   * MFA upgrade). The CSRF token is rotated alongside the id.
   *
   * Returns the new `Set-Cookie` and a `record.meta.id` distinct from before.
   */
  rotate(req: Request): Promise<SessionAttachment<T>>;

  /**
   * Destroy the active session and return an expiring `Set-Cookie`. Idempotent
   * — destroying an already-gone session is a no-op and still returns the
   * expiring cookie so the browser drops its copy.
   */
  destroy(req: Request): Promise<SessionAttachment<null>>;

  /**
   * Operational APIs for admin tooling and "log out everywhere" buttons.
   * They DO NOT touch `req` because they are typically called from background
   * jobs / RPC handlers that don't have one.
   */
  revokeBySessionId(id: string): Promise<boolean>;
  revokeByUser(userId: string): Promise<number>;
  listByUser(userId: string): Promise<readonly SessionMetadata[]>;

  /**
   * Verify a CSRF token against the active session (double-submit pattern).
   * `token` is the value the client posted in the `X-CSRF-Token` header (or
   * a hidden form field). Returns `false` for any failure mode — missing
   * session, missing token, mismatch, expired session.
   */
  verifyCsrf(req: Request, token: string): Promise<boolean>;

  /**
   * Read the active CSRF token without mutating the session — used to render
   * it into a form / inject into a meta tag. Returns `null` if no session.
   */
  getCsrfToken(req: Request): Promise<string | null>;
}

/**
 * The result of any mutating operation. Includes the post-state record and a
 * fully-formed `Set-Cookie` string. `applyTo()` is the recommended API — it
 * appends to an existing `ResponseInit` without clobbering pre-set headers.
 */
export interface SessionAttachment<T extends SessionData | null> {
  readonly record: T extends null ? null : SessionRecord<NonNullable<T>>;
  readonly setCookie: string;
  /**
   * Merge the attachment into a `ResponseInit`. Existing `Set-Cookie` headers
   * are preserved (multiple cookies, e.g. session + CSRF mirror, are allowed).
   */
  readonly applyTo: (init?: ResponseInit) => ResponseInit;
}
```

### 2.5 Configuration

```ts
export interface SessionConfig<T extends SessionData = SessionData> {
  /**
   * One or more 32+ byte secrets. The first is the active key (used for new
   * cookies / signatures); the rest are accepted on read for zero-downtime
   * rotation. Strings are interpreted as UTF-8 and HKDF-stretched — no need
   * to base64-encode random material yourself.
   *
   * MUST be ≥32 bytes after decoding. Shorter secrets throw
   * `SessionError('SECRET_TOO_SHORT')` at manager construction time.
   */
  secrets: string | Uint8Array | readonly (string | Uint8Array)[];

  /** Storage adapter. Defaults to MemoryStore with a one-shot dev warning. */
  store?: SessionStore<T>;

  /** Cookie name for the session id. Default `'sid'`. */
  cookieName?: string;

  /** Cookie attributes applied to every Set-Cookie. */
  cookie?: Partial<CookieOptions>;

  /** Expiration policy — sliding + absolute. */
  expiration?: ExpirationPolicy;

  /** Concurrent session limits. Off by default. */
  concurrency?: ConcurrencyPolicy;

  /** Device fingerprinting. Off by default — opt-in for privacy. */
  fingerprint?: FingerprintConfig;

  /** CSRF protection. Off by default — opt-in per app. */
  csrf?: CsrfConfig;

  /** Audit hook fired on every lifecycle event. */
  audit?: AuditHook;

  /**
   * Clock injector for tests. Returns Unix seconds. Defaults to
   * `() => Math.floor(Date.now() / 1000)`. Replacing it lets the test suite
   * fast-forward through expiration without fake timers.
   */
  clock?: () => number;
}

export interface CookieOptions {
  /** `Path=` attribute. Default `'/'`. */
  path?: string;
  /** `Domain=` attribute. No default — leave undefined for host-only. */
  domain?: string;
  /** `Secure`. Default `true` (always — even in dev when `secure-prefix` cookies are set). */
  secure?: boolean;
  /** `HttpOnly`. Default `true`. Disable only if you genuinely need JS read access. */
  httpOnly?: boolean;
  /** `SameSite`. Default `'Lax'` (compatible with top-level OAuth redirects). */
  sameSite?: 'Strict' | 'Lax' | 'None';
  /**
   * Cookie name prefix.
   *  - `'__Host-'`: host-only, secure, path=/ — recommended for SPAs.
   *  - `'__Secure-'`: secure-only, weaker than `__Host-`.
   *  - `false` (default): no prefix.
   */
  prefix?: '__Host-' | '__Secure-' | false;
  /** Optional `Partitioned` attribute (CHIPS) — for embeds in third-party iframes. */
  partitioned?: boolean;
}

export interface ExpirationPolicy {
  /** Absolute lifetime cap from creation. Default 30 days. */
  absoluteSeconds?: number;
  /**
   * Sliding window — extend `expiresAt` by N seconds on every successful read,
   * up to `absoluteSeconds`. Set to `0` to disable sliding. Default 7 days.
   */
  slidingSeconds?: number;
  /**
   * Force id rotation when a session is older than this. Mitigates fixation.
   * Default `86_400` (24 h). Set to `0` to disable.
   */
  rotateAfterSeconds?: number;
  /**
   * Throttle for sliding-expiration writes — only persist a new `lastSeenAt`
   * when the delta exceeds this many seconds. Default `60`. Stops a noisy
   * write per request from saturating the store on hot endpoints.
   */
  touchThrottleSeconds?: number;
}

export interface ConcurrencyPolicy {
  /** Max concurrent active sessions per user. */
  max: number;
  /**
   * Eviction strategy when the limit is hit:
   *   - `'lru'`     — drop least-recently-used (default).
   *   - `'fifo'`    — drop the oldest by `createdAt`.
   *   - `'deny-new'`— refuse the new session, throw `CONCURRENCY_DENIED`.
   */
  strategy?: EvictionStrategy;
}

export type EvictionStrategy = 'lru' | 'fifo' | 'deny-new';

export interface FingerprintConfig {
  /** Components included in the fingerprint hash. */
  include?: readonly ('user-agent' | 'accept-language' | 'ip' | 'sec-ch-ua')[];
  /**
   * IP extractor — required if `'ip'` is in `include`. Defaults to the first
   * hop in `X-Forwarded-For`, falling back to `CF-Connecting-IP` (Cloudflare),
   * then `True-Client-IP` (Akamai). Return `undefined` to skip — never throws.
   */
  ip?: (req: Request) => string | undefined;
  /**
   * On mismatch:
   *   - `'rotate'` (default) — keep data, regenerate id + CSRF (defence-in-depth).
   *   - `'destroy'`           — wipe the session entirely (high-security).
   *   - `'ignore'`            — log + accept (use for warm-up / dev only).
   */
  onMismatch?: 'rotate' | 'destroy' | 'ignore';
}

export interface Device {
  /** HMAC of the included fingerprint components — never the raw values. */
  readonly hash: string;
  readonly userAgent?: string;
  readonly platform?: string;
  /** Hashed IP (HMAC of the raw bytes), never the raw value. */
  readonly ip?: string;
  readonly firstSeenAt: number;
  readonly lastSeenAt: number;
}

export interface CsrfConfig {
  /** Cookie name for the mirror token. Default `'csrf'`. */
  cookieName?: string;
  /** Header name expected to mirror the cookie value. Default `'x-csrf-token'`. */
  headerName?: string;
  /** Methods to enforce on. Default `['POST','PUT','PATCH','DELETE']`. */
  protectedMethods?: readonly string[];
  /**
   * Origin / Host check. When `true` (default), the manager additionally
   * verifies `Origin` (or `Referer`) matches the request `Host` for the same
   * methods. Provides a second layer for browsers that mishandle SameSite.
   */
  enforceOrigin?: boolean;
}
```

### 2.6 Audit hook

```ts
export type DestroyReason =
  | 'logout'
  | 'expired'
  | 'rotated'
  | 'evicted'
  | 'fingerprint-mismatch'
  | 'manual';

export type AuditEvent =
  | { type: 'session.created';   sessionId: string; userId?: string; device?: Device; at: number }
  | { type: 'session.read';      sessionId: string; at: number }
  | { type: 'session.read.failed'; reason: SessionErrorCode; at: number }
  | { type: 'session.updated';   sessionId: string; at: number }
  | { type: 'session.rotated';   oldId: string; newId: string; at: number }
  | { type: 'session.destroyed'; sessionId: string; reason: DestroyReason; at: number }
  | { type: 'session.evicted';   sessionId: string; userId: string; strategy: EvictionStrategy; at: number }
  | { type: 'csrf.failed';       reason: 'missing' | 'mismatch' | 'origin' | 'no-session'; at: number };

/**
 * Audit hook. Errors thrown inside the hook are caught and swallowed — audit
 * MUST NOT break request flow. Use `composeAuditHook(...hooks)` to fan out
 * to multiple destinations (console, OTel, Sentry).
 */
export type AuditHook = (event: AuditEvent) => void | Promise<void>;

export function composeAuditHook(...hooks: AuditHook[]): AuditHook;
```

### 2.7 Errors — `@authkit/sessions/errors`

```ts
export const SESSION_ERROR_CODES = [
  'INVALID_COOKIE',         // could not parse cookie envelope
  'INVALID_SIGNATURE',      // HMAC / AEAD verification failed
  'EXPIRED',                // record fetched but already expired
  'NOT_FOUND',              // operation requires an active session
  'CONFLICT',               // store rejected create() — id collision
  'CONCURRENCY_DENIED',     // limit hit + strategy === 'deny-new'
  'CSRF_INVALID',           // double-submit token mismatch
  'CSRF_MISSING',           // protected method without token
  'STORE_UNAVAILABLE',      // adapter raised — wraps original error
  'SECRET_TOO_SHORT',       // < 32 bytes after decoding
  'CONFIG_INVALID',         // any other config validation failure
  'PAYLOAD_TOO_LARGE',      // cookie store: > 4 KB after seal
  'FINGERPRINT_MISMATCH',   // device hash diverged + onMismatch === 'destroy'
] as const;

export type SessionErrorCode = (typeof SESSION_ERROR_CODES)[number];

export class SessionError extends Error {
  readonly code: SessionErrorCode;
  readonly cause?: unknown;
  /** Public, machine-readable; never contains user input. */
  readonly publicMessage: string;
  constructor(code: SessionErrorCode, message: string, cause?: unknown);
  /** Type-guard usable across realm boundaries (Workers ↔ Durable Objects). */
  static is(value: unknown): value is SessionError;
}
```

### 2.8 Adapter constructors — example signatures

```ts
// @authkit/sessions/adapters/cookie
export function createCookieStore<T extends SessionData = SessionData>(opts?: {
  /** Hard ceiling on encoded payload size. Default 3072 bytes (browser-safe). */
  maxBytes?: number;
}): SessionStore<T>;

// @authkit/sessions/adapters/memory
export function createMemoryStore<T extends SessionData = SessionData>(opts?: {
  /** Max records — LRU-evicted past this. Default 10_000. */
  maxRecords?: number;
}): SessionStore<T>;

// @authkit/sessions/adapters/redis
export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: { ex?: number }): Promise<unknown>;
  del(key: string | readonly string[]): Promise<number>;
  expire?(key: string, seconds: number): Promise<number>;
  eval?(script: string, keys: readonly string[], args: readonly string[]): Promise<unknown>;
}
export function createRedisStore<T extends SessionData = SessionData>(
  client: RedisLike,
  opts?: { keyPrefix?: string; userIndexPrefix?: string },
): SessionStore<T>;

// @authkit/sessions/adapters/upstash
export function createUpstashStore<T extends SessionData = SessionData>(
  client: import('@upstash/redis').Redis,
  opts?: { keyPrefix?: string },
): SessionStore<T>;

// @authkit/sessions/adapters/cloudflare-kv
export function createKVStore<T extends SessionData = SessionData>(
  kv: KVNamespace,
  opts?: {
    /** Companion KV namespace for user-id → session-id index. Required for concurrency / listByUser. */
    userIndex?: KVNamespace;
    keyPrefix?: string;
  },
): SessionStore<T>;

// @authkit/sessions/adapters/cloudflare-d1
export function createD1Store<T extends SessionData = SessionData>(
  db: D1Database,
  opts?: { tableName?: string },
): SessionStore<T>;

// @authkit/sessions/adapters/postgres
export type PostgresQuery = <Row = unknown>(
  sql: string,
  params: readonly unknown[],
) => Promise<readonly Row[]>;
export function createPostgresStore<T extends SessionData = SessionData>(
  query: PostgresQuery,
  opts?: { tableName?: string },
): SessionStore<T>;

// @authkit/sessions/adapters/durable-object
export function createDurableObjectStore<T extends SessionData = SessionData>(
  stub: DurableObjectStub,
): SessionStore<T>;
```

### 2.9 Framework adapters — examples

```ts
// @authkit/sessions/frameworks/hono
declare module 'hono' {
  interface ContextVariableMap {
    session: SessionRecord<unknown> | null;
    sessions: SessionManager<unknown>;
  }
}
export function honoSessions<T extends SessionData = SessionData>(
  config: SessionConfig<T>,
): import('hono').MiddlewareHandler;

// @authkit/sessions/frameworks/next
export function getServerSession<T extends SessionData = SessionData>(
  manager: SessionManager<T>,
): Promise<SessionRecord<T> | null>; // reads cookies() from next/headers
export function setServerSession<T extends SessionData = SessionData>(
  manager: SessionManager<T>,
  data: T,
  opts?: { userId?: string },
): Promise<SessionRecord<T>>;
export function createSessionMiddleware<T extends SessionData = SessionData>(
  config: SessionConfig<T>,
  matcher?: (req: import('next/server').NextRequest) => boolean,
): (req: import('next/server').NextRequest) => Promise<import('next/server').NextResponse>;

// @authkit/sessions/frameworks/sveltekit
export function createSessionHandle<T extends SessionData = SessionData>(
  config: SessionConfig<T>,
): import('@sveltejs/kit').Handle;
// → augments event.locals.session: SessionRecord<T> | null
```

### 2.10 Ideal DX example (Hono + Cloudflare KV)

```ts
import { Hono } from 'hono';
import { createSessionManager } from '@authkit/sessions';
import { createKVStore } from '@authkit/sessions/adapters/cloudflare-kv';
import { honoSessions } from '@authkit/sessions/frameworks/hono';

type Session = { userId: string; role: 'admin' | 'user' };

interface Env {
  SESSION_KV: KVNamespace;
  SESSION_USER_INDEX: KVNamespace;
  SESSION_SECRET: string;
}

const app = new Hono<{ Bindings: Env; Variables: { session: SessionRecord<Session> | null } }>();

app.use('*', (c, next) =>
  honoSessions<Session>({
    secrets: [c.env.SESSION_SECRET],
    store: createKVStore<Session>(c.env.SESSION_KV, { userIndex: c.env.SESSION_USER_INDEX }),
    expiration: { absoluteSeconds: 60 * 60 * 24 * 30, slidingSeconds: 60 * 60 * 24 * 7 },
    concurrency: { max: 5, strategy: 'lru' },
    csrf: { enforceOrigin: true },
  })(c, next),
);

app.get('/me', (c) => {
  const session = c.get('session');
  if (!session) return c.json({ error: 'unauthorized' }, 401);
  return c.json(session.data); // <- typed as Session
});

app.post('/logout', async (c) => {
  const { applyTo } = await c.var.sessions.destroy(c.req.raw);
  return new Response(null, applyTo({ status: 204 }));
});
```

---

## 3. Internal Architecture

### 3.1 Module dependency graph

```
                       ┌─────────────────────┐
                       │   src/index.ts       │ public root
                       └─────────┬───────────┘
                                 ▼
                       ┌─────────────────────┐
                       │ core/manager.ts      │ orchestrator
                       └─┬──────┬──────┬─────┘
                         │      │      │
            ┌────────────┘      │      └────────────┐
            ▼                   ▼                    ▼
    ┌──────────────┐   ┌────────────────┐    ┌──────────────┐
    │ core/        │   │ core/cookie.ts │    │ types/*      │
    │ lifecycle.ts │   │ core/headers.ts│    │ (zero-runtime)│
    └──┬───┬───────┘   └────────┬───────┘    └──────────────┘
       │   │                    ▼
       │   │            ┌──────────────┐
       │   └──────────► │ core/encoder │ JSON envelope
       │                └──────┬───────┘
       │                       ▼
       │                ┌──────────────┐
       │                │ crypto/aead  │ AES-GCM seal/open
       │                │ crypto/hmac  │ HMAC-SHA256 sign/verify
       │                │ crypto/kdf   │ HKDF — derive 2 keys from 1 secret
       │                └──────────────┘
       │
       ├── core/expiration.ts  (sliding + absolute window)
       ├── core/concurrency.ts (LRU/FIFO/deny-new — calls store.listByUser)
       ├── core/csrf.ts        (double-submit issue + verify)
       ├── core/fingerprint.ts (UA/IP HMAC, mismatch policy)
       ├── core/audit.ts       (composeAuditHook, JSON formatter)
       └── core/id.ts          (256-bit random + base64url)
```

`SessionStore` is an interface, not an import — adapters live behind their
own subpath exports and are pulled in **only** when the user imports them.
Conversely, `core/*` never imports any adapter, so a consumer who imports
the cookie store does not pull Redis, Postgres, or DO clients.

### 3.2 Data flow — the request lifecycle

```
Request ──► core/headers.parseCookie    ──┐
                                          ▼
                              core/cookie.parseEnvelope
                                          ▼
                             crypto/hmac.verify (constant-time)
                                          ▼
                             crypto/aead.open  (cookie-store path)
                                       │
                          ┌────────────┴───────────────┐
                          ▼                            ▼
              [stateful adapter]               [cookie-only adapter]
              core/lifecycle.read              record materialised inline
                          │                            │
                          └────────────┬───────────────┘
                                       ▼
                       core/expiration.evaluate(record, now)
                                       ▼
                          ┌────────────┴────────────┐
                       ALIVE                      EXPIRED
                          │                          │
                          ▼                          ▼
                core/fingerprint.check        emit 'session.read.failed'
                          │                  return null
                          ▼
                   core/csrf.attach
                          ▼
                 SessionRecord<T>  ────► handler
```

Mutating ops follow the same prefix, then branch into
`core/lifecycle.{create|update|rotate|destroy}` which encodes a new record,
hands it to the store, and returns `SessionAttachment<T>` containing a
fully-formed `Set-Cookie` header.

### 3.3 Key design patterns

- **Adapter pattern (storage + framework)** — two orthogonal axes. The core
  manager works with **one** small interface per axis (`SessionStore`,
  `Request/Response`); every adapter is a thin glue layer ≤200 LOC.
- **Pure core, impure edges** — every function in `core/*` is pure with
  injected `now()` and explicit `Request` input. Side effects (network,
  process.env access, console.warn) live in `adapters/*` and `utils/env.ts`.
  Lets the test suite execute without mocks for 80 % of code paths.
- **Frozen handles** — `createSessionManager` returns a `Object.freeze`d
  object so callers cannot accidentally mutate config at runtime.
- **Single time source** — every clock read goes through `core/time.ts`,
  swapped via `config.clock`. Eliminates flaky tests around clock skew.
- **HKDF key separation** — the user gives one secret; we derive two
  internal keys (`enc` + `sig`) so they are never reused across primitives,
  per NIST SP 800-108.
- **Zero `any`, no internal casts** — `as` is banned by Biome rule outside
  `core/encoder.ts` (envelope deserialisation) and `crypto/*` (Uint8Array
  view casts). Runtime validation of decoded payloads happens at the
  boundary, not deep inside the engine.
- **Atomic concurrency** — Redis adapter ships a Lua script that does
  `LRANGE → EVICT → LPUSH` in one round-trip; Postgres adapter uses a
  single `WITH inserted AS (...) DELETE FROM ... WHERE ...` CTE; KV /
  Upstash use eventual consistency with a "stale-set tolerated, never
  exceeds N+1" guarantee documented in §9.

---

## 4. Type System

### 4.1 The single generic `T extends SessionData`

`T` flows from the consumer to **every** API surface — `SessionConfig<T>`,
`SessionStore<T>`, `SessionManager<T>`, `SessionRecord<T>`,
`SessionAttachment<T>`, `getServerSession<T>`. There is **no** `as` cast in
the runtime; type safety is preserved end-to-end through default
inference + `infer` in framework adapters.

```ts
// Inferred from store argument:
const sessions = createSessionManager({
  secrets: [SECRET],
  store: createRedisStore<{ userId: string }>(redis),
}); //  ^? SessionManager<{ userId: string }>

// Or supplied explicitly when the store is generic:
const sessions = createSessionManager<{ userId: string }>({ secrets: [SECRET] });
```

### 4.2 Conditional type for `SessionAttachment`

`SessionAttachment<T>` carries `record: T | null`, but typing a destroy
attachment as `SessionRecord<null>` is wrong (record is gone). The
conditional type encodes the invariant:

```ts
export interface SessionAttachment<T extends SessionData | null> {
  readonly record: T extends null ? null : SessionRecord<NonNullable<T>>;
  readonly setCookie: string;
  readonly applyTo: (init?: ResponseInit) => ResponseInit;
}
```

Consumers calling `destroy()` get `record: null` automatically; consumers
calling `create() / update() / rotate()` get `record: SessionRecord<T>`.

### 4.3 Framework augmentation

Hono / Express / Fastify / SvelteKit all support module augmentation. The
adapters use it to add typed `c.get('session')`, `req.session`,
`event.locals.session` — **typed via `T`**, not `any`:

```ts
// in @authkit/sessions/frameworks/hono/index.ts
declare module 'hono' {
  interface ContextVariableMap {
    session: SessionRecord<unknown> | null;
    sessions: SessionManager<unknown>;
  }
}
```

The `unknown` is intentional — consumers re-augment with their own `T` in a
single `.d.ts` file (documented in README), the recommended Hono pattern.

### 4.4 Branded ids

`SessionId` and `CsrfToken` are branded primitives:

```ts
export type SessionId = string & { readonly __brand: 'SessionId' };
export type CsrfToken = string & { readonly __brand: 'CsrfToken' };
```

Prevents accidentally passing a user id where a session id is expected,
without any runtime cost (the brand is a phantom property).

### 4.5 `Result<T, E>` for non-throwing reads

Most reads return `T | null`, but operational APIs that need to distinguish
"missing" from "store down" use `Result<T, SessionError>`:

```ts
export type Result<T, E = SessionError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
```

Used internally by `core/lifecycle.ts` to bubble store errors without
throwing in middleware paths. **Not** exposed on the public surface for
common operations — `null` is the right return shape for "no session".

### 4.6 Compile-time guarantees enforced

- `noUncheckedIndexedAccess` — every `headers.get(name)` is `string | undefined`.
- `exactOptionalPropertyTypes` — `cookie.domain?: string` rejects `undefined`
  assignments, so the cookie serializer never emits `Domain=undefined`.
- `verbatimModuleSyntax` — `import type` is enforced; the build never emits
  type imports as runtime imports (broken Workers bundles).
- `useUnknownInCatchVariables` — every `catch` handler proves it received
  an unknown before touching the value; eliminates a class of CVEs where
  `err.code` is read after a non-Error throw.

---

## 5. Error Handling Strategy

### 5.1 When to throw vs return `null`

| Operation                          | Failure mode                  | Behaviour            |
|-----------------------------------|-------------------------------|----------------------|
| `manager.get(req)`                | missing / expired / tampered  | `null` + audit event |
| `manager.get(req)`                | store unreachable             | throw `STORE_UNAVAILABLE` |
| `manager.create(req, data)`       | id collision                  | retry once, then throw `CONFLICT` |
| `manager.create(req, data)`       | concurrency `deny-new`        | throw `CONCURRENCY_DENIED` |
| `manager.update(req, fn)`         | no active session             | throw `NOT_FOUND` |
| `manager.update(req, fn)`         | record changed under us       | retry once, then throw `CONFLICT` |
| `manager.rotate(req)`             | no active session             | throw `NOT_FOUND` |
| `manager.destroy(req)`            | nothing to destroy            | resolve — idempotent |
| `manager.verifyCsrf(req, token)`  | any mismatch                  | resolve `false` + audit `csrf.failed` |
| `createSessionManager(config)`    | invalid secrets               | throw at construction `SECRET_TOO_SHORT` |
| `createSessionManager(config)`    | invalid policy                | throw at construction `CONFIG_INVALID` |

The rule of thumb: **read paths never throw on user-controlled inputs**
(missing cookies, expired sessions, tampered envelopes — all user-supplied
and should not generate 500s). Mutating paths throw on programmer errors
and infrastructure failures.

### 5.2 `SessionError` shape

```ts
export class SessionError extends Error {
  readonly name = 'SessionError';
  readonly code: SessionErrorCode;
  /** Original cause when wrapping store errors. Never serialised by default. */
  readonly cause?: unknown;
  /** Safe-to-log message — never includes session ids or user secrets. */
  readonly publicMessage: string;
  constructor(code: SessionErrorCode, message: string, cause?: unknown);
  static is(value: unknown): value is SessionError;
}
```

`static is()` works across realm boundaries (Workers ↔ Durable Objects),
where `instanceof` fails. It checks the `name` and `code` shape.

### 5.3 Adapter error wrapping

Every adapter wraps thrown infrastructure errors in
`new SessionError('STORE_UNAVAILABLE', '...', { cause: original })` so
consumers get a stable error code regardless of which store they use.
The original `cause` is preserved for debugging.

### 5.4 Audit-first signalling

For every "expected" failure mode (`INVALID_COOKIE`, `EXPIRED`,
`CSRF_INVALID`, `FINGERPRINT_MISMATCH`) the manager emits a structured
audit event **before** returning `null` / throwing. This lets ops teams
build dashboards on Auth-related anomalies without instrumenting the
library themselves.

---

## 6. Bundle & Tree-shaking Plan

### 6.1 Entry points

The package ships **20+ subpath exports**, every one a leaf module that the
bundler can tree-shake on its own. The user pays only for what they import.

| Subpath                                  | Bundle target | Notes                                     |
|------------------------------------------|--------------|--------------------------------------------|
| `@authkit/sessions`                      | **6 KB**     | core engine — manager + cookie + crypto    |
| `@authkit/sessions/errors`               | **0.4 KB**   | `SessionError` + codes                     |
| `@authkit/sessions/crypto`               | **2.0 KB**   | re-exports `aead`, `hmac`, `kdf` for power users |
| `@authkit/sessions/adapters/memory`      | **0.5 KB**   | dev-only LRU in-memory store               |
| `@authkit/sessions/adapters/cookie`      | **0.8 KB**   | adds the cookie-store wrapper              |
| `@authkit/sessions/adapters/redis`       | **1.2 KB**   | + Lua snippet inlined as string            |
| `@authkit/sessions/adapters/upstash`     | **1.0 KB**   | uses `@upstash/redis` peer client           |
| `@authkit/sessions/adapters/cloudflare-kv` | **0.9 KB** | KV + companion userIndex                   |
| `@authkit/sessions/adapters/cloudflare-d1` | **1.1 KB** | D1 + prepared statements                   |
| `@authkit/sessions/adapters/postgres`    | **1.3 KB**   | works with pg / postgres / neon            |
| `@authkit/sessions/adapters/durable-object` | **0.7 KB** | reference DO impl                         |
| `@authkit/sessions/frameworks/hono`      | **0.6 KB**   |                                            |
| `@authkit/sessions/frameworks/elysia`    | **0.6 KB**   |                                            |
| `@authkit/sessions/frameworks/next`      | **1.0 KB**   | App Router + middleware split exports      |
| `@authkit/sessions/frameworks/remix`     | **0.7 KB**   | createSessionStorage shape                 |
| `@authkit/sessions/frameworks/sveltekit` | **0.7 KB**   | handle wrapper                             |
| `@authkit/sessions/frameworks/express`   | **0.8 KB**   | (req,res,next) compat layer                |
| `@authkit/sessions/frameworks/fastify`   | **0.7 KB**   | fastify-plugin                             |
| `@authkit/sessions/frameworks/h3`        | **0.6 KB**   | h3 / Nitro                                 |

Budgets are enforced in CI via `size-limit` (see `.size-limit.json`). A PR
that breaks the budget fails the check.

### 6.2 Tree-shaking enablers

- `"sideEffects": false` in `package.json` — every module is pure (no
  top-level `console.warn`, no module-init side effects, no IIFE).
- **No barrel re-exports** in `src/core/*` → only at package boundaries
  (`src/index.ts`, `src/errors/index.ts`, `src/crypto/index.ts`) which are
  themselves tiny.
- **Per-feature opt-in** — `concurrency`, `fingerprint`, `csrf`, `audit`
  are all unused when the consumer doesn't pass the corresponding config
  field. Each feature module's exports are referenced only inside
  conditional branches that are minified away when the option is `undefined`.
- **No defensive `try/catch` around imports** — every conditional import
  is dynamic when truly optional (e.g. the express adapter dynamically
  imports `node:querystring` only when called from Express ≤4).

### 6.3 ESM-only

The package is **pure ESM** (`"type": "module"`, no `require` build).
Every supported runtime ships native ESM in 2026 (Node 20+, Bun, Deno,
all edge runtimes). Avoiding the dual-package hazard saves ~1 KB and a
non-trivial maintenance surface.

### 6.4 Build pipeline

`tsup` produces ESM + DTS for each `src/**/index.ts` listed in `tsup.config.ts`.
Build invariants enforced in CI:

- `attw --pack .` — `arethetypeswrong` validates every subpath under all
  resolution modes (`node10`, `node16`, `bundler`).
- `publint` — catches `package.json` shape errors (missing `types`
  conditions, mis-ordered keys).
- `size-limit` — per-entry KB budgets (table above).
- `vitest run --typecheck` — `.test-d.ts` files exercise generic propagation.

---

## 7. Dependencies

### 7.1 Runtime dependencies

| Package           | Why                                                    | Approx size | Audit status      |
|-------------------|---------------------------------------------------------|-------------|-------------------|
| `@noble/ciphers`  | AES-256-GCM (cookie sealing)                           | ~3 KB       | Audited (Cure53, Trail of Bits) |
| `@noble/hashes`   | HMAC-SHA256 (signing) + HKDF + SHA-256 (device hash)   | ~3 KB       | Same vendor, same audits         |

These are the same primitives backing `@oslojs/*` and the `arctic` OAuth
library — best-in-class TypeScript crypto with no native bindings, so they
work in every target runtime including Workers and Deno's Fresh.

**Why not Web Crypto for everything?** Web Crypto's `subtle.encrypt` does
work for AES-GCM, but its API is async-only and ~1.5× slower per operation
than `@noble/ciphers` in the cookie hot path (benchmarked on Node 20 + V8
12.1, 1k ops). For the hashes path we still use `globalThis.crypto` for
`getRandomValues` (the only sync-mandated primitive); everything else goes
through `@noble`. Net win: smaller bundle, faster, sync where it matters.

### 7.2 Peer dependencies (all optional)

| Package                   | When                                       |
|---------------------------|--------------------------------------------|
| `hono`                    | `frameworks/hono`                          |
| `elysia`                  | `frameworks/elysia`                        |
| `next`                    | `frameworks/next`                          |
| `@remix-run/server-runtime` (or `react-router`) | `frameworks/remix`        |
| `@sveltejs/kit`           | `frameworks/sveltekit`                     |
| `express`                 | `frameworks/express`                       |
| `fastify`                 | `frameworks/fastify`                       |
| `h3`                      | `frameworks/h3`                            |
| `@upstash/redis`          | `adapters/upstash`                         |
| `@cloudflare/workers-types` | `adapters/cloudflare-kv`, `cloudflare-d1`, `durable-object` (devDep only — types) |

All peer deps are listed in `peerDependenciesMeta` with `"optional": true`,
so npm/pnpm/bun installers don't warn when a consumer skips an unrelated
adapter.

### 7.3 Dev dependencies (high level)

`vitest`, `@vitest/coverage-v8`, `@cloudflare/vitest-pool-workers`,
`miniflare`, `tsup`, `@arethetypeswrong/cli`, `publint`,
`@biomejs/biome`, `size-limit`, `@size-limit/preset-small-lib`,
`@changesets/cli`, `pg-mem`, `ioredis-mock`, `supertest`, plus
`@types/node`, `@types/express` (only types).

### 7.4 Why two deps and not zero

Implementing AES-GCM and HMAC-SHA256 from scratch for the cookie path is a
poor trade-off — it adds CVE risk for ~2 KB savings. `@noble/*` is
hand-audited, side-channel-careful, MIT-licensed, and well-known in the
TypeScript-auth ecosystem. **Cookie-only adapter still needs them**;
consumers using only server-side stores (Redis/KV/D1/PG) get them too
because cookie envelope signing is universal. We do **not** ship a JWT
library — sessions are opaque ids; encryption only happens for cookie
envelope and CSRF token derivation.

---

## 8. Configuration

### 8.1 `package.json` (scaffold — see file at repo root)

Highlights:

- `"name": "@authkit/sessions"`, `"version": "0.1.0"`, `"type": "module"`.
- `"sideEffects": false`.
- `"exports"` maps every subpath listed in §6.1 to its `dist/**/index.js`
  with the matching `types` condition first (NodeNext requires it).
- `"engines": { "node": ">=20" }` — Node 18 is EoL April 2025, Node 20 is
  the current LTS in 2026.
- `"keywords"` matches the SEO list from `reports/05-session-vault.json`.
- `"scripts"` parallels the sibling `@authkit/permissions` library (build,
  test, test:types, lint, format, size, publint, attw, release).

### 8.2 `tsconfig.json`

```jsonc
{
  "compilerOptions": {
    "target": "ES2024",
    "lib": ["ES2024", "DOM", "DOM.Iterable"],
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "useUnknownInCatchVariables": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "rootDir": "src",
    "outDir": "dist",
    "types": ["node", "@cloudflare/workers-types"]
  },
  "include": ["src"]
}
```

A `tsconfig.build.json` extends this and excludes `test/` and
`**/*.test-d.ts` from emit.

### 8.3 `vitest.config.ts`

A single file with **two workspaces**:

1. **node** — default pool, runs `test/{core,crypto,adapters,frameworks,security,bench}/**`
2. **workers** — `@cloudflare/vitest-pool-workers`, runs
   `test/runtime/workers.test.ts` against a real Workers V8 isolate +
   miniflare-bound KV / D1 / DO.

Coverage thresholds: 95 % statements / 90 % branches across `src/core` and
`src/crypto`; 80 % for adapters and frameworks (lower because the upper
bounds are exercised in the runtime workspace, not the node pool).

### 8.4 `.gitignore`

See file at repo root. Convention: **no `./` prefix** on patterns
(critical — `./node_modules` silently fails to match when git evaluates
.gitignore relative to the repo root, the result is `node_modules`
sneaking into commits).

### 8.5 `.npmignore`

Inverse of `.gitignore`-style approach: an explicit `files` array in
`package.json` (`["dist", "README.md", "LICENSE"]`) is the source of
truth — the `.npmignore` is a defence-in-depth safety net that excludes
`test/`, `examples/`, `*.config.ts`, `coverage/`, `PLAN.md`.

### 8.6 `biome.json`

Formats + lints. Custom rules:

- Ban `console.*` outside `utils/env.ts` and `adapters/memory/index.ts`.
- Ban `as ` (TypeScript cast) outside `core/encoder.ts`, `crypto/*`,
  `utils/base64url.ts`.
- Ban dynamic `process.env.*` access outside `utils/env.ts`.

---

## 9. Edge Cases

The implementation MUST handle the following — each has a dedicated test in
`test/security/` or `test/core/`.

### 9.1 Cookie-layer edge cases

1. **Missing cookie header entirely.** `get()` returns `null` silently, no
   `INVALID_COOKIE` audit (it's a normal anonymous request).
2. **Cookie present but malformed envelope.** Returns `null`,
   audits `session.read.failed` with `INVALID_COOKIE`.
3. **Cookie present, envelope OK, signature fails.** Returns `null`,
   audits with `INVALID_SIGNATURE`. NEVER decrypts before HMAC verify
   (encrypt-then-MAC).
4. **Multiple `Cookie` headers** (legacy proxies). Parser concatenates.
5. **Multiple cookies with the same name** (browser-side weirdness when
   `Domain=` and host-only coexist). Pick the first that verifies; ignore
   the rest. Audit on more than one parse attempt.
6. **`Set-Cookie` header > 4096 bytes** (cookie store). Hard fail with
   `PAYLOAD_TOO_LARGE`; never silently truncate.
7. **`__Host-` prefix invariants.** When `cookie.prefix === '__Host-'`,
   cookie serializer enforces `Path=/`, `Secure`, no `Domain=` — and
   throws `CONFIG_INVALID` if the user opts into a conflicting attribute.
8. **`SameSite=None` without `Secure`.** Throws `CONFIG_INVALID` —
   browsers ignore the cookie otherwise; failing fast is the correct DX.
9. **Existing `Set-Cookie` headers** in the response. `applyTo()` appends
   without clobbering — a single `Headers` object can hold both the
   session cookie and a CSRF mirror.

### 9.2 Crypto / signature edge cases

1. **Secret rotation.** First key in `secrets[]` is used to sign new
   cookies; **every** key is tried for verification. Rotating in =
   prepend new key, redeploy, leave old key for one absolute-expiration
   window, drop.
2. **Secret too short.** Construction-time validation: HKDF input ≥32
   bytes; throw `SECRET_TOO_SHORT` clearly with the actual byte count.
3. **Tampered ciphertext.** AES-GCM authenticated decryption fails
   atomically; the manager treats the failure indistinguishably from a
   missing cookie (constant-time path).
4. **Replay of an old, unrotated id.** When `expiration.rotateAfterSeconds`
   is set, the manager auto-rotates on first read past the threshold —
   the old id can no longer be replayed.
5. **Clock skew.** `expiration.evaluate(record, now)` allows ±60 s of
   leeway by default; below that it tolerates skew, above it expires.

### 9.3 Concurrency / multi-instance edge cases

1. **N+1 race when two requests hit the limit simultaneously.** Redis
   adapter uses Lua `EVAL` for atomic `LRANGE → check → LPUSH → EXPIRE`.
   Postgres uses a `WITH inserted AS (...) DELETE FROM ... WHERE ...`
   single-statement CTE. KV and Upstash pipelines fall back to "best-effort"
   eviction with a documented worst-case overshoot of 1.
2. **`deny-new` strategy.** Throws `CONCURRENCY_DENIED` BEFORE creating
   the session, so the failed `create()` does not leave a half-written
   record in the store.
3. **`listByUser` returning stale entries.** Concurrency check first
   filters out `expiresAt < now()` records; never trusts the index alone.
4. **User id changes mid-session** (rare but happens during account
   merge). `update()` does NOT change `meta.userId` — that's only
   settable on `create()`. Account-merge flows must `rotate()` and then
   `revokeBySessionId()` the old.

### 9.4 Fingerprint / device edge cases

1. **Mobile carrier IP roams.** The default fingerprint config does NOT
   include IP; the user must opt in. When opted in, `onMismatch:
   'rotate'` is the recommended setting, not `'destroy'`.
2. **Bot User-Agent ranges.** Fingerprint is a hash, never a parser —
   we don't try to interpret UA. Mismatch is mismatch, full stop.
3. **`X-Forwarded-For` spoofing.** Default extractor takes the **first**
   hop (closest to client) which is what every reverse-proxy guide
   recommends; consumers behind multiple trusted proxies override `ip(req)`.
4. **No IP available** (Cloudflare local dev, some serverless platforms).
   Default extractor returns `undefined` → IP component is omitted from
   the hash. No throw.

### 9.5 CSRF edge cases

1. **Safe methods (`GET`, `HEAD`, `OPTIONS`)** are never enforced — even
   if the user adds them to `protectedMethods`, the manager logs a warning
   and ignores; safe methods MUST stay safe.
2. **Origin / Host mismatch** on `enforceOrigin: true`. If both `Origin`
   and `Referer` are absent, fail closed (`csrf.failed` reason `'origin'`).
3. **CSRF token without an active session.** Returns `false`, audits with
   `'no-session'` — the absence of a session implies no protected action.
4. **Cookie-store + CSRF.** When the session is stateless (cookie store),
   the CSRF token is derived from `meta.csrf` carried inside the
   encrypted envelope, so revoking is implicit on `destroy()`.

### 9.6 Storage adapter edge cases

1. **Redis disconnect mid-create.** The adapter wraps the underlying
   `ECONNRESET` in `STORE_UNAVAILABLE`; the manager surfaces it; the
   handler decides whether to retry. We do NOT auto-retry — that's
   middleware's job, not the library's.
2. **Cloudflare KV eventual consistency.** Reads after a `destroy()` may
   return the deleted record for up to 60 s globally. Documented
   prominently in the KV adapter README; the manager additionally checks
   `meta.expiresAt < now()` against a per-record tombstone marker
   (`destroyedAt`) we set in `destroy()` — providing immediate revoke at
   the cost of one extra small write that lives `expiresAt`-long.
3. **Postgres connection pool exhaustion.** Adapter does not own the
   pool; thrown errors propagate through `STORE_UNAVAILABLE`.
4. **D1 row size limit (1 MB).** Encoded record > 950 KB throws
   `PAYLOAD_TOO_LARGE` before write. (Practical sessions never approach
   this, but a typo `data: { x: hugeBlob }` should fail loudly.)
5. **Memory store in a serverless cold start.** The default warning emits
   exactly once per process via a module-scope `Symbol.for('authkit:memory:warned')`.
   Consumers explicitly disable with `createMemoryStore({ silent: true })`
   when intentional (tests).

### 9.7 Cookie-store specific edge cases

1. **Encoded payload > `maxBytes`.** Throws `PAYLOAD_TOO_LARGE` on
   `create` / `update`, never silently truncates.
2. **`listByUser` not supported** (cookie is per-browser, no cross-device
   index). The adapter returns `[]` and emits a one-shot warning when
   `concurrency` is configured against it. Consumers using cookie store
   for multi-device features should use a different adapter.
3. **`destroy()` semantics.** The cookie envelope is local; `destroy()`
   emits an expiring `Set-Cookie` to clear the browser copy. Server-side
   "log out everywhere" is impossible with a stateless adapter, by design.

### 9.8 Framework adapter edge cases

1. **Hono + Workers + KV** — `c.executionCtx.waitUntil(audit(event))`
   is used so the audit hook does not delay the response. The hono
   adapter passes `waitUntil` into the manager via `config.audit`.
2. **Next.js App Router + `cookies()` from `next/headers`** — works only
   in Server Components / Route Handlers / Server Actions. `getServerSession`
   detects misuse (bad context) and throws a friendly "called outside
   server context" error.
3. **Next.js middleware** runs at the edge before the cookie layer is
   re-set; mutating cookies must use `NextResponse.cookies.set()` not
   `Response.headers.append('set-cookie', ...)`. The middleware adapter
   handles both seamlessly.
4. **Express + JSON-body parsers** — CSRF verification needs the body
   parsed. The adapter requires `express.json()` / `express.urlencoded()`
   to run **before** the session middleware for protected methods; this
   is documented + asserted in dev mode.
5. **SvelteKit `event.cookies.set` vs raw `Headers`** — the adapter uses
   `event.cookies.set()` so the framework's own typed cookie store stays
   in sync.

### 9.9 Concurrent request edge cases

1. **Two requests in parallel touching the same session** (sliding
   expiration). `touchThrottleSeconds` (default 60s) deduplicates writes
   so we don't thrash the store.
2. **Rotation race.** Two parallel rotations both succeed but one wins
   the cookie; the other's id is orphaned and GC'd by store TTL. Audit
   logs both `rotated` events with distinct `newId`s.
3. **Rotate during destroy.** The manager serialises the per-request
   pipeline via a single `Promise` chain — no two ops on the same
   request can interleave.

---

## 10. Out of Scope (1.0)

Explicitly **not** addressed by `@authkit/sessions` — to keep scope tight
and the bundle small. Each is either a separate library in the `@authkit`
namespace or a problem we deliberately don't take on.

- **Authentication (login, password verification, OAuth).** Sessions are
  given a `userId`; how the user got it is the consumer's call. Use
  `arctic`, `@auth/core`, `better-auth`, or build it yourself.
- **Multi-factor (MFA / TOTP).** Slated for `@authkit/mfa`.
- **Passkeys / WebAuthn.** Slated for `@authkit/passkeys` (sibling lib).
- **Permissions / RBAC / ABAC.** Use `@authkit/permissions` (sibling lib).
- **Rate limiting.** Use `@devkit/ratelimit` or any general-purpose
  library; the manager exposes audit events you can plug into a limiter.
- **JWT issuance.** Sessions are opaque ids by design — see the
  interview talking points in the research report for the rationale.
- **Email / SMS verification flows.** Out of scope; consume our audit
  events to drive your own.
- **Session storage migrations.** v0.x → v1.0 ships a migration helper
  for the envelope tag (`v: 1`); changes between minor versions never
  break record format.
- **GUI for "Active devices".** We provide `listByUser()`; the rendering
  is yours. A reference React component will live in `examples/`, not in
  the library.
