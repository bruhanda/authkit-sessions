# Changelog

All notable changes to `@authkit/sessions` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-02

Initial release. Universal, TypeScript-first session layer with pluggable storage adapters and opt-in security features.

### Added

- **Core manager.** `createSessionManager<T>(config)` returns a frozen `SessionManager<T>` with `get`, `create`, `update`, `rotate`, `signOut`, `revokeBySessionId`, `revokeByUser`, `listByUser`, `verifyCsrf`, and `getCsrfToken`. Built on Web Standards `Request` / `Response` / `Headers` so the same instance runs on Node 20+, Bun, Deno, Cloudflare Workers, Vercel Edge, and Netlify Edge.
- **Typed `SessionAttachment<T>`** with `record`, `cookie`, `headers`, and `attachTo()` so callers can compose response headers in whichever style their framework prefers.
- **`SessionError`** — a single error class with stable codes (`INVALID_COOKIE`, `INVALID_SIGNATURE`, `EXPIRED`, `NOT_FOUND`, `CONFLICT`, `CONCURRENCY_DENIED`, `CSRF_INVALID`, `CSRF_MISSING`, `STORE_UNAVAILABLE`, `SECRET_TOO_SHORT`, `CONFIG_INVALID`, `PAYLOAD_TOO_LARGE`, `FINGERPRINT_MISMATCH`) and a realm-safe `SessionError.is()` type guard.
- **Cryptographic primitives** (`@authkit/sessions/crypto`): AES-256-GCM AEAD, HMAC-SHA256 signatures, HKDF-SHA256 key derivation (separate keys for encryption, signing, and fingerprinting), constant-time string compare, and CSPRNG-backed id / token generation. Secrets must carry >=256 bits of entropy.
- **Storage adapters** as separate entry points:
  - `/adapters/memory` — in-process `Map` for tests and dev (LRU eviction past `maxRecords`).
  - `/adapters/cookie` — `createCookieCodec` + `createCookieStore` for fully stateless AES-256-GCM-sealed cookies.
  - `/adapters/redis` — works with ioredis, node-redis 4+, and the Bun-native client; honours native `EX` TTL and uses Lua for atomic user-index ops when the client supports `eval`.
  - `/adapters/upstash` — HTTP-pipelined adapter for `@upstash/redis` (no Lua dependency).
  - `/adapters/cloudflare-kv` — KV-backed adapter with optional companion namespace for the user index.
  - `/adapters/cloudflare-d1` — strongly consistent SQLite adapter; ships `schema.sql`.
  - `/adapters/postgres` — driver-agnostic adapter that takes any `(sql, params) => Promise<Row[]>` query function.
  - `/adapters/durable-object` — JSON-over-`fetch` against a Durable Object stub.
- **Opt-in features** at separate subpaths so unused features never reach the bundle:
  - `/csrf` — OWASP double-submit cookie + optional `Origin` enforcement (on by default in framework adapters).
  - `/fingerprint` — HMAC-hashed device fingerprinting from configurable components (`user-agent`, `accept-language`, `sec-ch-ua`, optional `ip`); `onMismatch` policy of `rotate` (default), `destroy`, or `ignore`. Raw inputs are never persisted.
  - `/concurrency` — per-user session limits with `lru` / `fifo` / `deny-new` eviction strategies.
  - `/audit` — discriminated-union event stream (`session.created`, `session.read`, `session.read.failed`, `session.updated`, `session.rotated`, `session.destroyed`, `session.evicted`, `csrf.failed`) with `composeAuditHook` for fan-out and `formatAuditEventJson` for structured logging.
- **Framework adapters**, each at its own entry point and CSRF-on-by-default:
  - `/frameworks/hono` — middleware that exposes `c.var.sessions` and `c.var.session`.
  - `/frameworks/elysia` — plugin factory that derives a typed store on the app.
  - `/frameworks/next` — `getServerSession`, `setServerSession`, `createSessionMiddleware`, and `withSession` for App Router + middleware + Route Handlers.
  - `/frameworks/remix` — `getSession` / `commitSession` / `destroySession` matching the Remix shape.
  - `/frameworks/sveltekit` — `createSessionHandle` for the `Handle` hook with `event.locals` augmentation.
  - `/frameworks/express` — Node `IncomingMessage` -> Web `Request` bridge with `req.session` / `req.sessions`.
  - `/frameworks/fastify` — plugin that decorates the app and adds an `onRequest` hook.
  - `/frameworks/h3` — event handler for h3 / Nitro / Nuxt with `event.context.session` / `event.context.sessions`.
- **Sliding + absolute expiration** with `touchThrottleSeconds` to suppress redundant writes; **forced id rotation** past `rotateAfterSeconds` for fixation defence-in-depth (deferred to the next mutation so read paths cannot orphan the browser cookie).
- **Cookie hardening defaults**: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`. Optional `__Host-` / `__Secure-` prefixes and `Partitioned` (CHIPS).
- **Multi-secret rotation**: `secrets` accepts an array; the first entry is active for new cookies, the rest verify legacy cookies. Zero-downtime key rotation.
- **Bundle budgets** enforced in CI via `size-limit` — core stays under 5 KB gzipped, every feature and adapter has its own per-subpath budget.
- **Comprehensive unit tests** covering crypto primitives, core lifecycle, every storage adapter, and every framework adapter.

### Security

- All secrets are validated for >=256 bits of entropy at construction time; `SECRET_TOO_SHORT` is thrown with a message naming the entropy threshold rather than just byte count.
- `SessionError` messages never contain user-controlled values, session ids, or cookie payloads — dynamic data lives in `cause` for server-side debugging only.
- CSRF tokens and session ids are compared in constant time (`timingSafeEqualString`).
- Device fingerprint components are HMAC-digested with a derived key — raw IP / UA / `sec-ch-ua` values never leave the request.
- `SessionError.is()` works across realm boundaries (Workers <-> Durable Objects) where `instanceof` returns false.

[0.1.0]: https://github.com/bruhanda/authkit-sessions/releases/tag/v0.1.0
