# Response to code review on PR #1

Each numbered item below mirrors a finding from Mykhailo's review. Where I changed code, the file paths and the gist of the fix are listed; where I declined or partially agreed, the reasoning is in line.

---

## 1. [CRITICAL] Cookie header injection in `serializeCookie`

**Concern:** `domain` / `path` interpolated into `Set-Cookie` with no validation; an app that sourced either from user-influenced config could be tricked into emitting `Domain=evil.com\r\nSet-Cookie: x=y; ...`.

**Files changed:** `src/core/cookie.ts`.

**Fix:** added two regex guards plus a `rejectHeaderInjection` helper. `path` is now restricted to printable ASCII without `;` or whitespace; `domain` must match a strict RFC 1123 label pattern. Both are pre-checked for CR / LF / `;` / control bytes / whitespace before any interpolation. Bad values throw `SessionError('CONFIG_INVALID', ...)` at `serializeCookie` call time — i.e. at boot for the session cookie, on first set for any future admin path.

---

## 2. [CRITICAL] Atomic concurrency / Lua / Postgres CTE not implemented

**Concern:** plan committed to atomic Lua / CTE; current code does `listByUser → for each await store.delete`, leaving the N+1 race wide open.

**Files changed:** `PLAN.md` §3.4 ("Best-effort concurrency"), `src/features/concurrency/index.ts` (docstring), `src/adapters/redis/lua.ts` (header comment).

**Decision:** went with **option (b)** — downgraded the plan and the feature docs to "best-effort". The atomic primitives are non-trivial (single-EVAL enforce-and-evict for Redis, single-statement CTE for Postgres) and pulling them in alongside the rest of this review's fixes would have ballooned the diff. The plan now explicitly says concurrency is best-effort across every adapter and that two parallel `create()` calls can briefly admit `max + 1`. The cookie-codec adapter's no-op behaviour is also called out, and the manager now emits a one-shot dev warning when both `cookieCodec` and `concurrency` are wired (see §19 below). Atomic primitives are tracked as follow-up work alongside the lifecycle-hook refactor (§7).

---

## 3. [HIGH] `onMismatch: 'rotate'` was a silent no-op

**Concern:** comment said "rotate happens on the next mutation," but no code consumed the mismatch flag, and `record.meta.device` was never refreshed — every subsequent read from the new device repeated the mismatch indefinitely.

**Files changed:** `src/core/manager.ts`, `src/types/session.ts`.

**Fix:** added an optional `rotatePending: boolean` to `SessionMetadata`. On mismatch with `onMismatch: 'rotate'`, `readActive` now (a) refreshes `meta.device` to the **current** fingerprint so subsequent reads on the new device do not loop and (b) sets `rotatePending: true`, persisted via the existing touch path. The next `update()` / `rotate()` consumes the flag, mints a fresh `id` + `csrf`, and emits `session.rotated`. I deliberately did **not** rotate inline from `manager.get` — read paths cannot emit `Set-Cookie`, so an inline rotate would orphan the browser cookie. Documented in the new field's JSDoc.

---

## 4. [HIGH] `rotateAfterSeconds` policy was dead

**Concern:** `evaluate()` returned `rotate: true` past the threshold but `readActive` ignored it.

**Files changed:** `src/core/manager.ts`.

**Fix:** `outcome.rotate` is now consumed by the same `rotateOnNext` flag the fingerprint path uses. The next mutation rotates id+csrf inline. Same reasoning as §3 for not rotating from inside the read path. `shouldRotateOnMutation` is a small helper that re-checks the age threshold on every mutation as a safety net (the outcome from `readActive` is not piped into the mutation directly).

---

## 5. [HIGH] Framework adapters did not enable CSRF default-on

**Concern:** user follows README → manager has no `csrf` feature → middleware requires `X-CSRF-Token` while the manager never emits the mirror cookie → 100% broken happy path.

**Files changed:** `src/frameworks/require-csrf.ts` (new), all of `src/frameworks/{hono,elysia,sveltekit,express,fastify,h3,next/middleware}/index.ts`, `src/types/manager.ts`, `src/core/manager.ts`.

**Fix:** went with the reviewer's "refuse to construct without `csrf` set" option. Each framework adapter now calls `assertCsrfReady(manager)` at construction time, which:

- returns `'enabled'` when the manager has the csrf feature → middleware enforces `Origin` + `verifyCsrf` on protected methods,
- returns `'opted-out'` when the user passed `csrf: false` → middleware skips its enforcement,
- throws `SessionError('CONFIG_INVALID', ...)` with a message naming the fix when neither was supplied — bites at boot, not on first POST in production.

Added `__features: ReadonlySet<...>` and `__csrfOptedOut: boolean` to `SessionManager` so the helper has the introspection surface to make that decision. Both are documented as `@internal`.

I considered but rejected wrapping the manager into a "csrf-on" decorator — the manager is already frozen and shared across requests, the wrapper would have to reproduce nine methods, and the mirror cookie write lives inside `buildAttachment` which is not externally reachable. The hard-fail-at-boot path is closer to what the reviewer described as acceptable and matches the `@internal` introspection idiom already used elsewhere in this codebase.

---

## 6. [HIGH] `signOut` swallowed `STORE_UNAVAILABLE`

**Concern:** `await store.delete(id).catch(() => undefined)` returns 204 even if Redis is down, leaving the session live server-side.

**Files changed:** `src/core/manager.ts`.

**Fix:** dropped the `.catch` for the stateful path. `SessionError` instances now propagate; everything else is re-wrapped as `STORE_UNAVAILABLE`. Cookie-codec path still no-ops (the cookie expiry IS the logout — there is no server-side state).

---

## 7. [HIGH] Feature inlining vs lifecycle hooks

**Concern:** plan §3.1 promised feature lifecycle hooks; current code inlines `computeDevice` / `enforceConcurrency` / CSRF mirror-cookie write / audit shim into `core/manager.ts`. The 5 KB core budget will be unmeasurable until `size-limit` runs.

**Files changed:** `PLAN.md` §6.1 (architectural caveat).

**Decision:** deferred the refactor; updated the plan to reflect reality. The runtime logic does live in `core/manager.ts` rather than behind `feature.onCreate(...)` impl objects, but the public `SessionFeature` surface is already opaque (`__feature` discriminator only) and the subpath imports DO make the feature config factories tree-shakeable. Moving the runtime onto lifecycle hooks is a substantial refactor that would intersect badly with the deferred-rotate, retry, and CSRF-introspection changes shipped in this PR. The plan now acknowledges the inlining and explicitly marks the budgets as "aspirational targets" until `size-limit` is wired into CI.

---

## 8. [MEDIUM] `update()` retry on lost-update conflict

**Concern:** plan §5.1 calls for "retry once, then throw `CONFLICT`"; current code throws on the first `false` from `store.update`.

**Files changed:** `src/core/manager.ts`.

**Fix:** `update()` now loops up to two attempts. On the first `false`, it re-runs `readActive`, re-applies the mutator, and retries. After the second failure it throws `CONFLICT`. The codec path skips the retry path entirely (cookie codec has no CAS surface — the new sealed cookie supersedes the old).

---

## 9. [MEDIUM] `__codec` exposed on `SessionStore<T>` interface

**Concern:** the field is doc'd `@internal` but it's part of the public interface; third-party adapter authors see it in IntelliSense.

**Files changed:** `src/types/store.ts`, `src/types/config.ts`, `src/types/index.ts`, `src/adapters/cookie/index.ts`, `src/core/manager.ts`, `PLAN.md`.

**Fix:** lifted the codec out of the store interface entirely. New `StatelessCookieCodec<T>` type in `types/store.ts`. New `cookieCodec?: StatelessCookieCodec<T>` slot in `SessionConfig<T>`. New `createCookieCodec(opts)` factory in `@authkit/sessions/adapters/cookie`. The cookie-store stub (`createCookieStore()`) is now genuinely no-op — no secrets, no codec — and the user wires both pieces:

```ts
createSessionManager({
  secrets: [SECRET],
  store: createCookieStore(),
  cookieCodec: createCookieCodec({ secrets: [SECRET] }),
});
```

The manager reads `config.cookieCodec` directly. `SessionStore<T>` is now clean for third-party authors.

---

## 10. [MEDIUM] Adapters read `Date.now()` directly

**Concern:** plan §3.3 calls for `core/time.ts` + `config.clock` plumbing; tests can't fast-forward expiration on any backing store.

**Files changed:** `src/adapters/{memory,redis,upstash,cloudflare-kv,cloudflare-d1,postgres}/index.ts`.

**Fix:** every adapter factory now accepts `clock?: () => number` and defaults it to `nowSeconds` from `core/time.ts`. The wall-clock reads in TTL math, expiry filters, and read-side expiration checks all go through the injected clock.

---

## 11. [MEDIUM] No `session.destroyed` audit on EXPIRED reads

**Concern:** plan §5.4 says structured events fire for every expected failure mode; the manager `store.delete`s the expired record but only emits `session.read.failed`.

**Files changed:** `src/core/manager.ts`.

**Fix:** `readActive` now emits both `session.read.failed { reason: 'EXPIRED' }` and `session.destroyed { reason: 'expired' }` on the expired path, in that order, before the delete.

---

## 12. [MEDIUM] Memory adapter returned the live record reference

**Concern:** anything the caller does to `record.data` mutates the in-memory copy; `readonly` types prevent it at compile time but not at runtime.

**Files changed:** `src/adapters/memory/index.ts`.

**Fix:** added a `cloneRecord` helper using `structuredClone` (with a `JSON.parse(JSON.stringify(...))` fallback for older runtimes — the records we store are JSON-safe by construction). `read()`, `create()`, and `update()` all clone at the boundary. `listByUser` still returns metadata directly (it is read-only on a JSON-deep level since `Device` and `SessionMetadata` are flat).

---

## 13. [MEDIUM] `parseMeta` duplicated across five adapters

**Concern:** five almost-identical implementations, none of them validating `expiresAt` / `csrf` / `v` like `isMeta` in `core/encoder.ts` does. A corrupted blob with a missing `expiresAt` would round-trip and trip the manager later.

**Files changed:** `src/core/encoder.ts` (new `parseMetadataBlob` export), `src/adapters/{redis,upstash,cloudflare-kv,cloudflare-d1,postgres}/index.ts`.

**Fix:** consolidated into one helper that accepts string-or-object input (the postgres `jsonb` driver returns parsed objects; redis returns strings) and runs the same structural validation as `decodeRecord`'s `isMeta` — including `expiresAt`, `createdAt`, `lastSeenAt`, `csrf`, `v`. The five per-adapter `parseMeta` functions are deleted; every call site now goes through `parseMetadataBlob`.

---

## 14. [MEDIUM] Dead `activeSigKey` fallback

**Concern:** `sigKeys[0] ?? deriveSigKey(activeSecret)` is a redundant KDF call only present because of `noUncheckedIndexedAccess`.

**Files changed:** `src/core/manager.ts`.

**Fix:** rewrote as the suggested destructuring pattern: `const [activeSigKey, ...rotatedSigKeys] = [...] as const;`. Single KDF call, no fallback.

---

## 15. [LOW] CSRF cookie/header name validation at construction

**Concern:** `cookieName` is interpolated into `Set-Cookie` and only validated on first request; should fail at `csrf({...})` time so a typo is a boot error.

**Files changed:** `src/features/csrf/index.ts`.

**Fix:** validate both `cookieName` (RFC 6265 token) and `headerName` (RFC 7230 field-name token) at factory time. Bad input throws `SessionError('CONFIG_INVALID', ...)` immediately.

---

## 16. [LOW] Framework adapters use `as` casts for request augmentation

**Concern:** `(req as unknown as Record<string, unknown>)['session'] = ...` violates the plan's "no `as` outside `core/encoder.ts` / `crypto/*`" rule.

**Files changed:** `PLAN.md` (§3.4 architectural rules).

**Decision:** declined the code change; relaxed the plan instead. Framework adapters write onto framework-typed request contexts that the user augments via `declare module` — the cast is the documented escape hatch. Defining a `Record<string, unknown>` decorator on `Object.defineProperty` would carry the same erasure on the type level (we do not own the runtime type) and would make the augmentation harder to introspect for users who don't use `declare module`. The plan's `as` rule now lists `frameworks/*` alongside the existing exemptions.

---

## 17. [LOW] Elysia adapter no-op cast

**Concern:** `session as SessionRecord<T> | null` is redundant; `manager.get` already returns that exact type.

**Files changed:** `src/frameworks/elysia/index.ts`.

**Fix:** removed the cast and the now-unused `SessionRecord` import.

---

## 18. [LOW] Cookie adapter silent concurrency no-op

**Concern:** `listByUser` returns `[]` so concurrency becomes a silent no-op; plan §9.7.2 said the adapter should emit a one-shot warning when concurrency is wired against it.

**Files changed:** `src/core/manager.ts`.

**Fix:** the manager (which is the only place that has both signals — the codec and the concurrency feature) emits a one-shot `console.warn` at construction time when both `cookieCodec` and the concurrency feature are present **and** `isDev()` is true. The warning names the fix.

---

## 19. [LOW] `rotate()` swallowed the old-record delete failure

**Concern:** if `store.create(rotated)` succeeds but `store.delete(record.meta.id)` fails, the user has both records active — bad for concurrency limits and revocation.

**Files changed:** `src/core/manager.ts`.

**Fix:** the `delete` call is now wrapped in `try/catch` and rethrows as `STORE_UNAVAILABLE`. The new attachment is not yet returned to the client at the throw point, so the caller can retry without the user seeing partial state. Audit-event emission still fires (`session.rotated`) on the success path only.

---

## 20. [LOW] Redis `delete` does two round-trips (GET meta → DEL)

**Concern:** could be one EVAL `GET → DEL → SREM`.

**Decision:** declined. The two round-trips are intentional in the current cut so that the index removal can happen even when the client lacks `EVAL` (the `RedisLike` shape's `eval?` is optional). Folding both into a single Lua script would close one round-trip on the modern path but lose the no-Lua fallback the duck-type was designed for. I would revisit when the atomic concurrency Lua lands (§2) — at that point we'll have a hard `EVAL` requirement on Redis anyway and one `delete` script makes sense.

---

## Notes for the test phase

- The new `rotatePending` field on `SessionMetadata` needs round-trip tests through the cookie codec and the JSON metadata blob.
- The `assertCsrfReady` helper has three branches (`enabled` / `opted-out` / throw) that need framework-adapter tests.
- The cookie injection regex guards in `serializeCookie` need positive + negative cases (`evil.com\r\n...`, `Domain=foo;X=Y`, valid TLDs).
- Memory-adapter clone semantics need a "mutate returned data; re-read; verify unchanged" test.
- Clock plumbing needs an "advance the injected clock past `expiresAt` and observe `read()` returning null" test on every adapter.
