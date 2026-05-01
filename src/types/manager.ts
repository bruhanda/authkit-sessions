import type { Device } from './device.js';
import type { SessionData, SessionMetadata, SessionRecord } from './session.js';

/**
 * The result of any mutating operation. Two ways to consume it, both
 * idiomatic for the Web Standards `Request`/`Response` ecosystem:
 *
 *   1. `headers` — a fresh `Headers` with the `Set-Cookie` already
 *      appended. Pass directly to `new Response(body, { headers })`.
 *      The CSRF feature, when enabled, appends its mirror cookie into
 *      the same `Headers` so a single object carries everything.
 *   2. `cookie` — the raw `Set-Cookie` string. Drop into a framework's
 *      typed cookie store (`event.cookies.set(...)`,
 *      `c.header('set-cookie', ...)`) when the framework owns header
 *      composition.
 *
 * `attachTo(headers)` appends every `Set-Cookie` this attachment carries
 * into a caller-provided `Headers` without clobbering existing entries.
 */
export interface SessionAttachment<T extends SessionData | null> {
  readonly record: T extends null ? null : SessionRecord<NonNullable<T>>;
  readonly cookie: string;
  readonly headers: Headers;
  readonly attachTo: (headers: Headers) => Headers;
}

/**
 * Public manager surface. Returned by `createSessionManager` and frozen.
 *
 * Read paths (`get`, `getCsrfToken`, `verifyCsrf`) NEVER throw on
 * user-controlled inputs (missing/expired/tampered cookies); they return
 * `null`/`false` and emit a single audit event. Mutating paths throw on
 * programmer errors and infrastructure failures.
 *
 * @typeParam T  Shape of the session payload, propagated end-to-end.
 */
export interface SessionManager<T extends SessionData = SessionData> {
  /**
   * Read the session bound to `req`. Never throws on missing/expired/
   * tampered cookies.
   *
   * @param req  Standard `Request`.
   * @returns The full record, or `null` when no valid session is present.
   * @throws {SessionError} `STORE_UNAVAILABLE` if the backing store fails.
   *
   * @example
   *   const session = await sessions.get(req);
   *   if (!session) return new Response('unauthorized', { status: 401 });
   */
  get(req: Request): Promise<SessionRecord<T> | null>;

  /**
   * Create a new session. Returns the record and a `Headers` pre-filled
   * with the `Set-Cookie`. The `userId` is extracted from `data` via
   * `config.getUserId`; the caller never passes it twice.
   *
   * @param req   Originating `Request` — used to capture device fingerprint
   *              and to honour same-`Headers` composition.
   * @param data  Initial session payload.
   * @param opts  Optional capture overrides (e.g. supply a partial Device).
   * @returns Attachment carrying the new record and `Set-Cookie`.
   * @throws {SessionError} `CONCURRENCY_DENIED` when `concurrency: deny-new` rejects,
   *                        `CONFLICT` for an id collision (re-tried once),
   *                        `STORE_UNAVAILABLE` for infrastructure errors.
   *
   * @example
   *   const { record, headers } = await sessions.create(req, { userId, role: 'user' });
   *   return new Response(JSON.stringify(record.data), { status: 201, headers });
   */
  create(
    req: Request,
    data: T,
    opts?: { device?: Partial<Device> },
  ): Promise<SessionAttachment<T>>;

  /**
   * Mutate the active session by replacing its `data`. The mutator
   * receives the current data and returns the next; partial writes are
   * not supported because they complicate type inference for `T`.
   *
   * @param req      Originating `Request`.
   * @param mutator  Pure function returning the new payload.
   * @returns Attachment carrying the updated record.
   * @throws {SessionError} `NOT_FOUND` when there is no active session,
   *                        `CONFLICT` when CAS detects a lost-update race.
   *
   * @example
   *   await sessions.update(req, (data) => ({ ...data, lastAction: 'view' }));
   */
  update(
    req: Request,
    mutator: (data: T) => T | Promise<T>,
  ): Promise<SessionAttachment<T>>;

  /**
   * Rotate the session id while keeping the data. Defence-in-depth
   * against fixation attacks — call after privilege changes (login,
   * password change, MFA upgrade). The CSRF token is rotated alongside
   * the id.
   *
   * @param req  Originating `Request`.
   * @returns Attachment carrying a fresh `Set-Cookie` and a new `meta.id`.
   * @throws {SessionError} `NOT_FOUND` when there is no active session.
   *
   * @example
   *   const { headers } = await sessions.rotate(req);
   *   return new Response(null, { status: 204, headers });
   */
  rotate(req: Request): Promise<SessionAttachment<T>>;

  /**
   * End the active session for the current request and return an
   * expiring `Set-Cookie` so the browser drops its copy. Idempotent.
   *
   * @param req  Originating `Request`.
   * @returns Attachment with `record: null` and an expiring cookie.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   *
   * @example
   *   const { headers } = await sessions.signOut(req);
   *   return new Response(null, { status: 204, headers });
   */
  signOut(req: Request): Promise<SessionAttachment<null>>;

  /**
   * Revoke a single session by id. Does not require a `Request` — typically
   * called from background jobs / RPC handlers.
   *
   * @param id  Opaque session id.
   * @returns `true` iff a session was removed.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  revokeBySessionId(id: string): Promise<boolean>;

  /**
   * Revoke every session for a user — "log out everywhere".
   *
   * @param userId  User identifier returned by `getUserId(data)`.
   * @returns Number of sessions removed.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  revokeByUser(userId: string): Promise<number>;

  /**
   * List a user's active sessions for an "active devices" UI.
   *
   * @param userId  User identifier.
   * @returns Read-only metadata array, freshest first.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  listByUser(userId: string): Promise<readonly SessionMetadata[]>;

  /**
   * Verify a CSRF token against the active session (double-submit
   * pattern). Returns `false` for any failure mode — missing session,
   * missing token, mismatch, expired session.
   *
   * @param req    Originating `Request`.
   * @param token  Value the client posted in the configured header / form field.
   * @returns `true` iff the token matches the active session's `meta.csrf`.
   *
   * @example
   *   const ok = await sessions.verifyCsrf(req, req.headers.get('x-csrf-token') ?? '');
   *   if (!ok) return new Response('csrf', { status: 403 });
   */
  verifyCsrf(req: Request, token: string): Promise<boolean>;

  /**
   * Read the active CSRF token without mutating the session — used to
   * render it into a form / inject into a meta tag.
   *
   * @param req  Originating `Request`.
   * @returns The token, or `null` when no active session.
   *
   * @example
   *   const token = await sessions.getCsrfToken(req);
   */
  getCsrfToken(req: Request): Promise<string | null>;

  /**
   * Set of feature names enabled on this manager (e.g. `'csrf'`,
   * `'fingerprint'`). Framework adapters use this to refuse to start
   * when a security-relevant feature was forgotten — see the
   * `csrf-default-on` invariant they enforce. Internal: do not rely
   * on the membership semantics for anything other than introspection.
   *
   * @internal
   */
  readonly __features: ReadonlySet<'audit' | 'csrf' | 'fingerprint' | 'concurrency'>;

  /**
   * `true` iff the user passed `csrf: false` in the config — i.e.
   * explicitly opted out of CSRF rather than forgetting to wire it.
   * Framework adapters consult this to decide between "fail at boot"
   * (forgot) and "skip enforcement" (opted out).
   *
   * @internal
   */
  readonly __csrfOptedOut: boolean;
}
