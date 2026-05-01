import { SESSION_ERROR_CODES, type SessionErrorCode } from './codes.js';

/**
 * Single error class thrown by every public surface in `@authkit/sessions`.
 *
 * Carries a machine-readable `code` (stable across versions, see
 * `SESSION_ERROR_CODES`) and an original `cause` when wrapping store /
 * crypto / framework errors. The `name` is fixed to `'SessionError'` so
 * `SessionError.is(value)` works across realm boundaries (Workers ↔
 * Durable Objects) where `instanceof` cannot be relied on.
 *
 * Error messages NEVER contain user-controlled values — no session ids,
 * no secrets, no cookie payload. Anything dynamic ends up in `cause` for
 * server-side debugging only.
 *
 * @example
 *   try {
 *     await sessions.update(req, fn);
 *   } catch (err) {
 *     if (SessionError.is(err) && err.code === 'NOT_FOUND') {
 *       return new Response('no session', { status: 401 });
 *     }
 *     throw err;
 *   }
 */
export class SessionError extends Error {
  override readonly name = 'SessionError';
  readonly code: SessionErrorCode;
  override readonly cause?: unknown;
  /** Safe-to-log message. Never contains secrets or user input. */
  readonly publicMessage: string;

  /**
   * @param code     Stable error code from `SESSION_ERROR_CODES`.
   * @param message  Human-readable, log-safe message.
   * @param cause    Original error when wrapping infrastructure failures.
   */
  constructor(code: SessionErrorCode, message: string, cause?: unknown) {
    super(message);
    this.code = code;
    this.publicMessage = message;
    if (cause !== undefined) this.cause = cause;
  }

  /**
   * Type guard usable across realm boundaries (e.g. Cloudflare Durable
   * Object ↔ Worker, where `instanceof` returns `false` because `Error`
   * is a different constructor in each realm).
   *
   * @param value  Anything thrown.
   * @returns `true` iff `value` looks structurally like a `SessionError`.
   *
   * @example
   *   if (SessionError.is(err)) {
   *     console.error(err.code, err.publicMessage);
   *   }
   */
  static is(value: unknown): value is SessionError {
    if (value === null || typeof value !== 'object') return false;
    const v = value as { name?: unknown; code?: unknown };
    return (
      v.name === 'SessionError' &&
      typeof v.code === 'string' &&
      (SESSION_ERROR_CODES as readonly string[]).includes(v.code)
    );
  }
}
