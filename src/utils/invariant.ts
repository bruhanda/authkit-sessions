import { SessionError } from '../errors/base.js';
import type { SessionErrorCode } from '../errors/codes.js';

/**
 * Assert a runtime invariant. Throws a `SessionError` with the supplied
 * code + message when `cond` is falsy. Compresses the common
 * `if (!cond) throw new SessionError(...)` pattern into one expression and
 * lets TypeScript narrow the asserted condition through `asserts cond`.
 *
 * @param cond     Condition to verify.
 * @param code     Stable session error code.
 * @param message  Human-readable, log-safe message.
 * @throws {SessionError} When `cond` is falsy.
 *
 * @example
 *   invariant(secret.length >= 32, 'SECRET_TOO_SHORT', 'secret < 256 bits of entropy');
 */
export function invariant(cond: unknown, code: SessionErrorCode, message: string): asserts cond {
  if (!cond) throw new SessionError(code, message);
}
