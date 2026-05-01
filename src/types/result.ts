import type { SessionError } from '../errors/base.js';

/**
 * Sum type for non-throwing operations that need to distinguish "missing"
 * from "store unavailable". Mostly used internally; the public surface
 * prefers `T | null` for "no session".
 *
 * @typeParam T  Successful payload type.
 * @typeParam E  Error type. Defaults to `SessionError`.
 *
 * @example
 *   const r: Result<number> = { ok: true, value: 42 };
 *   if (r.ok) console.log(r.value); else console.error(r.error.code);
 */
export type Result<T, E = SessionError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
