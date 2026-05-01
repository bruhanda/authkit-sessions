/**
 * Configuration for the `csrf` feature (double-submit cookie pattern).
 *
 * Methods are constrained to a literal union so a typo (`'POSTT'`) is a
 * compile-time error — the "safe methods MUST stay safe" invariant is
 * enforceable at the type level instead of a runtime warning.
 *
 * @see `@authkit/sessions/csrf` for the factory.
 */
export interface CsrfConfig {
  /** Cookie name for the mirror token. Default `'csrf'`. */
  cookieName?: string;
  /** Header name expected to mirror the cookie value. Default `'x-csrf-token'`. */
  headerName?: string;
  /** Methods to enforce on. Default `['POST','PUT','PATCH','DELETE']`. */
  protectedMethods?: readonly ('POST' | 'PUT' | 'PATCH' | 'DELETE')[];
  /**
   * When `true` (default), additionally verify `Origin` (or `Referer`)
   * matches the request `Host` for protected methods. Provides a second
   * layer for browsers that mishandle `SameSite`.
   */
  enforceOrigin?: boolean;
}
