/**
 * Cookie attributes applied to every `Set-Cookie` minted by the manager.
 * Defaults follow the OWASP cookie hardening guide: `Secure`, `HttpOnly`,
 * `SameSite=Lax`, `Path=/`. The `__Host-` prefix is the most secure choice
 * for SPAs; `__Secure-` is a weaker variant.
 */
export interface CookieOptions {
  /** `Path=` attribute. Default `'/'`. */
  path?: string;
  /** `Domain=` attribute. No default — leave undefined for host-only. */
  domain?: string;
  /** `Secure` attribute. Default `true`. */
  secure?: boolean;
  /** `HttpOnly` attribute. Default `true`. Disable only if you genuinely need JS read access. */
  httpOnly?: boolean;
  /** `SameSite` attribute. Default `'Lax'` (compatible with top-level OAuth redirects). */
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
