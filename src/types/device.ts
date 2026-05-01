/**
 * A device entry attached to a session. Hashes (`hash`, `ip`) are HMAC
 * digests — never raw values — so listing a user's active devices via
 * `listByUser` cannot leak the raw fingerprint inputs.
 */
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

/**
 * Configuration for the `fingerprint` feature.
 *
 * @see `@authkit/sessions/fingerprint` for the factory.
 */
export interface FingerprintConfig {
  /**
   * Components included in the fingerprint hash. **Default**:
   * `['user-agent', 'accept-language', 'sec-ch-ua']`. Adding `'ip'` raises
   * entropy substantially at the cost of mobile-roam churn — pair it with
   * `onMismatch: 'rotate'` (the default) to avoid kicking legitimate
   * users on carrier IP changes.
   */
  include?: readonly ('user-agent' | 'accept-language' | 'ip' | 'sec-ch-ua')[];
  /**
   * IP extractor — required if `'ip'` is in `include`. Defaults to the
   * first hop in `X-Forwarded-For`, falling back to `CF-Connecting-IP`
   * (Cloudflare), then `True-Client-IP` (Akamai). Return `undefined` to
   * skip — never throws.
   */
  ip?: (req: Request) => string | undefined;
  /**
   * On mismatch:
   *   - `'rotate'` (default) — keep data, regenerate id + CSRF.
   *   - `'destroy'`           — wipe the session entirely.
   *   - `'ignore'`            — log + accept (warm-up / dev only).
   */
  onMismatch?: 'rotate' | 'destroy' | 'ignore';
}
