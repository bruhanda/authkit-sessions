import { SessionError } from '../errors/base.js';
import type { CookieOptions } from '../types/cookie.js';

/** Default cookie attributes — secure-by-default. */
export const DEFAULT_COOKIE_OPTIONS: Required<Omit<CookieOptions, 'domain'>> = {
  path: '/',
  secure: true,
  httpOnly: true,
  sameSite: 'Lax',
  prefix: false,
  partitioned: false,
};

/** Reserved cookie name characters per RFC 6265. */
const COOKIE_NAME_RE = /^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$/;

/**
 * Compose a `Set-Cookie` header value from a name, value and attribute
 * bag. Hand-rolled to keep the bundle small and to avoid a dependency
 * on the `cookie` npm package, which is CommonJS and not edge-friendly.
 *
 * Enforces the `__Host-` / `__Secure-` invariants documented by Mozilla:
 *   - `__Host-`: requires `Path=/`, `Secure`, and no `Domain=`.
 *   - `__Secure-`: requires `Secure`.
 *
 * @param name     Bare cookie name (without prefix).
 * @param value    Cookie value — must already be URL-safe.
 * @param maxAgeSeconds  `Max-Age` attribute in seconds. `0` means "expire now".
 * @param options  Optional attribute overrides; merged onto defaults.
 * @returns Encoded `Set-Cookie` header value.
 * @throws {SessionError} `CONFIG_INVALID` on invariant violations.
 *
 * @example
 *   serializeCookie('sid', 'abc...', 86400, { sameSite: 'Strict' });
 */
export function serializeCookie(
  name: string,
  value: string,
  maxAgeSeconds: number,
  options: Partial<CookieOptions> = {},
): string {
  if (!COOKIE_NAME_RE.test(name)) {
    throw new SessionError('CONFIG_INVALID', `invalid cookie name: ${JSON.stringify(name)}`);
  }

  const opts = { ...DEFAULT_COOKIE_OPTIONS, ...options };
  const prefix = opts.prefix === false ? '' : opts.prefix;

  if (prefix === '__Host-') {
    if (opts.path !== '/') {
      throw new SessionError('CONFIG_INVALID', '__Host- cookies require Path=/');
    }
    if (!opts.secure) {
      throw new SessionError('CONFIG_INVALID', '__Host- cookies require Secure');
    }
    if (opts.domain !== undefined) {
      throw new SessionError('CONFIG_INVALID', '__Host- cookies must not set Domain');
    }
  } else if (prefix === '__Secure-' && !opts.secure) {
    throw new SessionError('CONFIG_INVALID', '__Secure- cookies require Secure');
  }

  if (opts.sameSite === 'None' && !opts.secure) {
    throw new SessionError('CONFIG_INVALID', 'SameSite=None requires Secure');
  }

  const parts: string[] = [`${prefix}${name}=${value}`];
  parts.push(`Path=${opts.path}`);
  if (opts.domain !== undefined && prefix !== '__Host-') parts.push(`Domain=${opts.domain}`);
  parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`);
  parts.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) parts.push('Secure');
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.partitioned) parts.push('Partitioned');
  return parts.join('; ');
}

/**
 * Parse a `Cookie` header value (or concatenation of values) into a
 * map. The parser is permissive: unknown attribute syntax is ignored,
 * empty values are treated as missing, and duplicate names yield the
 * **first** occurrence (defence against header smuggling where a
 * second cookie overrides a hardened one).
 *
 * @param header  Raw `Cookie:` header value, or `null` for missing.
 * @returns Map of cookie name → value.
 *
 * @example
 *   const cookies = parseCookie(req.headers.get('cookie'));
 *   const sid = cookies.get('sid');
 */
export function parseCookie(header: string | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  const pairs = header.split(/;\s*/);
  for (const pair of pairs) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name || out.has(name)) continue;
    out.set(name, value);
  }
  return out;
}

/**
 * Compute the prefixed cookie name actually written to the browser.
 * `'sid'` + `__Host-` becomes `'__Host-sid'`.
 *
 * @param name      Bare cookie name.
 * @param options   Cookie attribute bag (only `prefix` is consulted).
 * @returns Effective cookie name.
 *
 * @example
 *   prefixedName('sid', { prefix: '__Host-' }); // '__Host-sid'
 */
export function prefixedName(name: string, options: Partial<CookieOptions> = {}): string {
  const prefix = options.prefix === false || options.prefix === undefined ? '' : options.prefix;
  return `${prefix}${name}`;
}
