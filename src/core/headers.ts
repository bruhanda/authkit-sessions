import { parseCookie } from './cookie.js';

/**
 * The single file that touches `Request` / `Headers`. Every other module
 * receives already-parsed cookie maps so `Request` is not a hard
 * dependency anywhere else in the engine.
 */

/**
 * Extract a named cookie from a request.
 *
 * @param req   Standard `Request`.
 * @param name  Effective cookie name (already prefixed).
 * @returns Cookie value, or `undefined` when missing.
 *
 * @example
 *   const sid = extractCookie(req, '__Host-sid');
 */
export function extractCookie(req: Request, name: string): string | undefined {
  const cookies = parseCookie(req.headers.get('cookie'));
  return cookies.get(name);
}

/**
 * Extract every cookie from a request.
 *
 * @param req  Standard `Request`.
 * @returns Map of cookie name → value (first occurrence wins).
 *
 * @example
 *   const cookies = extractCookies(req);
 *   for (const [name, value] of cookies) { ... }
 */
export function extractCookies(req: Request): Map<string, string> {
  return parseCookie(req.headers.get('cookie'));
}

/**
 * Append a `Set-Cookie` to a `Headers` object without clobbering
 * existing entries. Returns the same `Headers` so callers can chain.
 *
 * @param headers  Target headers.
 * @param value    Pre-formatted `Set-Cookie` value (from `serializeCookie`).
 * @returns The `headers` argument (same reference).
 *
 * @example
 *   appendSetCookie(response.headers, serializeCookie('sid', sid, 86400));
 */
export function appendSetCookie(headers: Headers, value: string): Headers {
  headers.append('Set-Cookie', value);
  return headers;
}
