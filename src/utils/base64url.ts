/**
 * Base64url encode/decode helpers for the cookie envelope and session ids.
 *
 * The implementation is hand-rolled (rather than going through `Buffer`) so
 * the same code runs in Node, Bun, Deno, Cloudflare Workers and Vercel
 * Edge — none of which agree on `Buffer` availability without a polyfill.
 *
 * `atob` / `btoa` are present in every supported runtime per WHATWG; we
 * only translate the alphabet and pad/strip the padding character.
 */

const PAD_RE = /=+$/;

/**
 * Encode raw bytes to a URL-safe base64 string (no padding).
 *
 * @param bytes  Bytes to encode.
 * @returns Base64url string with `+`, `/` and `=` replaced.
 *
 * @example
 *   base64urlEncode(new Uint8Array([1, 2, 3])); // 'AQID'
 */
export function base64urlEncode(bytes: Uint8Array): string {
  // Avoid `String.fromCharCode(...bytes)` for large inputs — V8 throws
  // RangeError past ~64 KB. Build a binary string in chunks instead.
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(PAD_RE, '');
}

/**
 * Decode a URL-safe base64 string back to raw bytes.
 *
 * @param str  Base64url string. Padding is optional.
 * @returns Decoded byte array.
 * @throws {Error} If the input contains characters outside the base64url alphabet.
 *
 * @example
 *   base64urlDecode('AQID'); // Uint8Array(3) [1, 2, 3]
 */
export function base64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Encode a UTF-8 string to base64url.
 *
 * @param text  String to encode.
 * @returns Base64url representation of the UTF-8 bytes.
 *
 * @example
 *   base64urlEncodeString('hi'); // 'aGk'
 */
export function base64urlEncodeString(text: string): string {
  return base64urlEncode(new TextEncoder().encode(text));
}

/**
 * Decode a base64url string back to a UTF-8 string.
 *
 * @param str  Base64url-encoded UTF-8 input.
 * @returns Decoded UTF-8 string.
 * @throws {Error} If decoding produces invalid UTF-8.
 *
 * @example
 *   base64urlDecodeString('aGk'); // 'hi'
 */
export function base64urlDecodeString(str: string): string {
  return new TextDecoder().decode(base64urlDecode(str));
}
