/**
 * Wrapper around `crypto.getRandomValues` that returns a fresh
 * `Uint8Array`. The Web Crypto API is the only sync-mandated random
 * source available across every supported runtime — `globalThis.crypto`
 * exists in Node 20+, Bun, Deno, Cloudflare Workers and Vercel Edge.
 *
 * @param length  Number of bytes to generate.
 * @returns A fresh `Uint8Array` filled with cryptographically strong randomness.
 *
 * @example
 *   const nonce = randomBytes(12); // AES-GCM nonce
 */
export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}
