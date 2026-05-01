/**
 * Single portable runtime probe for "are we in a development environment".
 *
 * Centralised here because `process` may be undefined on Cloudflare Workers
 * and Deno (without `--allow-env`); inlining the check elsewhere risks a
 * `ReferenceError` at module load time. Every other module that needs the
 * answer imports this function rather than touching `globalThis.process`.
 *
 * @returns `true` when `process.env.NODE_ENV !== 'production'` is observable;
 *          `false` in any runtime where `process` is unavailable or the
 *          variable is set to `'production'`.
 *
 * @example
 *   import { isDev } from './env.js';
 *   if (isDev()) {
 *     // dev-only diagnostics
 *   }
 */
export function isDev(): boolean {
  return (
    typeof process !== 'undefined' &&
    typeof process.env !== 'undefined' &&
    process.env['NODE_ENV'] !== 'production'
  );
}
