/**
 * Default clock — Unix seconds. Every other module reads time through
 * this function (or the user-supplied `config.clock`) so tests can
 * fast-forward through expiration without fake-timer machinery.
 *
 * @returns Current Unix timestamp in seconds.
 *
 * @example
 *   const now = nowSeconds();
 */
export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
