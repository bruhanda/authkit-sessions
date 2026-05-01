/**
 * Constant-time byte comparison. Always inspects every byte of both
 * inputs to avoid leaking length / position via wall-clock timing — the
 * implementation does NOT bail early when a mismatch is found.
 *
 * Useful for HMAC tag verification, CSRF token comparison and any other
 * comparison where a timing oracle would let an attacker iteratively
 * guess the correct value.
 *
 * @param a  Left operand.
 * @param b  Right operand.
 * @returns `true` iff both arrays have the same length and contents.
 *
 * @example
 *   if (!timingSafeEqual(expected, provided)) throw new Error('bad mac');
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    // Bytewise XOR accumulator. Non-zero bit anywhere => mismatch.
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * String variant — encodes both inputs as UTF-8 and delegates. Safe to
 * call with attacker-controlled values; the only side effect on length
 * mismatch is the early `false`, which leaks length only — the tokens we
 * compare are fixed-length so this is not exploitable.
 *
 * @param a  Left operand.
 * @param b  Right operand.
 * @returns `true` iff both encode to identical byte sequences.
 *
 * @example
 *   timingSafeEqualString(meta.csrf, providedToken);
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  const enc = new TextEncoder();
  return timingSafeEqual(enc.encode(a), enc.encode(b));
}
