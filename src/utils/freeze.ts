/**
 * Recursively freeze a value and every nested plain object / array.
 *
 * Used by `createSessionManager` to harden the returned handle so consumers
 * cannot mutate config at runtime. Cycles are tolerated via a visited set —
 * the function does not recurse into already-frozen objects.
 *
 * Non-plain objects (`Map`, `Set`, `Headers`, class instances, Uint8Array)
 * are passed through unchanged: freezing them would either no-op or break
 * their internal mutators.
 *
 * @typeParam T  Inferred from the argument; the return type matches.
 * @param value  Value to freeze. Returned as-is when not a plain object/array.
 * @returns The same reference, deeply frozen.
 *
 * @example
 *   const cfg = deepFreeze({ secrets: ['s'], cookie: { secure: true } });
 *   cfg.cookie.secure = false; // throws in strict mode
 */
export function deepFreeze<T>(value: T): T {
  freezeRecursive(value, new WeakSet<object>());
  return value;
}

function freezeRecursive(value: unknown, seen: WeakSet<object>): void {
  if (value === null || typeof value !== 'object') return;
  if (seen.has(value as object)) return;

  const proto = Object.getPrototypeOf(value);
  const isPlain = proto === Object.prototype || proto === null || Array.isArray(value);
  if (!isPlain) return;

  seen.add(value as object);
  Object.freeze(value);
  for (const key of Object.getOwnPropertyNames(value)) {
    freezeRecursive((value as Record<string, unknown>)[key], seen);
  }
}
