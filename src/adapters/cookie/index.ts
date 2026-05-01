import { coerceSecret, deriveEncKey, validateSecret } from '../../crypto/kdf.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionRecord } from '../../types/session.js';
import type { SessionStore, StatelessCookieCodec } from '../../types/store.js';
import { DEFAULT_COOKIE_MAX_BYTES, guardCookieSize } from './compact.js';
import { openRecord, sealRecord } from './seal.js';

/**
 * Construct the stateless cookie codec — the AEAD seal/open pair that
 * makes the manager carry the entire `SessionRecord` inside the
 * session cookie. Pair with `createCookieStore` (a no-op stub used as
 * `SessionConfig.store`).
 *
 * @typeParam T  Session payload shape.
 * @param opts.secrets  One or more secrets ≥256 bits each. The first
 *                      is the active sealing key; the rest verify
 *                      old cookies during rotation.
 * @param opts.maxBytes Hard ceiling on encoded cookie length. Default 3072.
 * @returns A `StatelessCookieCodec<T>` to assign to `SessionConfig.cookieCodec`.
 * @throws {SessionError} `SECRET_TOO_SHORT` for a secret <256 bits.
 *
 * @example
 *   import { createCookieCodec, createCookieStore } from '@authkit/sessions/adapters/cookie';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createCookieStore(),
 *     cookieCodec: createCookieCodec({ secrets: [SECRET] }),
 *   });
 */
export function createCookieCodec<T extends SessionData = SessionData>(opts: {
  secrets: string | Uint8Array | readonly (string | Uint8Array)[];
  maxBytes?: number;
}): StatelessCookieCodec<T> {
  const list: readonly (string | Uint8Array)[] =
    typeof opts.secrets === 'string' || opts.secrets instanceof Uint8Array
      ? [opts.secrets]
      : opts.secrets;
  const keys = list.map((s) => {
    const bytes = coerceSecret(s);
    validateSecret(bytes);
    return deriveEncKey(bytes);
  });
  const [activeKey, ...otherKeys] = keys;
  if (!activeKey) {
    throw new SessionError('CONFIG_INVALID', 'cookie codec requires at least one secret');
  }
  const maxBytes = opts.maxBytes ?? DEFAULT_COOKIE_MAX_BYTES;
  return {
    encode(record: SessionRecord<T>): string {
      const value = sealRecord(record, activeKey);
      guardCookieSize(value, maxBytes);
      return value;
    },
    decode(value: string): SessionRecord<T> | null {
      return openRecord<T>(value, [activeKey, ...otherKeys]);
    },
  };
}

/**
 * Construct the no-op stub store the manager pairs with `cookieCodec`
 * for the stateless cookie path. The cookie envelope IS the storage:
 *   - `read` always returns `null` (the manager goes through the codec).
 *   - Mutating ops are no-ops.
 *   - `listByUser` returns `[]` — no cross-device index is possible —
 *     so `concurrency` becomes a no-op against this adapter (the
 *     manager emits a one-shot dev warning when both are wired).
 *
 * @typeParam T  Session payload shape.
 * @returns A no-op `SessionStore<T>`.
 *
 * @example
 *   import { createCookieStore, createCookieCodec } from '@authkit/sessions/adapters/cookie';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createCookieStore(),
 *     cookieCodec: createCookieCodec({ secrets: [SECRET] }),
 *   });
 */
export function createCookieStore<T extends SessionData = SessionData>(): SessionStore<T> {
  return {
    async create() {
      // No-op — the cookie envelope IS the storage.
    },
    async read() {
      return null;
    },
    async update() {
      return true;
    },
    async delete() {
      return true;
    },
    async listByUser() {
      return [];
    },
    async deleteByUser() {
      return 0;
    },
  };
}
