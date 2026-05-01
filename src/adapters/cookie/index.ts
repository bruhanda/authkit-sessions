import { coerceSecret, deriveEncKey, validateSecret } from '../../crypto/kdf.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionRecord } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';
import { DEFAULT_COOKIE_MAX_BYTES, guardCookieSize } from './compact.js';
import { openRecord, sealRecord } from './seal.js';

/**
 * Create a stateless, encrypted-cookie session store.
 *
 * The cookie carries the entire AEAD-sealed `SessionRecord` — there is
 * no server-side database. Best fit for stateless serverless functions
 * where you accept that:
 *   - Server-side instant `revoke` is impossible (the cookie itself is
 *     the source of truth — only `signOut()` from the same browser can
 *     drop it). For revocation needs, pair with a stateful store.
 *   - `listByUser` returns `[]` (no cross-device index possible) — so
 *     `concurrency` becomes a no-op against this adapter.
 *   - The encoded payload must fit under `maxBytes` (default 3072) —
 *     browsers reject larger cookies. Throws `PAYLOAD_TOO_LARGE` when
 *     exceeded; never silently truncates.
 *
 * Secrets are passed in directly (rather than reused from
 * `SessionConfig.secrets`) because the store must derive its own AEAD
 * key from them; the manager does not share derived keys with stores.
 *
 * @typeParam T  Session payload shape.
 * @param secrets  One or more secrets ≥256 bits each. The first is the
 *                 active sealing key; the rest are accepted on read for
 *                 zero-downtime rotation.
 * @param opts.maxBytes  Hard ceiling on encoded cookie length. Default 3072.
 * @returns A `SessionStore` whose `__codec` triggers the manager's
 *          stateless cookie path.
 * @throws {SessionError} `SECRET_TOO_SHORT` when any secret carries
 *                        <256 bits of entropy.
 *
 * @example
 *   import { createCookieStore } from '@authkit/sessions/adapters/cookie';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createCookieStore({ secrets: [SECRET] }),
 *   });
 */
export function createCookieStore<T extends SessionData = SessionData>(opts: {
  secrets: string | Uint8Array | readonly (string | Uint8Array)[];
  maxBytes?: number;
}): SessionStore<T> {
  const list: readonly (string | Uint8Array)[] =
    typeof opts.secrets === 'string' || opts.secrets instanceof Uint8Array
      ? [opts.secrets]
      : opts.secrets;
  const keys = list.map((s) => {
    const bytes = coerceSecret(s);
    validateSecret(bytes);
    return deriveEncKey(bytes);
  });
  if (keys.length === 0) {
    throw new SessionError('CONFIG_INVALID', 'cookie store requires at least one secret');
  }
  const [activeKey, ...otherKeys] = keys;
  if (!activeKey) {
    throw new SessionError('CONFIG_INVALID', 'cookie store requires at least one secret');
  }
  const maxBytes = opts.maxBytes ?? DEFAULT_COOKIE_MAX_BYTES;

  return {
    async create() {
      // No-op — the cookie envelope IS the storage.
    },
    async read() {
      // The manager materializes records via `__codec.decode` and
      // never calls `read()` for cookie-store cookies.
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
    __codec: {
      encode(record: SessionRecord<T>): string {
        const value = sealRecord(record, activeKey);
        guardCookieSize(value, maxBytes);
        return value;
      },
      decode(value: string): SessionRecord<T> | null {
        return openRecord<T>(value, [activeKey, ...otherKeys]);
      },
    },
  };
}
