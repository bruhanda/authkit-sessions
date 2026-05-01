import { decodeRecord, encodeRecord, parseMetadataBlob } from '../../core/encoder.js';
import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

const DEFAULT_KEY_PREFIX = 'sess:';
const META_PREFIX = 'meta:';

/**
 * Create a Cloudflare KV-backed session store.
 *
 * KV is **eventually consistent** — reads after a `delete()` may return
 * the deleted record for up to 60 s globally. The adapter therefore
 * documents "best-effort instant revoke + bounded staleness ≤60 s
 * globally", not "immediate revoke". For deployments needing genuine
 * instant revoke, use `createDurableObjectStore` instead, or pair KV
 * for hot-path reads with a DO consulted on every privileged action.
 *
 * `concurrency` and `listByUser` require an optional companion KV
 * namespace passed via `opts.userIndex`; without it, `listByUser`
 * returns `[]` and `concurrency` becomes a no-op. The companion
 * namespace stores comma-separated session-id lists keyed by user id.
 *
 * @typeParam T  Session payload shape.
 * @param kv               Bound KV namespace.
 * @param opts.userIndex   Companion KV namespace for the user → session-ids map.
 *                         Required for `concurrency` / `listByUser`.
 * @param opts.keyPrefix   Override for the session-record namespace. Default `'sess:'`.
 * @returns A `SessionStore` backed by Cloudflare KV.
 *
 * @example
 *   import { createKVStore } from '@authkit/sessions/adapters/cloudflare-kv';
 *   const sessions = createSessionManager({
 *     secrets: [env.SESSION_SECRET],
 *     store: createKVStore(env.SESSION_KV, { userIndex: env.SESSION_USER_INDEX }),
 *   });
 */
export function createKVStore<T extends SessionData = SessionData>(
  kv: KVNamespace,
  opts: { userIndex?: KVNamespace; keyPrefix?: string; clock?: () => number } = {},
): SessionStore<T> {
  const keyPrefix = opts.keyPrefix ?? DEFAULT_KEY_PREFIX;
  const userIndex = opts.userIndex;
  const clock = opts.clock ?? nowSeconds;
  const recordKey = (id: string): string => `${keyPrefix}${id}`;
  const metaKey = (id: string): string => `${keyPrefix}${META_PREFIX}${id}`;
  const userKey = (userId: string): string => `user:${userId}`;

  const ttlFor = (meta: SessionMetadata): number => Math.max(60, meta.expiresAt - clock());

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      throw new SessionError('STORE_UNAVAILABLE', `kv ${op} failed`, err);
    }
  };

  const readUserList = async (userId: string): Promise<string[]> => {
    if (!userIndex) return [];
    const raw = await userIndex.get(userKey(userId));
    if (!raw) return [];
    return raw.split(',').filter(Boolean);
  };

  const writeUserList = async (userId: string, ids: string[], ttl: number): Promise<void> => {
    if (!userIndex) return;
    if (ids.length === 0) {
      await userIndex.delete(userKey(userId));
      return;
    }
    await userIndex.put(userKey(userId), ids.join(','), { expirationTtl: ttl });
  };

  return {
    async create(record) {
      await wrap(async () => {
        const exists = await kv.get(recordKey(record.meta.id));
        if (exists !== null) throw new SessionError('CONFLICT', 'session id collision');
        const ttl = ttlFor(record.meta);
        await kv.put(recordKey(record.meta.id), encodeRecord(record), { expirationTtl: ttl });
        await kv.put(metaKey(record.meta.id), JSON.stringify(record.meta), { expirationTtl: ttl });
        if (record.meta.userId !== undefined && userIndex) {
          const ids = await readUserList(record.meta.userId);
          if (!ids.includes(record.meta.id)) ids.push(record.meta.id);
          await writeUserList(record.meta.userId, ids, ttl);
        }
      }, 'create');
    },

    async read(id) {
      return wrap(async () => {
        const blob = await kv.get(recordKey(id));
        if (blob === null) return null;
        return decodeRecord<T>(blob);
      }, 'read');
    },

    async update(record) {
      return wrap(async () => {
        const existing = await kv.get(recordKey(record.meta.id));
        if (existing === null) return false;
        const ttl = ttlFor(record.meta);
        await kv.put(recordKey(record.meta.id), encodeRecord(record), { expirationTtl: ttl });
        await kv.put(metaKey(record.meta.id), JSON.stringify(record.meta), { expirationTtl: ttl });
        return true;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const metaBlob = await kv.get(metaKey(id));
        await Promise.all([kv.delete(recordKey(id)), kv.delete(metaKey(id))]);
        if (metaBlob && userIndex) {
          const meta = parseMetadataBlob(metaBlob);
          if (meta?.userId !== undefined) {
            const ids = (await readUserList(meta.userId)).filter((x) => x !== id);
            await writeUserList(meta.userId, ids, 60);
          }
        }
        return metaBlob !== null;
      }, 'delete');
    },

    async listByUser(userId) {
      if (!userIndex) return [];
      return wrap(async () => {
        const ids = await readUserList(userId);
        const out: SessionMetadata[] = [];
        for (const id of ids) {
          const blob = await kv.get(metaKey(id));
          if (!blob) continue;
          const meta = parseMetadataBlob(blob);
          if (meta) out.push(meta);
        }
        return out;
      }, 'listByUser');
    },

    async deleteByUser(userId) {
      if (!userIndex) return 0;
      return wrap(async () => {
        const ids = await readUserList(userId);
        if (ids.length === 0) return 0;
        await Promise.all(
          ids.flatMap((id) => [kv.delete(recordKey(id)), kv.delete(metaKey(id))]),
        );
        await userIndex.delete(userKey(userId));
        return ids.length;
      }, 'deleteByUser');
    },
  };
}

