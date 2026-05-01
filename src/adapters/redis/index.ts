import { decodeRecord, encodeRecord, parseMetadataBlob } from '../../core/encoder.js';
import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';
import type { RedisLike } from './client.js';
import { ADD_TO_USER_INDEX, REMOVE_FROM_USER_INDEX } from './lua.js';

const DEFAULT_KEY_PREFIX = 'sess:';
const DEFAULT_USER_INDEX_PREFIX = 'sess:user:';
const META_PREFIX = 'meta:';

/**
 * Create a Redis-backed session store.
 *
 * Storage layout:
 *   - `sess:<id>`       → encoded `SessionRecord` (JSON+base64url envelope)
 *   - `meta:<id>`       → encoded `SessionMetadata` (used for `listByUser`)
 *   - `sess:user:<uid>` → SET of session ids belonging to `uid`
 *
 * TTL is honoured natively via `SET ... EX`; the store never extends
 * TTL on read — sliding expiration is the manager's responsibility.
 *
 * @typeParam T  Session payload shape.
 * @param client  Any Redis-compatible client implementing `RedisLike`.
 *                ioredis, node-redis 4+, and the Bun-native client all
 *                satisfy the duck type.
 * @param opts.keyPrefix       Override for the session-record namespace.
 *                              Default `'sess:'`.
 * @param opts.userIndexPrefix Override for the user-index namespace.
 *                              Default `'sess:user:'`.
 * @returns A `SessionStore` backed by Redis.
 *
 * @example
 *   import { createRedisStore } from '@authkit/sessions/adapters/redis';
 *   import Redis from 'ioredis';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createRedisStore(new Redis()),
 *   });
 */
export function createRedisStore<T extends SessionData = SessionData>(
  client: RedisLike,
  opts: { keyPrefix?: string; userIndexPrefix?: string; clock?: () => number } = {},
): SessionStore<T> {
  const keyPrefix = opts.keyPrefix ?? DEFAULT_KEY_PREFIX;
  const userIndexPrefix = opts.userIndexPrefix ?? DEFAULT_USER_INDEX_PREFIX;
  const clock = opts.clock ?? nowSeconds;
  const recordKey = (id: string): string => `${keyPrefix}${id}`;
  const metaKey = (id: string): string => `${keyPrefix}${META_PREFIX}${id}`;
  const userKey = (userId: string): string => `${userIndexPrefix}${userId}`;

  const ttlFor = (meta: SessionMetadata): number => Math.max(1, meta.expiresAt - clock());

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      throw new SessionError('STORE_UNAVAILABLE', `redis ${op} failed`, err);
    }
  };

  const indexAdd = async (userId: string, id: string, ttl: number): Promise<void> => {
    if (client.eval) {
      await client.eval(ADD_TO_USER_INDEX, [userKey(userId)], [id, String(ttl)]);
      return;
    }
    if (client.sadd) await client.sadd(userKey(userId), id);
    if (client.expire) await client.expire(userKey(userId), ttl);
  };

  const indexRemove = async (userId: string, id: string): Promise<void> => {
    if (client.eval) {
      await client.eval(REMOVE_FROM_USER_INDEX, [userKey(userId)], [id]);
      return;
    }
    if (client.srem) await client.srem(userKey(userId), id);
  };

  return {
    async create(record) {
      await wrap(async () => {
        const exists = await client.get(recordKey(record.meta.id));
        if (exists !== null) throw new SessionError('CONFLICT', 'session id collision');
        const ttl = ttlFor(record.meta);
        await client.set(recordKey(record.meta.id), encodeRecord(record), { ex: ttl });
        await client.set(metaKey(record.meta.id), encodeMeta(record.meta), { ex: ttl });
        if (record.meta.userId !== undefined) {
          await indexAdd(record.meta.userId, record.meta.id, ttl);
        }
      }, 'create');
    },

    async read(id) {
      return wrap(async () => {
        const blob = await client.get(recordKey(id));
        if (blob === null) return null;
        return decodeRecord<T>(blob);
      }, 'read');
    },

    async update(record) {
      return wrap(async () => {
        const existing = await client.get(recordKey(record.meta.id));
        if (existing === null) return false;
        const ttl = ttlFor(record.meta);
        await client.set(recordKey(record.meta.id), encodeRecord(record), { ex: ttl });
        await client.set(metaKey(record.meta.id), encodeMeta(record.meta), { ex: ttl });
        return true;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const existingMeta = await client.get(metaKey(id));
        const removed = await client.del([recordKey(id), metaKey(id)]);
        if (existingMeta) {
          const meta = parseMetadataBlob(existingMeta);
          if (meta?.userId !== undefined) await indexRemove(meta.userId, id);
        }
        return removed > 0;
      }, 'delete');
    },

    async listByUser(userId) {
      return wrap(async () => {
        const ids = client.smembers ? await client.smembers(userKey(userId)) : [];
        const out: SessionMetadata[] = [];
        for (const id of ids) {
          const blob = await client.get(metaKey(id));
          if (!blob) continue;
          const meta = parseMetadataBlob(blob);
          if (meta) out.push(meta);
        }
        return out;
      }, 'listByUser');
    },

    async deleteByUser(userId) {
      return wrap(async () => {
        const ids = client.smembers ? await client.smembers(userKey(userId)) : [];
        if (ids.length === 0) return 0;
        const keys: string[] = [];
        for (const id of ids) {
          keys.push(recordKey(id));
          keys.push(metaKey(id));
        }
        keys.push(userKey(userId));
        await client.del(keys);
        return ids.length;
      }, 'deleteByUser');
    },
  };
}

function encodeMeta(meta: SessionMetadata): string {
  return JSON.stringify(meta);
}
