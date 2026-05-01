import { decodeRecord, encodeRecord, parseMetadataBlob } from '../../core/encoder.js';
import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

const DEFAULT_KEY_PREFIX = 'sess:';
const META_PREFIX = 'meta:';
const USER_PREFIX = 'sess:user:';

/**
 * Minimal Upstash REST client shape — a subset of `@upstash/redis` we
 * actually use. Declaring the shape locally lets the adapter compile
 * even when `@upstash/redis` is not installed (it's an optional peer).
 *
 * @internal
 */
export interface UpstashClientLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, opts?: { ex?: number }): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
  expire(key: string, seconds: number): Promise<number>;
}

/**
 * Create an Upstash-backed session store.
 *
 * Uses HTTP pipelining instead of Lua (Upstash's free tier disables
 * `EVAL`); concurrency falls back to a `SADD` + `EXPIRE` pair, which is
 * non-atomic but tolerable given the documented worst-case overshoot
 * of 1 (§9.3.1 of `PLAN.md`).
 *
 * @typeParam T  Session payload shape.
 * @param client     `@upstash/redis` instance, or any client matching `UpstashClientLike`.
 * @param opts.keyPrefix  Override for the session-record namespace. Default `'sess:'`.
 * @returns A `SessionStore` backed by Upstash Redis.
 *
 * @example
 *   import { Redis } from '@upstash/redis';
 *   import { createUpstashStore } from '@authkit/sessions/adapters/upstash';
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createUpstashStore(Redis.fromEnv()),
 *   });
 */
export function createUpstashStore<T extends SessionData = SessionData>(
  client: UpstashClientLike,
  opts: { keyPrefix?: string; clock?: () => number } = {},
): SessionStore<T> {
  const keyPrefix = opts.keyPrefix ?? DEFAULT_KEY_PREFIX;
  const clock = opts.clock ?? nowSeconds;
  const recordKey = (id: string): string => `${keyPrefix}${id}`;
  const metaKey = (id: string): string => `${keyPrefix}${META_PREFIX}${id}`;
  const userKey = (userId: string): string => `${USER_PREFIX}${userId}`;

  const ttlFor = (meta: SessionMetadata): number => Math.max(1, meta.expiresAt - clock());

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      throw new SessionError('STORE_UNAVAILABLE', `upstash ${op} failed`, err);
    }
  };

  return {
    async create(record) {
      await wrap(async () => {
        const exists = await client.get(recordKey(record.meta.id));
        if (exists !== null) throw new SessionError('CONFLICT', 'session id collision');
        const ttl = ttlFor(record.meta);
        await client.set(recordKey(record.meta.id), encodeRecord(record), { ex: ttl });
        await client.set(metaKey(record.meta.id), JSON.stringify(record.meta), { ex: ttl });
        if (record.meta.userId !== undefined) {
          await client.sadd(userKey(record.meta.userId), record.meta.id);
          await client.expire(userKey(record.meta.userId), ttl);
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
        await client.set(metaKey(record.meta.id), JSON.stringify(record.meta), { ex: ttl });
        return true;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const metaBlob = await client.get(metaKey(id));
        const removed = await client.del(recordKey(id), metaKey(id));
        if (metaBlob) {
          const meta = parseMetadataBlob(metaBlob);
          if (meta?.userId !== undefined) await client.srem(userKey(meta.userId), id);
        }
        return removed > 0;
      }, 'delete');
    },

    async listByUser(userId) {
      return wrap(async () => {
        const ids = await client.smembers(userKey(userId));
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
        const ids = await client.smembers(userKey(userId));
        if (ids.length === 0) return 0;
        const keys: string[] = [];
        for (const id of ids) {
          keys.push(recordKey(id));
          keys.push(metaKey(id));
        }
        keys.push(userKey(userId));
        await client.del(...keys);
        return ids.length;
      }, 'deleteByUser');
    },
  };
}

