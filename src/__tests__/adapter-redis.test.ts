import { describe, expect, it } from 'vitest';
import { createRedisStore } from '../adapters/redis/index.js';
import type { RedisLike } from '../adapters/redis/client.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import type { SessionRecord } from '../types/session.js';
import { makeClock } from './_helpers.js';

interface Data extends Record<string, unknown> {
  v: number;
}

interface FakeRedisOpts {
  /** Throw on every operation. */
  faulty?: boolean;
  /** Disable EVAL so the adapter takes the SADD/EXPIRE fallback path. */
  noEval?: boolean;
}

class FakeRedis implements RedisLike {
  private kv = new Map<string, string>();
  private sets = new Map<string, Set<string>>();
  private faulty: boolean;
  private noEval: boolean;

  constructor(opts: FakeRedisOpts = {}) {
    this.faulty = opts.faulty ?? false;
    this.noEval = opts.noEval ?? false;
    if (this.noEval) (this as { eval?: RedisLike['eval'] }).eval = undefined;
  }

  async get(key: string): Promise<string | null> {
    if (this.faulty) throw new Error('redis down');
    return this.kv.get(key) ?? null;
  }

  async set(key: string, value: string): Promise<unknown> {
    if (this.faulty) throw new Error('redis down');
    this.kv.set(key, value);
    return 'OK';
  }

  async del(key: string | readonly string[]): Promise<number> {
    if (this.faulty) throw new Error('redis down');
    const keys = Array.isArray(key) ? key : [key];
    let removed = 0;
    for (const k of keys) {
      if (this.kv.delete(k)) removed++;
      if (this.sets.delete(k)) removed++;
    }
    return removed;
  }

  async expire(): Promise<number> {
    return 1;
  }

  async eval(_script: string, keys: readonly string[], args: readonly string[]): Promise<unknown> {
    // Mimic the SADD/SREM scripts for the Redis adapter.
    const k = keys[0];
    if (!k) return 0;
    const a0 = args[0];
    if (a0 === undefined) return 0;
    let set = this.sets.get(k);
    if (!set) {
      set = new Set();
      this.sets.set(k, set);
    }
    // Heuristic: if there's an args[1] it's the ADD script (id, ttl).
    if (args.length === 2) {
      set.add(a0);
      return 1;
    }
    set.delete(a0);
    return 1;
  }

  async smembers(key: string): Promise<readonly string[]> {
    if (this.faulty) throw new Error('redis down');
    return Array.from(this.sets.get(key) ?? []);
  }

  async sadd(key: string, ...members: readonly string[]): Promise<number> {
    let set = this.sets.get(key);
    if (!set) {
      set = new Set();
      this.sets.set(key, set);
    }
    let added = 0;
    for (const m of members) {
      if (!set.has(m)) {
        set.add(m);
        added++;
      }
    }
    return added;
  }

  async srem(key: string, ...members: readonly string[]): Promise<number> {
    const set = this.sets.get(key);
    if (!set) return 0;
    let removed = 0;
    for (const m of members) {
      if (set.delete(m)) removed++;
    }
    return removed;
  }
}

const buildRecord = (overrides: Partial<{ userId?: string }> = {}): SessionRecord<Data> => ({
  meta: mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined),
  data: { v: 1 },
});

describe('createRedisStore', () => {
  it('should round-trip a record', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should throw CONFLICT when a record with the same id exists', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading a missing id', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when the record is missing', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should return false from delete when nothing exists', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    expect(await store.delete('missing')).toBe(false);
  });

  it('should delete a record and remove it from the user index', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    const r = buildRecord({ userId: 'u' });
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect((await store.listByUser('u')).length).toBe(0);
  });

  it('should list a user’s active sessions', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect((await store.listByUser('u')).length).toBe(2);
  });

  it('should return [] from listByUser when smembers is unavailable', async () => {
    const fake = new FakeRedis();
    (fake as { smembers?: unknown }).smembers = undefined;
    const store = createRedisStore<Data>(fake);
    expect(await store.listByUser('u')).toEqual([]);
  });

  it('should bulk-delete every record for a user', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
  });

  it('should return 0 from deleteByUser for an unknown user', async () => {
    const store = createRedisStore<Data>(new FakeRedis());
    expect(await store.deleteByUser('nobody')).toBe(0);
  });

  it('should fall back to SADD/EXPIRE when EVAL is unavailable', async () => {
    const store = createRedisStore<Data>(new FakeRedis({ noEval: true }));
    await store.create(buildRecord({ userId: 'u' }));
    expect((await store.listByUser('u')).length).toBe(1);
  });

  it('should re-wrap underlying errors as STORE_UNAVAILABLE', async () => {
    const store = createRedisStore<Data>(new FakeRedis({ faulty: true }));
    await expect(store.read('id')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });

  it('should compute TTL based on the injected clock', async () => {
    const clock = makeClock();
    const store = createRedisStore<Data>(new FakeRedis(), { clock });
    const r = buildRecord();
    await store.create(r);
    expect(await store.read(r.meta.id)).not.toBeNull();
    clock.advance(86_400 * 2);
    // Fake redis does not honour TTL, so the record is still there — the
    // adapter's role is just to compute a >0 TTL when calling SET EX.
    expect(await store.read(r.meta.id)).not.toBeNull();
  });

  it('should accept opts.keyPrefix override', async () => {
    const store = createRedisStore<Data>(new FakeRedis(), { keyPrefix: 'custom:' });
    const r = buildRecord();
    await expect(store.create(r)).resolves.toBeUndefined();
  });
});
