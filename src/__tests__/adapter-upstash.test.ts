import { describe, expect, it } from 'vitest';
import { createUpstashStore, type UpstashClientLike } from '../adapters/upstash/index.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import type { SessionRecord } from '../types/session.js';

interface Data extends Record<string, unknown> {
  v: number;
}

class FakeUpstash implements UpstashClientLike {
  kv = new Map<string, string>();
  sets = new Map<string, Set<string>>();
  faulty = false;

  async get(key: string): Promise<string | null> {
    if (this.faulty) throw new Error('upstash down');
    return this.kv.get(key) ?? null;
  }
  async set(key: string, value: string): Promise<unknown> {
    if (this.faulty) throw new Error('upstash down');
    this.kv.set(key, value);
    return 'OK';
  }
  async del(...keys: string[]): Promise<number> {
    if (this.faulty) throw new Error('upstash down');
    let removed = 0;
    for (const k of keys) {
      if (this.kv.delete(k)) removed++;
      if (this.sets.delete(k)) removed++;
    }
    return removed;
  }
  async sadd(key: string, ...members: string[]): Promise<number> {
    let s = this.sets.get(key);
    if (!s) {
      s = new Set();
      this.sets.set(key, s);
    }
    let added = 0;
    for (const m of members) {
      if (!s.has(m)) {
        s.add(m);
        added++;
      }
    }
    return added;
  }
  async srem(key: string, ...members: string[]): Promise<number> {
    const s = this.sets.get(key);
    if (!s) return 0;
    let removed = 0;
    for (const m of members) {
      if (s.delete(m)) removed++;
    }
    return removed;
  }
  async smembers(key: string): Promise<string[]> {
    return Array.from(this.sets.get(key) ?? []);
  }
  async expire(): Promise<number> {
    return 1;
  }
}

const buildRecord = (overrides: Partial<{ userId?: string }> = {}): SessionRecord<Data> => ({
  meta: mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined),
  data: { v: 1 },
});

describe('createUpstashStore', () => {
  it('should round-trip a record', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should throw CONFLICT for duplicate id', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading a missing id', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when missing', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
  });

  it('should delete a record and remove from user index', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    const r = buildRecord({ userId: 'u' });
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect((await store.listByUser('u')).length).toBe(0);
  });

  it('should return false from delete when nothing exists', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    expect(await store.delete('missing')).toBe(false);
  });

  it('should bulk-delete every record for a user', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
  });

  it('should return 0 from deleteByUser for an unknown user', async () => {
    const store = createUpstashStore<Data>(new FakeUpstash());
    expect(await store.deleteByUser('unknown')).toBe(0);
  });

  it('should re-wrap thrown errors as STORE_UNAVAILABLE', async () => {
    const fake = new FakeUpstash();
    fake.faulty = true;
    const store = createUpstashStore<Data>(fake);
    await expect(store.read('any')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });
});
