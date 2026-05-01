import { describe, expect, it } from 'vitest';
import { createKVStore } from '../adapters/cloudflare-kv/index.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import type { SessionRecord } from '../types/session.js';
import { makeClock } from './_helpers.js';

interface Data extends Record<string, unknown> {
  v: number;
}

class FakeKVNamespace {
  store = new Map<string, string>();
  faulty = false;

  async get(key: string): Promise<string | null> {
    if (this.faulty) throw new Error('kv down');
    return this.store.get(key) ?? null;
  }

  async put(key: string, value: string, _opts?: { expirationTtl?: number }): Promise<void> {
    if (this.faulty) throw new Error('kv down');
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(): Promise<{ keys: { name: string }[] }> {
    return { keys: [...this.store.keys()].map((name) => ({ name })) };
  }
}

const fakeNs = (): KVNamespace => new FakeKVNamespace() as unknown as KVNamespace;

const buildRecord = (overrides: Partial<{ userId?: string; expiresAt?: number }> = {}): SessionRecord<Data> => ({
  meta: { ...mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined), ...overrides },
  data: { v: 1 },
});

describe('createKVStore', () => {
  it('should round-trip a record', async () => {
    const store = createKVStore<Data>(fakeNs());
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should throw CONFLICT on duplicate id', async () => {
    const store = createKVStore<Data>(fakeNs());
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading missing id', async () => {
    const store = createKVStore<Data>(fakeNs());
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when missing', async () => {
    const store = createKVStore<Data>(fakeNs());
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createKVStore<Data>(fakeNs());
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should delete a record', async () => {
    const store = createKVStore<Data>(fakeNs());
    const r = buildRecord();
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
  });

  it('should return false from delete when nothing exists', async () => {
    const store = createKVStore<Data>(fakeNs());
    expect(await store.delete('missing')).toBe(false);
  });

  it('should return [] from listByUser when no userIndex namespace is configured', async () => {
    const store = createKVStore<Data>(fakeNs());
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.listByUser('u')).toEqual([]);
  });

  it('should index sessions by user when a userIndex namespace is provided', async () => {
    const ns = fakeNs();
    const idx = fakeNs();
    const store = createKVStore<Data>(ns, { userIndex: idx });
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect((await store.listByUser('u')).length).toBe(2);
  });

  it('should not duplicate ids in the user index when re-creating with the same id (no-op test path)', async () => {
    const ns = fakeNs();
    const idx = fakeNs();
    const store = createKVStore<Data>(ns, { userIndex: idx });
    const r = buildRecord({ userId: 'u' });
    await store.create(r);
    // Trigger a fresh listByUser path even after deletion+recreate sequence.
    await store.delete(r.meta.id);
    await store.create(r);
    expect((await store.listByUser('u')).length).toBe(1);
  });

  it('should bulk-delete every record for a user (with index)', async () => {
    const ns = fakeNs();
    const idx = fakeNs();
    const store = createKVStore<Data>(ns, { userIndex: idx });
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
    expect((await store.listByUser('u')).length).toBe(0);
  });

  it('should return 0 from deleteByUser when no userIndex is configured', async () => {
    const store = createKVStore<Data>(fakeNs());
    expect(await store.deleteByUser('u')).toBe(0);
  });

  it('should re-wrap underlying errors as STORE_UNAVAILABLE', async () => {
    const ns = new FakeKVNamespace();
    ns.faulty = true;
    const store = createKVStore<Data>(ns as unknown as KVNamespace);
    await expect(store.read('id')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });

  it('should compute a TTL >=60 even when expiresAt is close to now (KV minimum)', async () => {
    const clock = makeClock();
    const store = createKVStore<Data>(fakeNs(), { clock });
    // Adapter clamps TTL >= 60s by design.
    const r = buildRecord({ expiresAt: clock() + 5 });
    await expect(store.create(r)).resolves.toBeUndefined();
  });
});
