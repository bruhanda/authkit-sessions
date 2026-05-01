import { describe, expect, it } from 'vitest';
import { createMemoryStore } from '../adapters/memory/index.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import { SessionError } from '../errors/base.js';
import type { SessionRecord } from '../types/session.js';
import { makeClock } from './_helpers.js';

interface Data extends Record<string, unknown> {
  v: number;
}

const buildRecord = (overrides: Partial<{ id: string; userId?: string; expiresAt: number; createdAt: number; lastSeenAt: number }> = {}): SessionRecord<Data> => {
  const now = overrides.createdAt ?? nowSeconds();
  const meta = mintMetadata(now, 86_400, 3_600, overrides.userId, undefined);
  return {
    meta: { ...meta, ...overrides },
    data: { v: 1 },
  };
};

describe('createMemoryStore', () => {
  it('should write and read a record', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord();
    await store.create(r);
    const got = await store.read(r.meta.id);
    expect(got?.data.v).toBe(1);
  });

  it('should return null for a missing id', async () => {
    const store = createMemoryStore<Data>();
    expect(await store.read('missing')).toBeNull();
  });

  it('should clone records on read so external mutations cannot leak back in', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord();
    await store.create(r);
    const first = await store.read(r.meta.id);
    if (!first) throw new Error('expected record');
    (first.data as { v: number }).v = 999;
    const second = await store.read(r.meta.id);
    expect(second?.data.v).toBe(1);
  });

  it('should throw CONFLICT when create sees a duplicate id', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should report SessionError for collisions', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord();
    await store.create(r);
    try {
      await store.create(r);
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
    }
  });

  it('should return false from update when the record is missing', async () => {
    const store = createMemoryStore<Data>();
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord();
    await store.create(r);
    const next: SessionRecord<Data> = { meta: r.meta, data: { v: 2 } };
    expect(await store.update(next)).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should update the user index when userId changes', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord({ userId: 'u1' });
    await store.create(r);
    expect((await store.listByUser('u1')).length).toBe(1);
    await store.update({ ...r, meta: { ...r.meta, userId: 'u2' } });
    expect((await store.listByUser('u1')).length).toBe(0);
    expect((await store.listByUser('u2')).length).toBe(1);
  });

  it('should remove a session and update the user index on delete', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord({ userId: 'u' });
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect(await store.delete(r.meta.id)).toBe(false);
    expect((await store.listByUser('u')).length).toBe(0);
  });

  it('should expire records past expiresAt and remove them on read', async () => {
    const clock = makeClock(1_000);
    const store = createMemoryStore<Data>({ clock });
    const r = buildRecord({ expiresAt: 1_500 });
    await store.create(r);
    clock.advance(1_000);
    expect(await store.read(r.meta.id)).toBeNull();
  });

  it('should list active sessions for a user (excluding expired)', async () => {
    const clock = makeClock(1_000);
    const store = createMemoryStore<Data>({ clock });
    const r1 = buildRecord({ userId: 'u', expiresAt: 1_500 });
    const r2 = buildRecord({ userId: 'u', expiresAt: 5_000 });
    await store.create(r1);
    await store.create(r2);
    clock.advance(1_000);
    const out = await store.listByUser('u');
    expect(out.length).toBe(1);
    expect(out[0]?.id).toBe(r2.meta.id);
  });

  it('should return an empty array for an unknown user from listByUser', async () => {
    const store = createMemoryStore<Data>();
    expect(await store.listByUser('nope')).toEqual([]);
  });

  it('should bulk-delete every session for a user', async () => {
    const store = createMemoryStore<Data>();
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
    expect((await store.listByUser('u')).length).toBe(0);
  });

  it('should return 0 from deleteByUser for an unknown user', async () => {
    const store = createMemoryStore<Data>();
    expect(await store.deleteByUser('unknown')).toBe(0);
  });

  it('should sweep expired records via the optional sweep method', async () => {
    const clock = makeClock(1_000);
    const store = createMemoryStore<Data>({ clock });
    await store.create(buildRecord({ expiresAt: 1_200 }));
    await store.create(buildRecord({ expiresAt: 5_000 }));
    clock.advance(2_000);
    expect(await store.sweep?.()).toBe(1);
  });

  it('should accept an explicit cutoff for sweep', async () => {
    const store = createMemoryStore<Data>();
    const r = buildRecord({ expiresAt: 100 });
    await store.create(r);
    expect(await store.sweep?.(200)).toBe(1);
  });

  it('should evict the LRU entry when maxRecords is exceeded', async () => {
    const store = createMemoryStore<Data>({ maxRecords: 2 });
    const a = buildRecord();
    const b = buildRecord();
    const c = buildRecord();
    await store.create(a);
    await store.create(b);
    await store.read(b.meta.id); // bumps b
    await store.create(c);
    expect(await store.read(a.meta.id)).toBeNull();
    expect(await store.read(b.meta.id)).not.toBeNull();
    expect(await store.read(c.meta.id)).not.toBeNull();
  });
});
