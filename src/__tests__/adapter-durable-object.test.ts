import { describe, expect, it } from 'vitest';
import { createDurableObjectStore } from '../adapters/durable-object/index.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import type { SessionRecord } from '../types/session.js';

interface Data extends Record<string, unknown> {
  v: number;
}

class FakeDOStub {
  records = new Map<string, SessionRecord<Data>>();
  userIndex = new Map<string, Set<string>>();
  faulty = false;

  fetch = async (url: string, init?: RequestInit): Promise<Response> => {
    if (this.faulty) throw new Error('do down');
    const u = new URL(url);
    const path = u.pathname;
    const method = init?.method ?? 'GET';
    if (path.startsWith('/sessions/')) {
      const id = decodeURIComponent(path.slice('/sessions/'.length));
      if (method === 'PUT') {
        if (this.records.has(id)) return new Response('conflict', { status: 409 });
        // Body is base64url-encoded record per encoder.
        const body = (await new Response(init?.body).text()) ?? '';
        const record = parseEnvelope<Data>(body);
        if (!record) return new Response('bad', { status: 400 });
        this.records.set(id, record);
        if (record.meta.userId !== undefined) {
          let set = this.userIndex.get(record.meta.userId);
          if (!set) {
            set = new Set();
            this.userIndex.set(record.meta.userId, set);
          }
          set.add(id);
        }
        return new Response(null, { status: 201 });
      }
      if (method === 'GET') {
        const r = this.records.get(id);
        if (!r) return new Response('not found', { status: 404 });
        return new Response(encodeEnvelope(r));
      }
      if (method === 'POST') {
        const r = this.records.get(id);
        if (!r) return new Response('not found', { status: 404 });
        const body = await new Response(init?.body).text();
        const next = parseEnvelope<Data>(body);
        if (!next) return new Response('bad', { status: 400 });
        this.records.set(id, next);
        return new Response(null, { status: 200 });
      }
      if (method === 'DELETE') {
        const had = this.records.delete(id);
        return new Response(null, { status: had ? 200 : 404 });
      }
    }
    if (path.startsWith('/users/')) {
      const userId = decodeURIComponent(path.split('/')[2] ?? '');
      if (method === 'GET') {
        const set = this.userIndex.get(userId) ?? new Set();
        const out = [];
        for (const id of set) {
          const r = this.records.get(id);
          if (r) out.push(r.meta);
        }
        return new Response(JSON.stringify(out));
      }
      if (method === 'DELETE') {
        const set = this.userIndex.get(userId) ?? new Set();
        let count = 0;
        for (const id of set) {
          if (this.records.delete(id)) count++;
        }
        this.userIndex.delete(userId);
        return new Response(JSON.stringify({ count }));
      }
    }
    return new Response('not found', { status: 404 });
  };
}

function encodeEnvelope<T extends Record<string, unknown>>(record: SessionRecord<T>): string {
  const env = JSON.stringify({ v: 1, meta: record.meta, data: record.data });
  return btoa(env).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function parseEnvelope<T extends Record<string, unknown>>(blob: string): SessionRecord<T> | null {
  try {
    const padded = blob.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (blob.length % 4)) % 4);
    const obj = JSON.parse(atob(padded)) as { meta: SessionRecord<T>['meta']; data: T };
    return { meta: obj.meta, data: obj.data };
  } catch {
    return null;
  }
}

const fakeStub = (): DurableObjectStub => new FakeDOStub() as unknown as DurableObjectStub;

const buildRecord = (overrides: Partial<{ userId?: string }> = {}): SessionRecord<Data> => ({
  meta: mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined),
  data: { v: 1 },
});

describe('createDurableObjectStore', () => {
  it('should round-trip a record', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should throw CONFLICT when the DO returns 409', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading a missing id', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when the id is missing', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should delete a record', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    const r = buildRecord();
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect(await store.delete(r.meta.id)).toBe(false);
  });

  it('should list active sessions for a user', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect((await store.listByUser('u')).length).toBe(2);
  });

  it('should bulk-delete every record for a user', async () => {
    const store = createDurableObjectStore<Data>(fakeStub());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
  });

  it('should re-wrap thrown errors as STORE_UNAVAILABLE', async () => {
    const stub = new FakeDOStub();
    stub.faulty = true;
    const store = createDurableObjectStore<Data>(stub as unknown as DurableObjectStub);
    await expect(store.read('id')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });
});
