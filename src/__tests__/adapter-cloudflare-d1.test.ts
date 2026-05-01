import { describe, expect, it } from 'vitest';
import { createD1Store } from '../adapters/cloudflare-d1/index.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import { SessionError } from '../errors/base.js';
import type { SessionRecord } from '../types/session.js';
import { makeClock } from './_helpers.js';

interface Data extends Record<string, unknown> {
  v: number;
}

interface Row {
  id: string;
  user_id: string | null;
  meta: string;
  data: string;
  expires_at: number;
  created_at: number;
  last_seen_at: number;
}

class FakeD1Database {
  rows = new Map<string, Row>();
  faulty = false;

  prepare(sql: string): D1PreparedStatement {
    const db = this;
    const params: unknown[] = [];
    const stmt: D1PreparedStatement = {
      bind: (...vals: unknown[]) => {
        params.push(...vals);
        return stmt;
      },
      first: async <T = unknown>(): Promise<T | null> => {
        if (db.faulty) throw new Error('d1 down');
        if (sql.startsWith('SELECT meta, data FROM')) {
          const id = params[0] as string;
          const cutoff = params[1] as number;
          const row = db.rows.get(id);
          if (!row || row.expires_at <= cutoff) return null;
          return { meta: row.meta, data: row.data } as unknown as T;
        }
        return null;
      },
      all: async <T = unknown>(): Promise<{ results: T[] }> => {
        if (db.faulty) throw new Error('d1 down');
        if (sql.startsWith('SELECT meta FROM')) {
          const userId = params[0] as string;
          const cutoff = params[1] as number;
          const out = [];
          for (const row of db.rows.values()) {
            if (row.user_id === userId && row.expires_at > cutoff) {
              out.push({ meta: row.meta });
            }
          }
          return { results: out as unknown as T[] };
        }
        return { results: [] };
      },
      run: async (): Promise<D1Result> => {
        if (db.faulty) throw new Error('d1 down');
        if (sql.startsWith('INSERT')) {
          const [id, user_id, meta, data, expires_at, created_at, last_seen_at] = params;
          if (db.rows.has(id as string)) {
            return { success: false, meta: { changes: 0 } } as unknown as D1Result;
          }
          db.rows.set(id as string, {
            id: id as string,
            user_id: user_id as string | null,
            meta: meta as string,
            data: data as string,
            expires_at: expires_at as number,
            created_at: created_at as number,
            last_seen_at: last_seen_at as number,
          });
          return { success: true, meta: { changes: 1 } } as unknown as D1Result;
        }
        if (sql.startsWith('UPDATE')) {
          const [id, user_id, meta, data, expires_at, last_seen_at] = params;
          const existing = db.rows.get(id as string);
          if (!existing) return { success: true, meta: { changes: 0 } } as unknown as D1Result;
          existing.user_id = user_id as string | null;
          existing.meta = meta as string;
          existing.data = data as string;
          existing.expires_at = expires_at as number;
          existing.last_seen_at = last_seen_at as number;
          return { success: true, meta: { changes: 1 } } as unknown as D1Result;
        }
        if (sql.startsWith('DELETE FROM') && sql.includes('user_id =')) {
          const userId = params[0] as string;
          let removed = 0;
          for (const [k, row] of [...db.rows]) {
            if (row.user_id === userId) {
              db.rows.delete(k);
              removed++;
            }
          }
          return { success: true, meta: { changes: removed } } as unknown as D1Result;
        }
        if (sql.startsWith('DELETE FROM') && sql.includes('id =') && !sql.includes('user_id =')) {
          const id = params[0] as string;
          return { success: true, meta: { changes: db.rows.delete(id) ? 1 : 0 } } as unknown as D1Result;
        }
        if (sql.startsWith('DELETE FROM') && sql.includes('expires_at')) {
          const cutoff = params[0] as number;
          let removed = 0;
          for (const [k, row] of db.rows) {
            if (row.expires_at <= cutoff) {
              db.rows.delete(k);
              removed++;
            }
          }
          return { success: true, meta: { changes: removed } } as unknown as D1Result;
        }
        return { success: false, meta: { changes: 0 } } as unknown as D1Result;
      },
    } as D1PreparedStatement;
    return stmt;
  }
}

const fakeDb = (): D1Database => new FakeD1Database() as unknown as D1Database;

const buildRecord = (overrides: Partial<{ userId?: string; expiresAt?: number }> = {}): SessionRecord<Data> => ({
  meta: { ...mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined), ...overrides },
  data: { v: 1 },
});

describe('createD1Store', () => {
  it('should round-trip a record', async () => {
    const store = createD1Store<Data>(fakeDb());
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should throw CONFLICT on duplicate id', async () => {
    const store = createD1Store<Data>(fakeDb());
    const r = buildRecord();
    await store.create(r);
    await expect(store.create(r)).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading missing id', async () => {
    const store = createD1Store<Data>(fakeDb());
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when nothing exists', async () => {
    const store = createD1Store<Data>(fakeDb());
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const store = createD1Store<Data>(fakeDb());
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should delete a record', async () => {
    const store = createD1Store<Data>(fakeDb());
    const r = buildRecord();
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect(await store.delete(r.meta.id)).toBe(false);
  });

  it('should list active sessions for a user (excluding expired)', async () => {
    const clock = makeClock();
    const store = createD1Store<Data>(fakeDb(), { clock });
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u', expiresAt: clock() - 100 }));
    expect((await store.listByUser('u')).length).toBe(1);
  });

  it('should bulk-delete every record for a user', async () => {
    const store = createD1Store<Data>(fakeDb());
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
  });

  it('should sweep expired records', async () => {
    const clock = makeClock();
    const store = createD1Store<Data>(fakeDb(), { clock });
    await store.create(buildRecord());
    clock.advance(86_400 * 365);
    expect(await store.sweep?.()).toBe(1);
  });

  it('should re-wrap underlying errors as STORE_UNAVAILABLE', async () => {
    const db = new FakeD1Database();
    db.faulty = true;
    const store = createD1Store<Data>(db as unknown as D1Database);
    await expect(store.read('id')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });

  it('should reject an invalid table name at construction time', () => {
    expect(() => createD1Store(fakeDb(), { tableName: '1bad name' })).toThrowError(SessionError);
    expect(() => createD1Store(fakeDb(), { tableName: 'bad-name' })).toThrowError(/invalid table name/);
  });
});
