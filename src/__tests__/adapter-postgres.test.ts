import { describe, expect, it } from 'vitest';
import { createPostgresStore, type PostgresQuery } from '../adapters/postgres/index.js';
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
  meta: unknown;
  data: unknown;
  expires_at: number;
  created_at: number;
  last_seen_at: number;
}

class FakePostgres {
  rows = new Map<string, Row>();
  faulty = false;
  uniqueViolations = false;

  query: PostgresQuery = async <RowOut = unknown>(sql: string, params: readonly unknown[]): Promise<readonly RowOut[]> => {
    if (this.faulty) throw new Error('pg down');
    if (this.uniqueViolations && sql.startsWith('INSERT')) {
      throw Object.assign(new Error('duplicate key'), { code: '23505' });
    }
    if (sql.startsWith('INSERT')) {
      const [id, user_id, meta, data, expires_at, created_at, last_seen_at] = params;
      this.rows.set(id as string, {
        id: id as string,
        user_id: user_id as string | null,
        meta: JSON.parse(meta as string),
        data: JSON.parse(data as string),
        expires_at: expires_at as number,
        created_at: created_at as number,
        last_seen_at: last_seen_at as number,
      });
      return [];
    }
    if (sql.startsWith('SELECT meta, data')) {
      const id = params[0] as string;
      const cutoff = params[1] as number;
      const row = this.rows.get(id);
      if (!row || row.expires_at <= cutoff) return [];
      return [{ meta: row.meta, data: row.data }] as unknown as RowOut[];
    }
    if (sql.startsWith('UPDATE')) {
      const [id, user_id, meta, data, expires_at, last_seen_at] = params;
      const existing = this.rows.get(id as string);
      if (!existing) return [];
      existing.user_id = user_id as string | null;
      existing.meta = JSON.parse(meta as string);
      existing.data = JSON.parse(data as string);
      existing.expires_at = expires_at as number;
      existing.last_seen_at = last_seen_at as number;
      return [{ id }] as unknown as RowOut[];
    }
    if (sql.startsWith('DELETE FROM') && sql.includes('id = $1') && !sql.includes('user_id')) {
      const id = params[0] as string;
      const existed = this.rows.delete(id);
      return existed ? ([{ id }] as unknown as RowOut[]) : [];
    }
    if (sql.startsWith('DELETE FROM') && sql.includes('user_id')) {
      const userId = params[0] as string;
      const out: { id: string }[] = [];
      for (const [k, row] of this.rows) {
        if (row.user_id === userId) {
          this.rows.delete(k);
          out.push({ id: k });
        }
      }
      return out as unknown as RowOut[];
    }
    if (sql.startsWith('DELETE FROM') && sql.includes('expires_at')) {
      const cutoff = params[0] as number;
      const out: { id: string }[] = [];
      for (const [k, row] of this.rows) {
        if (row.expires_at <= cutoff) {
          this.rows.delete(k);
          out.push({ id: k });
        }
      }
      return out as unknown as RowOut[];
    }
    if (sql.startsWith('SELECT meta FROM')) {
      const userId = params[0] as string;
      const cutoff = params[1] as number;
      const out: { meta: unknown }[] = [];
      for (const row of this.rows.values()) {
        if (row.user_id === userId && row.expires_at > cutoff) {
          out.push({ meta: row.meta });
        }
      }
      return out as unknown as RowOut[];
    }
    return [];
  };
}

const buildRecord = (overrides: Partial<{ userId?: string; expiresAt?: number }> = {}): SessionRecord<Data> => ({
  meta: { ...mintMetadata(nowSeconds(), 86_400, 3_600, overrides.userId, undefined), ...overrides },
  data: { v: 1 },
});

describe('createPostgresStore', () => {
  it('should round-trip a record', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    const r = buildRecord();
    await store.create(r);
    expect((await store.read(r.meta.id))?.data.v).toBe(1);
  });

  it('should map a 23505 unique-violation to CONFLICT', async () => {
    const fake = new FakePostgres();
    fake.uniqueViolations = true;
    const store = createPostgresStore<Data>(fake.query);
    await expect(store.create(buildRecord())).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('should return null when reading missing id', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    expect(await store.read('missing')).toBeNull();
  });

  it('should return false from update when missing', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    expect(await store.update(buildRecord())).toBe(false);
  });

  it('should update an existing record', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    const r = buildRecord();
    await store.create(r);
    expect(await store.update({ ...r, data: { v: 2 } })).toBe(true);
    expect((await store.read(r.meta.id))?.data.v).toBe(2);
  });

  it('should delete a record by id', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    const r = buildRecord();
    await store.create(r);
    expect(await store.delete(r.meta.id)).toBe(true);
    expect(await store.delete(r.meta.id)).toBe(false);
  });

  it('should list active sessions for a user', async () => {
    const fake = new FakePostgres();
    const clock = makeClock();
    const store = createPostgresStore<Data>(fake.query, { clock });
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u', expiresAt: clock() - 1 }));
    expect((await store.listByUser('u')).length).toBe(1);
  });

  it('should bulk-delete every record for a user', async () => {
    const fake = new FakePostgres();
    const store = createPostgresStore<Data>(fake.query);
    await store.create(buildRecord({ userId: 'u' }));
    await store.create(buildRecord({ userId: 'u' }));
    expect(await store.deleteByUser('u')).toBe(2);
  });

  it('should sweep expired records', async () => {
    const fake = new FakePostgres();
    const clock = makeClock();
    const store = createPostgresStore<Data>(fake.query, { clock });
    await store.create(buildRecord({ expiresAt: clock() - 1 }));
    expect(await store.sweep?.()).toBe(1);
  });

  it('should re-wrap thrown errors as STORE_UNAVAILABLE', async () => {
    const fake = new FakePostgres();
    fake.faulty = true;
    const store = createPostgresStore<Data>(fake.query);
    await expect(store.read('id')).rejects.toMatchObject({ code: 'STORE_UNAVAILABLE' });
  });

  it('should reject an invalid table name at construction time', () => {
    expect(() =>
      createPostgresStore(async () => [], { tableName: 'bad name' }),
    ).toThrowError(SessionError);
  });
});
