import { parseMetadataBlob } from '../../core/encoder.js';
import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

const DEFAULT_TABLE = 'sessions';

/**
 * Generic Postgres query function. Compatible with `pg.Pool#query`,
 * `postgres.js`, `@neondatabase/serverless`, and most SQL builders that
 * accept a parameterised query and return an array of rows.
 *
 * @typeParam Row  Expected row shape.
 * @param sql      Parameterised SQL using `$1, $2, ...` placeholders.
 * @param params   Values for the placeholders.
 * @returns Read-only array of rows.
 */
export type PostgresQuery = <Row = unknown>(
  sql: string,
  params: readonly unknown[],
) => Promise<readonly Row[]>;

/**
 * Create a Postgres-backed session store.
 *
 * Schema is in `schema.sql` next to this file. The adapter does NOT
 * issue DDL — production deployments run migrations separately. The
 * `sessions_user_idx` keeps `listByUser` O(log n).
 *
 * @typeParam T  Session payload shape.
 * @param query              Query function — see `PostgresQuery`.
 * @param opts.tableName     Override for the table name. Default `'sessions'`.
 * @returns A `SessionStore` backed by Postgres.
 *
 * @example
 *   import pg from 'pg';
 *   import { createPostgresStore } from '@authkit/sessions/adapters/postgres';
 *
 *   const pool = new pg.Pool();
 *   const sessions = createSessionManager({
 *     secrets: [SECRET],
 *     store: createPostgresStore(async (sql, params) => {
 *       const result = await pool.query(sql, [...params]);
 *       return result.rows;
 *     }),
 *   });
 */
export function createPostgresStore<T extends SessionData = SessionData>(
  query: PostgresQuery,
  opts: { tableName?: string; clock?: () => number } = {},
): SessionStore<T> {
  const table = sanitiseTableName(opts.tableName ?? DEFAULT_TABLE);
  const clock = opts.clock ?? nowSeconds;

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      // Postgres unique-violation = `23505`. Surface as CONFLICT.
      if (typeof (err as { code?: unknown }).code === 'string' && (err as { code: string }).code === '23505') {
        throw new SessionError('CONFLICT', 'session id collision', err);
      }
      throw new SessionError('STORE_UNAVAILABLE', `postgres ${op} failed`, err);
    }
  };

  return {
    async create(record) {
      await wrap(async () => {
        await query(
          `INSERT INTO ${table}
            (id, user_id, meta, data, expires_at, created_at, last_seen_at)
            VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7)`,
          [
            record.meta.id,
            record.meta.userId ?? null,
            JSON.stringify(record.meta),
            JSON.stringify(record.data),
            record.meta.expiresAt,
            record.meta.createdAt,
            record.meta.lastSeenAt,
          ],
        );
      }, 'create');
    },

    async read(id) {
      return wrap(async () => {
        const rows = await query<{ meta: unknown; data: unknown }>(
          `SELECT meta, data FROM ${table}
            WHERE id = $1 AND expires_at > $2 LIMIT 1`,
          [id, clock()],
        );
        const row = rows[0];
        if (!row) return null;
        return parseRow<T>(row);
      }, 'read');
    },

    async update(record) {
      return wrap(async () => {
        const rows = await query<{ id: string }>(
          `UPDATE ${table} SET
              user_id = $2,
              meta = $3::jsonb,
              data = $4::jsonb,
              expires_at = $5,
              last_seen_at = $6
            WHERE id = $1
            RETURNING id`,
          [
            record.meta.id,
            record.meta.userId ?? null,
            JSON.stringify(record.meta),
            JSON.stringify(record.data),
            record.meta.expiresAt,
            record.meta.lastSeenAt,
          ],
        );
        return rows.length > 0;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const rows = await query<{ id: string }>(
          `DELETE FROM ${table} WHERE id = $1 RETURNING id`,
          [id],
        );
        return rows.length > 0;
      }, 'delete');
    },

    async listByUser(userId) {
      return wrap(async () => {
        const rows = await query<{ meta: unknown }>(
          `SELECT meta FROM ${table}
            WHERE user_id = $1 AND expires_at > $2
            ORDER BY last_seen_at DESC`,
          [userId, clock()],
        );
        const out: SessionMetadata[] = [];
        for (const row of rows) {
          const meta = parseMetadataBlob(row.meta);
          if (meta) out.push(meta);
        }
        return out;
      }, 'listByUser');
    },

    async deleteByUser(userId) {
      return wrap(async () => {
        const rows = await query<{ id: string }>(
          `DELETE FROM ${table} WHERE user_id = $1 RETURNING id`,
          [userId],
        );
        return rows.length;
      }, 'deleteByUser');
    },

    async sweep(now) {
      return wrap(async () => {
        const cutoff = now ?? clock();
        const rows = await query<{ id: string }>(
          `DELETE FROM ${table} WHERE expires_at <= $1 RETURNING id`,
          [cutoff],
        );
        return rows.length;
      }, 'sweep');
    },
  };
}

function sanitiseTableName(name: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new SessionError('CONFIG_INVALID', `invalid table name: ${JSON.stringify(name)}`);
  }
  return name;
}

function parseRow<T extends SessionData>(row: {
  meta: unknown;
  data: unknown;
}): SessionRecord<T> | null {
  const meta = parseMetadataBlob(row.meta);
  if (!meta) return null;
  // Postgres `jsonb` columns deserialise to `unknown`; the row's `data`
  // is the user-shaped payload by contract (see schema.sql).
  return { meta, data: row.data as T };
}
