import { parseMetadataBlob } from '../../core/encoder.js';
import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

const DEFAULT_TABLE = 'sessions';
/** Cloudflare D1 row size limit is 1 MB. We hard-stop at 950 KB. */
const D1_ROW_CEILING = 950 * 1024;

/**
 * Create a Cloudflare D1-backed session store.
 *
 * Schema is in `schema.sql` next to this file — apply via
 * `wrangler d1 execute <db> --file=node_modules/@authkit/sessions/dist/adapters/cloudflare-d1/schema.sql`
 * (or copy it into your migrations folder). The adapter itself does NOT
 * issue DDL; production deployments should run schema migrations
 * separately.
 *
 * Strong consistency is provided per-request (D1 sees each request
 * against the latest committed state). `concurrency` and `listByUser`
 * use the `sessions_user_idx` index to keep the per-user scan O(log n).
 *
 * @typeParam T  Session payload shape.
 * @param db                 Bound D1 database.
 * @param opts.tableName     Override for the table name. Default `'sessions'`.
 * @returns A `SessionStore` backed by D1.
 *
 * @example
 *   import { createD1Store } from '@authkit/sessions/adapters/cloudflare-d1';
 *   const sessions = createSessionManager({
 *     secrets: [env.SESSION_SECRET],
 *     store: createD1Store(env.DB),
 *   });
 */
export function createD1Store<T extends SessionData = SessionData>(
  db: D1Database,
  opts: { tableName?: string; clock?: () => number } = {},
): SessionStore<T> {
  const table = sanitiseTableName(opts.tableName ?? DEFAULT_TABLE);
  const clock = opts.clock ?? nowSeconds;

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      throw new SessionError('STORE_UNAVAILABLE', `d1 ${op} failed`, err);
    }
  };

  const guardSize = (data: string): void => {
    if (data.length > D1_ROW_CEILING) {
      throw new SessionError(
        'PAYLOAD_TOO_LARGE',
        `serialised session ${data.length} bytes exceeds D1 row ceiling`,
      );
    }
  };

  return {
    async create(record) {
      await wrap(async () => {
        const meta = JSON.stringify(record.meta);
        const data = JSON.stringify(record.data);
        guardSize(meta);
        guardSize(data);
        const result = await db
          .prepare(
            `INSERT INTO ${table}
              (id, user_id, meta, data, expires_at, created_at, last_seen_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
          )
          .bind(
            record.meta.id,
            record.meta.userId ?? null,
            meta,
            data,
            record.meta.expiresAt,
            record.meta.createdAt,
            record.meta.lastSeenAt,
          )
          .run();
        if (!result.success) {
          throw new SessionError('CONFLICT', 'session id collision');
        }
      }, 'create');
    },

    async read(id) {
      return wrap(async () => {
        const row = await db
          .prepare(
            `SELECT meta, data FROM ${table}
              WHERE id = ?1 AND expires_at > ?2 LIMIT 1`,
          )
          .bind(id, clock())
          .first<{ meta: string; data: string }>();
        if (!row) return null;
        return parseRow<T>(row);
      }, 'read');
    },

    async update(record) {
      return wrap(async () => {
        const meta = JSON.stringify(record.meta);
        const data = JSON.stringify(record.data);
        guardSize(meta);
        guardSize(data);
        const result = await db
          .prepare(
            `UPDATE ${table} SET
                user_id = ?2,
                meta = ?3,
                data = ?4,
                expires_at = ?5,
                last_seen_at = ?6
              WHERE id = ?1`,
          )
          .bind(
            record.meta.id,
            record.meta.userId ?? null,
            meta,
            data,
            record.meta.expiresAt,
            record.meta.lastSeenAt,
          )
          .run();
        return (result.meta?.changes ?? 0) > 0;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const result = await db.prepare(`DELETE FROM ${table} WHERE id = ?1`).bind(id).run();
        return (result.meta?.changes ?? 0) > 0;
      }, 'delete');
    },

    async listByUser(userId) {
      return wrap(async () => {
        const rows = await db
          .prepare(
            `SELECT meta FROM ${table}
              WHERE user_id = ?1 AND expires_at > ?2
              ORDER BY last_seen_at DESC`,
          )
          .bind(userId, clock())
          .all<{ meta: string }>();
        const out: SessionMetadata[] = [];
        for (const row of rows.results ?? []) {
          const meta = parseMetadataBlob(row.meta);
          if (meta) out.push(meta);
        }
        return out;
      }, 'listByUser');
    },

    async deleteByUser(userId) {
      return wrap(async () => {
        const result = await db
          .prepare(`DELETE FROM ${table} WHERE user_id = ?1`)
          .bind(userId)
          .run();
        return result.meta?.changes ?? 0;
      }, 'deleteByUser');
    },

    async sweep(now) {
      return wrap(async () => {
        const cutoff = now ?? clock();
        const result = await db
          .prepare(`DELETE FROM ${table} WHERE expires_at <= ?1`)
          .bind(cutoff)
          .run();
        return result.meta?.changes ?? 0;
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
  meta: string;
  data: string;
}): SessionRecord<T> | null {
  const meta = parseMetadataBlob(row.meta);
  if (!meta) return null;
  let data: unknown;
  try {
    data = JSON.parse(row.data);
  } catch {
    return null;
  }
  // Schema-validated: meta passes structural checks, data is the
  // user payload of declared shape `T`.
  return { meta, data: data as T };
}
