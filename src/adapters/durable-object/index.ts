import { decodeRecord, encodeRecord } from '../../core/encoder.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

/**
 * Wire-protocol routes the adapter calls on the DO. Implement these in
 * the DO class via `fetch(req)` dispatching on `req.url` / `req.method`.
 *
 * Why a JSON-over-`fetch` protocol? Because Durable Object stubs
 * (`DurableObjectStub`) only expose a single `fetch` entry point — they
 * are HTTP-shaped from the outside.
 */
export interface DurableObjectRoutes {
  /** `PUT /sessions/:id` — body: `SessionRecord` JSON. */
  create: 'PUT';
  /** `GET /sessions/:id` — returns `SessionRecord` JSON or 404. */
  read: 'GET';
  /** `POST /sessions/:id` — body: `SessionRecord` JSON; returns 200/404. */
  update: 'POST';
  /** `DELETE /sessions/:id` — returns 200/404. */
  delete: 'DELETE';
  /** `GET /users/:userId/sessions` — returns `SessionMetadata[]` JSON. */
  list: 'GET';
  /** `DELETE /users/:userId/sessions` — returns count JSON. */
  deleteByUser: 'DELETE';
}

/**
 * Create a Durable Object-backed session store.
 *
 * Durable Objects are **strongly consistent** within a single object —
 * a `delete()` is observed by every subsequent read immediately. This
 * is the recommended Cloudflare adapter for security-sensitive
 * deployments where the eventual-consistency window of KV is
 * unacceptable.
 *
 * The DO class itself is the user's responsibility — a reference impl
 * lives in the `examples/` directory. The routes are documented on
 * `DurableObjectRoutes`; the adapter speaks JSON over `fetch`.
 *
 * @typeParam T  Session payload shape.
 * @param stub   Bound DO stub (e.g. `env.SESSIONS.get(env.SESSIONS.idFromName('singleton'))`).
 * @returns A `SessionStore` backed by the supplied DO.
 *
 * @example
 *   import { createDurableObjectStore } from '@authkit/sessions/adapters/durable-object';
 *   const stub = env.SESSIONS.get(env.SESSIONS.idFromName('singleton'));
 *   const sessions = createSessionManager({
 *     secrets: [env.SESSION_SECRET],
 *     store: createDurableObjectStore(stub),
 *   });
 */
export function createDurableObjectStore<T extends SessionData = SessionData>(
  stub: DurableObjectStub,
): SessionStore<T> {
  // The stub.fetch URL host is irrelevant to the DO routing layer; the
  // path is what the DO inspects. We pick a placeholder host for clarity.
  const base = 'https://do.local';

  const wrap = async <R>(fn: () => Promise<R>, op: string): Promise<R> => {
    try {
      return await fn();
    } catch (err) {
      if (SessionError.is(err)) throw err;
      throw new SessionError('STORE_UNAVAILABLE', `durable-object ${op} failed`, err);
    }
  };

  return {
    async create(record) {
      await wrap(async () => {
        const res = await stub.fetch(`${base}/sessions/${record.meta.id}`, {
          method: 'PUT',
          body: encodeRecord(record),
          headers: { 'content-type': 'text/plain' },
        });
        if (res.status === 409) {
          throw new SessionError('CONFLICT', 'session id collision');
        }
        if (!res.ok) {
          throw new SessionError('STORE_UNAVAILABLE', `durable-object create returned ${res.status}`);
        }
      }, 'create');
    },

    async read(id) {
      return wrap(async () => {
        const res = await stub.fetch(`${base}/sessions/${id}`, { method: 'GET' });
        if (res.status === 404) return null;
        if (!res.ok) throw new Error(`durable-object read returned ${res.status}`);
        return decodeRecord<T>(await res.text());
      }, 'read');
    },

    async update(record) {
      return wrap(async () => {
        const res = await stub.fetch(`${base}/sessions/${record.meta.id}`, {
          method: 'POST',
          body: encodeRecord(record),
          headers: { 'content-type': 'text/plain' },
        });
        if (res.status === 404) return false;
        if (!res.ok) throw new Error(`durable-object update returned ${res.status}`);
        return true;
      }, 'update');
    },

    async delete(id) {
      return wrap(async () => {
        const res = await stub.fetch(`${base}/sessions/${id}`, { method: 'DELETE' });
        if (res.status === 404) return false;
        if (!res.ok) throw new Error(`durable-object delete returned ${res.status}`);
        return true;
      }, 'delete');
    },

    async listByUser(userId) {
      return wrap(async () => {
        const res = await stub.fetch(`${base}/users/${encodeURIComponent(userId)}/sessions`, {
          method: 'GET',
        });
        if (!res.ok) throw new Error(`durable-object list returned ${res.status}`);
        const json: unknown = await res.json();
        if (!Array.isArray(json)) return [];
        return json.filter(isMeta);
      }, 'listByUser');
    },

    async deleteByUser(userId) {
      return wrap(async () => {
        const res = await stub.fetch(`${base}/users/${encodeURIComponent(userId)}/sessions`, {
          method: 'DELETE',
        });
        if (!res.ok) throw new Error(`durable-object deleteByUser returned ${res.status}`);
        const json: unknown = await res.json();
        if (typeof json === 'object' && json !== null && 'count' in json) {
          const count = (json as { count: unknown }).count;
          return typeof count === 'number' ? count : 0;
        }
        return 0;
      }, 'deleteByUser');
    },
  };
}

function isMeta(value: unknown): value is SessionMetadata {
  if (!value || typeof value !== 'object') return false;
  const m = value as Record<string, unknown>;
  return typeof m['id'] === 'string' && typeof m['createdAt'] === 'number';
}
