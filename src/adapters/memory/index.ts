import { nowSeconds } from '../../core/time.js';
import { SessionError } from '../../errors/base.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../../types/session.js';
import type { SessionStore } from '../../types/store.js';

const DEFAULT_MAX_RECORDS = 10_000;

/**
 * Defensive clone — `read()` returns a copy of the stored record so
 * callers cannot mutate `record.data` through the back door. The
 * `readonly` types prevent mutation at compile time but not at
 * runtime, and tests / examples that do `record.data.x = 1` would
 * silently corrupt the in-memory store.
 *
 * Uses `structuredClone` when present (Node 17+, Bun, Deno, modern
 * browsers, Cloudflare Workers); falls back to `JSON.parse(JSON.stringify(...))`
 * elsewhere — the records we store are JSON-safe by construction
 * (no functions, no cycles, no Maps/Sets).
 */
const cloneRecord = <T extends SessionData>(record: SessionRecord<T>): SessionRecord<T> => {
  if (typeof structuredClone === 'function') return structuredClone(record);
  return JSON.parse(JSON.stringify(record)) as SessionRecord<T>;
};

interface MemoryEntry<T extends SessionData> {
  record: SessionRecord<T>;
  /** Insertion order — proxy for LRU eviction. Updated on every read. */
  touchOrder: number;
}

/**
 * In-memory session store. **Test/dev only.**
 *
 * The constructor returning a `SessionStore` is the explicit signal "I
 * know what I am doing, this is a test or single-process dev". The
 * `SessionConfig.store` field is required, so production deployments
 * cannot fall through to this adapter by accident — picking the wrong
 * store is a TypeScript error, not a runtime guess.
 *
 * @typeParam T  Session payload shape.
 * @param opts.maxRecords  Hard cap on stored sessions; oldest LRU entries
 *                         are evicted past it. Default 10 000.
 * @returns A `SessionStore` backed by an in-process `Map`.
 *
 * @example
 *   import { createMemoryStore } from '@authkit/sessions/adapters/memory';
 *   const sessions = createSessionManager({ secrets: [SECRET], store: createMemoryStore() });
 */
export function createMemoryStore<T extends SessionData = SessionData>(
  opts: { maxRecords?: number; clock?: () => number } = {},
): SessionStore<T> {
  const maxRecords = opts.maxRecords ?? DEFAULT_MAX_RECORDS;
  const clock = opts.clock ?? nowSeconds;
  const records = new Map<string, MemoryEntry<T>>();
  const userIndex = new Map<string, Set<string>>();
  let counter = 0;

  const indexOf = (userId: string): Set<string> => {
    let bucket = userIndex.get(userId);
    if (!bucket) {
      bucket = new Set();
      userIndex.set(userId, bucket);
    }
    return bucket;
  };

  const evictIfNeeded = (): void => {
    if (records.size <= maxRecords) return;
    const overflow = records.size - maxRecords;
    const ordered = [...records.entries()].sort(
      (a, b) => a[1].touchOrder - b[1].touchOrder,
    );
    for (let i = 0; i < overflow; i++) {
      const entry = ordered[i];
      if (!entry) break;
      const [id, e] = entry;
      records.delete(id);
      if (e.record.meta.userId !== undefined) {
        userIndex.get(e.record.meta.userId)?.delete(id);
      }
    }
  };

  const expired = (meta: SessionMetadata, now: number): boolean => meta.expiresAt < now;

  return {
    async create(record) {
      if (records.has(record.meta.id)) {
        throw new SessionError('CONFLICT', 'session id collision');
      }
      records.set(record.meta.id, { record: cloneRecord(record), touchOrder: ++counter });
      if (record.meta.userId !== undefined) {
        indexOf(record.meta.userId).add(record.meta.id);
      }
      evictIfNeeded();
    },

    async read(id) {
      const entry = records.get(id);
      if (!entry) return null;
      const now = clock();
      if (expired(entry.record.meta, now)) {
        records.delete(id);
        if (entry.record.meta.userId !== undefined) {
          userIndex.get(entry.record.meta.userId)?.delete(id);
        }
        return null;
      }
      entry.touchOrder = ++counter;
      return cloneRecord(entry.record);
    },

    async update(record) {
      const existing = records.get(record.meta.id);
      if (!existing) return false;
      const oldUserId = existing.record.meta.userId;
      const newUserId = record.meta.userId;
      records.set(record.meta.id, { record: cloneRecord(record), touchOrder: ++counter });
      if (oldUserId !== newUserId) {
        if (oldUserId !== undefined) userIndex.get(oldUserId)?.delete(record.meta.id);
        if (newUserId !== undefined) indexOf(newUserId).add(record.meta.id);
      }
      return true;
    },

    async delete(id) {
      const entry = records.get(id);
      if (!entry) return false;
      records.delete(id);
      if (entry.record.meta.userId !== undefined) {
        userIndex.get(entry.record.meta.userId)?.delete(id);
      }
      return true;
    },

    async listByUser(userId) {
      const bucket = userIndex.get(userId);
      if (!bucket) return [];
      const now = clock();
      const out: SessionMetadata[] = [];
      for (const id of bucket) {
        const entry = records.get(id);
        if (entry && !expired(entry.record.meta, now)) out.push(entry.record.meta);
      }
      return out;
    },

    async deleteByUser(userId) {
      const bucket = userIndex.get(userId);
      if (!bucket) return 0;
      let removed = 0;
      for (const id of bucket) {
        if (records.delete(id)) removed++;
      }
      userIndex.delete(userId);
      return removed;
    },

    async sweep(now) {
      const cutoff = now ?? clock();
      let removed = 0;
      for (const [id, entry] of records) {
        if (expired(entry.record.meta, cutoff)) {
          records.delete(id);
          if (entry.record.meta.userId !== undefined) {
            userIndex.get(entry.record.meta.userId)?.delete(id);
          }
          removed++;
        }
      }
      return removed;
    },
  };
}
