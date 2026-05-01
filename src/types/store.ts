import type { SessionData, SessionMetadata, SessionRecord } from './session.js';

/**
 * Storage contract every adapter implements. The contract is intentionally
 * minimal — concurrency policy, expiration arithmetic and cookie handling
 * live in the manager, NOT the store.
 *
 * Naming convention: the manager **revokes**, the store **deletes**. The
 * security-flavoured verb (`revoke`) lives on the public surface; the
 * mechanical verb (`delete`) lives at the persistence layer.
 *
 * Stores SHOULD honour native TTL where the backend exposes one (Redis
 * `EXPIRE`, KV `expirationTtl`, Postgres `WHERE expires_at < now()`).
 * Stores MUST NOT extend TTL on read — the manager owns sliding
 * expiration.
 *
 * All methods are async even when the implementation is synchronous so
 * that adapters can be swapped without changing call sites.
 */
export interface SessionStore<T extends SessionData = SessionData> {
  /**
   * Atomically write a new session. MUST throw `SessionError('CONFLICT')`
   * if `record.meta.id` already exists. The collision probability for a
   * 256-bit random id is negligible — the throw is for defensive
   * programming, not a retry loop.
   *
   * @param record  The full record including the freshly-minted metadata.
   * @throws {SessionError} `CONFLICT` when the id already exists,
   *                        `STORE_UNAVAILABLE` for infrastructure errors.
   */
  create(record: SessionRecord<T>): Promise<void>;

  /**
   * Read by id. Returns `null` for missing or expired records.
   *
   * @param id  Opaque session id.
   * @returns The record, or `null` when missing/expired.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  read(id: string): Promise<SessionRecord<T> | null>;

  /**
   * Replace data and metadata of an existing session. Returns `false` if
   * the id was not found.
   *
   * @param record  The updated record (same `meta.id`).
   * @returns `true` iff a record existed and was updated.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  update(record: SessionRecord<T>): Promise<boolean>;

  /**
   * Delete a single session.
   *
   * @param id  Opaque session id.
   * @returns `true` iff something was removed.
   * @throws {SessionError} `STORE_UNAVAILABLE` for infrastructure errors.
   */
  delete(id: string): Promise<boolean>;

  /**
   * List active sessions for a user — used by the "active devices" UI and
   * the concurrency enforcer. Implementations MAY return an empty array
   * if they cannot index by user (cookie-only adapter); that disables
   * concurrency.
   *
   * @param userId  User identifier from `getUserId(data)`.
   * @returns Read-only metadata array (no `data`).
   */
  listByUser(userId: string): Promise<readonly SessionMetadata[]>;

  /**
   * Delete every session for a user. Used on password change / suspicious
   * activity / "log out everywhere".
   *
   * @param userId  User identifier from `getUserId(data)`.
   * @returns Number of sessions removed.
   */
  deleteByUser(userId: string): Promise<number>;

  /**
   * Optional bulk garbage collection of expired records. Stores with
   * native TTL (Redis, KV) typically implement this as a no-op. Stores
   * without it (Postgres, in-memory) implement a `WHERE expires_at <
   * now()` delete.
   *
   * @param now  Optional clock override (Unix seconds).
   * @returns Number of sessions removed.
   */
  sweep?(now?: number): Promise<number>;

  /**
   * Opt-in stateless cookie codec. When present, the manager carries
   * the entire `SessionRecord` inside the session cookie itself (AEAD
   * sealed) and bypasses the default opaque-id + HMAC scheme. Set ONLY
   * by the cookie adapter; user-defined stores leave it `undefined`.
   *
   * @internal
   */
  __codec?: {
    /** AEAD-seal the record into a cookie-safe string. */
    encode(record: SessionRecord<T>): string;
    /** Reverse of `encode`. Returns `null` on any auth/decoding failure. */
    decode(value: string): SessionRecord<T> | null;
  };
}
