import type { Device } from './device.js';

/**
 * Marker base for the user-supplied session payload. Library-internal
 * metadata lives on `SessionMetadata`, never on `SessionData`, so user
 * code cannot accidentally clobber it.
 */
export type SessionData = Record<string, unknown>;

/**
 * Engine-managed metadata stored alongside every session.
 *
 * Every field is `readonly` from the consumer's perspective — mutations go
 * through `manager.update` / `manager.rotate`, which mint a fresh record.
 */
export interface SessionMetadata {
  /** Opaque session identifier — 32 random bytes, base64url-encoded (43 chars). */
  readonly id: string;
  /** Optional user binding. Required for `revokeByUser` and `concurrency`. */
  readonly userId?: string;
  /** Unix seconds when the session was created. Never updated — see `lastSeenAt`. */
  readonly createdAt: number;
  /** Unix seconds of the most recent successful read; drives sliding expiration. */
  readonly lastSeenAt: number;
  /** Unix seconds when the session expires (absolute cap — never extended past it). */
  readonly expiresAt: number;
  /** Captured device — present iff `fingerprint` is enabled. */
  readonly device?: Device;
  /** Per-session CSRF token; rotated together with `id` on rotate(). */
  readonly csrf: string;
  /**
   * Set by `manager.get` when a rotation condition fired during a read
   * (`rotateAfterSeconds` elapsed, or fingerprint mismatch with
   * `onMismatch: 'rotate'`). The next `update` / `rotate` mutation
   * consumes the flag and mints a fresh `id` + `csrf`. Inline-rotating
   * on read would orphan the browser cookie because read paths cannot
   * emit `Set-Cookie` — the deferred consume keeps the round-trip
   * sound.
   */
  readonly rotatePending?: boolean;
  /** Envelope schema version — read-only, used for forward compatibility. */
  readonly v: 1;
}

/**
 * The full session record stored in the backing adapter. Splits the
 * library-managed `meta` from the user-managed `data`.
 */
export interface SessionRecord<T extends SessionData> {
  readonly meta: SessionMetadata;
  readonly data: T;
}
