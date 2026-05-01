import { sign, verifyAny } from '../crypto/hmac.js';
import { SessionError } from '../errors/base.js';
import type { Device } from '../types/device.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../types/session.js';
import type { SessionStore } from '../types/store.js';
import { base64urlDecode, base64urlEncode } from '../utils/base64url.js';
import { generateCsrfToken, generateSessionId } from './id.js';

/**
 * The opaque cookie value carried for stateful stores has the form
 *
 *     <session-id> '.' <hmac-tag>
 *
 * where the HMAC is computed over the UTF-8 bytes of the id with the
 * derived signing key. Encrypting the id would buy nothing — the id by
 * itself reveals nothing about the session content, which lives
 * server-side.
 */

const SEPARATOR = '.';

/**
 * Sign an opaque session id into the cookie value.
 *
 * @param id      Bare session id (43-char base64url).
 * @param sigKey  Derived HMAC-SHA256 key.
 * @returns Cookie value of the form `id.tag`.
 *
 * @example
 *   const cookie = signSessionId(meta.id, sigKey);
 */
export function signSessionId(id: string, sigKey: Uint8Array): string {
  const tag = sign(sigKey, new TextEncoder().encode(id));
  return `${id}${SEPARATOR}${base64urlEncode(tag)}`;
}

/**
 * Verify a `id.tag` cookie value against every accepted key. Returns
 * the bare session id on success, or `null` on any failure (malformed
 * input, bad tag).
 *
 * @param value   Raw cookie value.
 * @param sigKeys Candidate signing keys (freshest first).
 * @returns Bare session id, or `null` on failure.
 *
 * @example
 *   const id = verifySessionId(cookie, allSigKeys);
 *   if (!id) return null;
 */
export function verifySessionId(value: string, sigKeys: readonly Uint8Array[]): string | null {
  const sep = value.indexOf(SEPARATOR);
  if (sep <= 0 || sep === value.length - 1) return null;
  const id = value.slice(0, sep);
  const tagB64 = value.slice(sep + 1);
  let tag: Uint8Array;
  try {
    tag = base64urlDecode(tagB64);
  } catch {
    return null;
  }
  return verifyAny(sigKeys, new TextEncoder().encode(id), tag) ? id : null;
}

/**
 * Mint fresh metadata for a new session.
 *
 * @param now             Current Unix seconds.
 * @param absoluteSeconds Absolute lifetime cap.
 * @param slidingSeconds  Sliding window length.
 * @param userId          Optional user binding from `getUserId`.
 * @param device          Optional captured device.
 * @returns A fresh `SessionMetadata`.
 *
 * @example
 *   const meta = mintMetadata(now, 86400 * 30, 86400 * 7, userId);
 */
export function mintMetadata(
  now: number,
  absoluteSeconds: number,
  slidingSeconds: number,
  userId: string | undefined,
  device: Device | undefined,
): SessionMetadata {
  const slidingExp = slidingSeconds > 0 ? now + slidingSeconds : now + absoluteSeconds;
  const meta: SessionMetadata = {
    id: generateSessionId(),
    ...(userId !== undefined ? { userId } : {}),
    createdAt: now,
    lastSeenAt: now,
    expiresAt: Math.min(slidingExp, now + absoluteSeconds),
    ...(device !== undefined ? { device } : {}),
    csrf: generateCsrfToken(),
    v: 1,
  };
  return meta;
}

/**
 * Persist a freshly-minted record, retrying once on `CONFLICT`. The
 * collision probability for a 256-bit id is negligible, but a defensive
 * retry costs nothing and protects against bad RNG in future runtimes.
 *
 * @param store   Session store.
 * @param record  Record to write.
 * @returns The same record on success; throws `CONFLICT` after one retry.
 * @throws {SessionError}
 *
 * @example
 *   await persistWithRetry(store, record);
 */
export async function persistWithRetry<T extends SessionData>(
  store: SessionStore<T>,
  record: SessionRecord<T>,
  mintReplacement: () => SessionRecord<T>,
): Promise<SessionRecord<T>> {
  try {
    await store.create(record);
    return record;
  } catch (err) {
    if (SessionError.is(err) && err.code === 'CONFLICT') {
      const retry = mintReplacement();
      await store.create(retry);
      return retry;
    }
    throw err;
  }
}
