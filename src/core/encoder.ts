import { SessionError } from '../errors/base.js';
import type { SessionData, SessionMetadata, SessionRecord } from '../types/session.js';
import { base64urlDecodeString, base64urlEncodeString } from '../utils/base64url.js';

/**
 * Forward-compatible JSON+base64url envelope used by the cookie store
 * and by tests / debug tooling that need a stable on-the-wire format.
 *
 * The envelope carries a SemVer tag (`v: 1`) at the outermost layer; a
 * future v2 format ships a one-shot migration helper that decodes both.
 */

interface EnvelopeShape<T> {
  readonly v: 1;
  readonly meta: unknown;
  readonly data: T;
}

/**
 * Encode a record to a base64url-wrapped JSON string. The envelope is
 * a deterministic representation of the input — `JSON.stringify` ordering
 * is undefined for objects, but the format is forward-compatible because
 * decoders parse on field names.
 *
 * @param record  Session record.
 * @returns base64url-encoded UTF-8 JSON string.
 *
 * @example
 *   const blob = encodeRecord(record);
 */
export function encodeRecord<T extends SessionData>(record: SessionRecord<T>): string {
  const envelope: EnvelopeShape<T> = { v: 1, meta: record.meta, data: record.data };
  return base64urlEncodeString(JSON.stringify(envelope));
}

/**
 * Reverse of `encodeRecord`. Returns `null` on any structural failure;
 * the manager treats that indistinguishably from a missing record.
 *
 * @typeParam T  Expected payload shape.
 * @param blob  base64url-encoded envelope.
 * @returns Decoded record, or `null` when the input is malformed.
 *
 * @example
 *   const record = decodeRecord<MySession>(blob);
 */
export function decodeRecord<T extends SessionData>(blob: string): SessionRecord<T> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(base64urlDecodeString(blob));
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== 'object') return null;
  const env = parsed as { v?: unknown; meta?: unknown; data?: unknown };
  if (env.v !== 1) return null;
  if (!isMeta(env.meta) || env.data === undefined) return null;

  // Cast at the boundary only — the envelope contract guarantees the
  // shape, but TypeScript cannot statically verify deserialised JSON.
  // This is the single sanctioned `as` cast in core/encoder.ts (per the
  // §3.3 architecture rule).
  return { meta: env.meta, data: env.data as T };
}

function isMeta(value: unknown): value is SessionRecord<SessionData>['meta'] {
  if (!value || typeof value !== 'object') return false;
  const m = value as Record<string, unknown>;
  return (
    typeof m['id'] === 'string' &&
    typeof m['createdAt'] === 'number' &&
    typeof m['lastSeenAt'] === 'number' &&
    typeof m['expiresAt'] === 'number' &&
    typeof m['csrf'] === 'string' &&
    m['v'] === 1
  );
}

/**
 * Adapter-side helper: parse a metadata blob (JSON string OR a parsed
 * object — Postgres `jsonb` deserialises as the latter) and validate
 * every field every consumer of `SessionMetadata` relies on. A
 * corrupted blob with a missing `expiresAt` or `csrf` would silently
 * round-trip through a per-adapter `parseMeta` that only checked `id`
 * and trip the manager later; this helper is the single source of
 * truth so all adapters reject malformed records identically.
 *
 * @param value  String or already-parsed object from the backing store.
 * @returns Validated metadata, or `null` on any structural failure.
 *
 * @example
 *   const meta = parseMetadataBlob(rawValueFromRedis);
 */
export function parseMetadataBlob(value: unknown): SessionMetadata | null {
  let parsed: unknown = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  if (!isMeta(parsed)) return null;
  return parsed;
}

/**
 * Encode a record and assert it fits within `maxBytes`. Used by the
 * cookie store to fail loudly when a payload would overflow the 4 KB
 * browser cookie ceiling.
 *
 * @param record    Session record.
 * @param maxBytes  Hard ceiling on the encoded length.
 * @returns Encoded string.
 * @throws {SessionError} `PAYLOAD_TOO_LARGE` when the encoded length exceeds the ceiling.
 *
 * @example
 *   const blob = encodeRecordBounded(record, 3072);
 */
export function encodeRecordBounded<T extends SessionData>(
  record: SessionRecord<T>,
  maxBytes: number,
): string {
  const blob = encodeRecord(record);
  if (blob.length > maxBytes) {
    throw new SessionError(
      'PAYLOAD_TOO_LARGE',
      `encoded session is ${blob.length} bytes; ceiling is ${maxBytes}`,
    );
  }
  return blob;
}
