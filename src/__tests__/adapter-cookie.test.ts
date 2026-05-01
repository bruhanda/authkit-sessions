import { describe, expect, it } from 'vitest';
import { createCookieCodec, createCookieStore } from '../adapters/cookie/index.js';
import { DEFAULT_COOKIE_MAX_BYTES, guardCookieSize } from '../adapters/cookie/compact.js';
import { openRecord, sealRecord } from '../adapters/cookie/seal.js';
import { deriveEncKey } from '../crypto/kdf.js';
import { mintMetadata } from '../core/lifecycle.js';
import { nowSeconds } from '../core/time.js';
import { SessionError } from '../errors/base.js';
import type { SessionRecord } from '../types/session.js';
import { ALT_SECRET, SECRET } from './_helpers.js';

interface Data extends Record<string, unknown> {
  user: string;
}

const buildRecord = (data: Data = { user: 'alice' }): SessionRecord<Data> => ({
  meta: mintMetadata(nowSeconds(), 86_400, 3_600, 'u', undefined),
  data,
});

describe('createCookieCodec', () => {
  it('should round-trip a record through encode/decode', () => {
    const codec = createCookieCodec<Data>({ secrets: SECRET });
    const r = buildRecord();
    const cookie = codec.encode(r);
    const decoded = codec.decode(cookie);
    expect(decoded?.data.user).toBe('alice');
    expect(decoded?.meta.id).toBe(r.meta.id);
  });

  it('should accept multiple secrets and decrypt with any', () => {
    const old = createCookieCodec<Data>({ secrets: ALT_SECRET });
    const r = buildRecord();
    const cookie = old.encode(r);
    const fresh = createCookieCodec<Data>({ secrets: [SECRET, ALT_SECRET] });
    expect(fresh.decode(cookie)?.data.user).toBe('alice');
  });

  it('should return null when decoding a tampered cookie', () => {
    const codec = createCookieCodec<Data>({ secrets: SECRET });
    const cookie = codec.encode(buildRecord());
    const tampered = cookie.slice(0, -1) + (cookie.endsWith('A') ? 'B' : 'A');
    expect(codec.decode(tampered)).toBeNull();
  });

  it('should return null when decoding gibberish', () => {
    const codec = createCookieCodec<Data>({ secrets: SECRET });
    expect(codec.decode('!!! not base64 !!!')).toBeNull();
  });

  it('should throw SECRET_TOO_SHORT for short secrets', () => {
    expect(() => createCookieCodec({ secrets: 'short' })).toThrowError(SessionError);
  });

  it('should throw CONFIG_INVALID when given an empty secrets array', () => {
    expect(() => createCookieCodec({ secrets: [] })).toThrowError(/at least one secret/);
  });

  it('should throw PAYLOAD_TOO_LARGE when encoded record exceeds maxBytes', () => {
    const codec = createCookieCodec<Data>({ secrets: SECRET, maxBytes: 16 });
    expect(() => codec.encode(buildRecord())).toThrowError(/PAYLOAD_TOO_LARGE|ceiling/);
  });

  it('should accept a single Uint8Array secret', () => {
    const codec = createCookieCodec<Data>({ secrets: new Uint8Array(32).fill(7) });
    const cookie = codec.encode(buildRecord());
    expect(codec.decode(cookie)).not.toBeNull();
  });
});

describe('createCookieStore (no-op stub)', () => {
  it('should return null from read', async () => {
    const store = createCookieStore();
    expect(await store.read('any')).toBeNull();
  });

  it('should be a no-op for create', async () => {
    const store = createCookieStore();
    await expect(store.create({} as never)).resolves.toBeUndefined();
  });

  it('should return true from update (no-op success)', async () => {
    const store = createCookieStore();
    expect(await store.update({} as never)).toBe(true);
  });

  it('should return true from delete', async () => {
    const store = createCookieStore();
    expect(await store.delete('id')).toBe(true);
  });

  it('should return [] from listByUser', async () => {
    const store = createCookieStore();
    expect(await store.listByUser('u')).toEqual([]);
  });

  it('should return 0 from deleteByUser', async () => {
    const store = createCookieStore();
    expect(await store.deleteByUser('u')).toBe(0);
  });
});

describe('guardCookieSize', () => {
  it('should pass when value is below the ceiling', () => {
    expect(() => guardCookieSize('x', 100)).not.toThrow();
  });

  it('should throw PAYLOAD_TOO_LARGE when over the ceiling', () => {
    expect(() => guardCookieSize('x'.repeat(200), 100)).toThrowError(SessionError);
  });

  it('should expose a default ceiling of 3072', () => {
    expect(DEFAULT_COOKIE_MAX_BYTES).toBe(3072);
  });
});

describe('seal/openRecord helpers', () => {
  const KEY = deriveEncKey(new Uint8Array(32).fill(7));

  it('should round-trip a record', () => {
    const r = buildRecord();
    const sealed = sealRecord(r, KEY);
    const out = openRecord<Data>(sealed, [KEY]);
    expect(out?.data.user).toBe('alice');
  });

  it('should return null for malformed base64', () => {
    expect(openRecord('!!!', [KEY])).toBeNull();
  });

  it('should return null when no key matches', () => {
    const r = buildRecord();
    const sealed = sealRecord(r, deriveEncKey(new Uint8Array(32).fill(8)));
    expect(openRecord(sealed, [KEY])).toBeNull();
  });
});
