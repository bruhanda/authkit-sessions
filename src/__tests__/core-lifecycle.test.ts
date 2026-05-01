import { describe, expect, it } from 'vitest';
import { deriveSigKey } from '../crypto/kdf.js';
import {
  mintMetadata,
  persistWithRetry,
  signSessionId,
  verifySessionId,
} from '../core/lifecycle.js';
import { SessionError } from '../errors/base.js';
import type { SessionRecord } from '../types/session.js';
import type { SessionStore } from '../types/store.js';

const SIG_KEY = deriveSigKey(new Uint8Array(32).fill(7));
const ALT_SIG_KEY = deriveSigKey(new Uint8Array(32).fill(8));

describe('signSessionId / verifySessionId', () => {
  it('should round-trip the id through sign+verify', () => {
    const id = 'a'.repeat(43);
    const cookie = signSessionId(id, SIG_KEY);
    expect(verifySessionId(cookie, [SIG_KEY])).toBe(id);
  });

  it('should return null for missing separator', () => {
    expect(verifySessionId('no-separator-here', [SIG_KEY])).toBeNull();
  });

  it('should return null when separator is at the start', () => {
    expect(verifySessionId('.tag', [SIG_KEY])).toBeNull();
  });

  it('should return null when separator is at the end', () => {
    expect(verifySessionId('id.', [SIG_KEY])).toBeNull();
  });

  it('should return null for tampered tag', () => {
    const id = 'a'.repeat(43);
    const cookie = signSessionId(id, SIG_KEY);
    const tampered = cookie.slice(0, -1) + (cookie.endsWith('A') ? 'B' : 'A');
    expect(verifySessionId(tampered, [SIG_KEY])).toBeNull();
  });

  it('should return null for unknown signing key', () => {
    const cookie = signSessionId('a'.repeat(43), ALT_SIG_KEY);
    expect(verifySessionId(cookie, [SIG_KEY])).toBeNull();
  });

  it('should accept any rotated key', () => {
    const cookie = signSessionId('a'.repeat(43), ALT_SIG_KEY);
    expect(verifySessionId(cookie, [SIG_KEY, ALT_SIG_KEY])).toBe('a'.repeat(43));
  });

  it('should return null for non-base64url tag', () => {
    expect(verifySessionId('id.@@@@', [SIG_KEY])).toBeNull();
  });
});

describe('mintMetadata', () => {
  it('should set createdAt and lastSeenAt to now', () => {
    const meta = mintMetadata(1_000, 86_400, 3_600, undefined, undefined);
    expect(meta.createdAt).toBe(1_000);
    expect(meta.lastSeenAt).toBe(1_000);
  });

  it('should compute expiresAt as min(now+sliding, now+absolute)', () => {
    const meta = mintMetadata(1_000, 100, 50, undefined, undefined);
    expect(meta.expiresAt).toBe(1_050);
  });

  it('should compute expiresAt = now+absolute when sliding > absolute', () => {
    const meta = mintMetadata(1_000, 100, 1_000, undefined, undefined);
    expect(meta.expiresAt).toBe(1_100);
  });

  it('should compute expiresAt = now+absolute when slidingSeconds <= 0', () => {
    const meta = mintMetadata(1_000, 200, 0, undefined, undefined);
    expect(meta.expiresAt).toBe(1_200);
  });

  it('should attach userId when provided', () => {
    const meta = mintMetadata(1_000, 100, 50, 'user_42', undefined);
    expect(meta.userId).toBe('user_42');
  });

  it('should attach device when provided', () => {
    const dev = { hash: 'h', firstSeenAt: 1, lastSeenAt: 1 };
    const meta = mintMetadata(1_000, 100, 50, undefined, dev);
    expect(meta.device).toEqual(dev);
  });

  it('should set v=1 and produce a 43-char id and csrf', () => {
    const meta = mintMetadata(1_000, 100, 50, undefined, undefined);
    expect(meta.v).toBe(1);
    expect(meta.id.length).toBe(43);
    expect(meta.csrf.length).toBe(43);
  });
});

describe('persistWithRetry', () => {
  const buildStore = (createImpl: SessionStore['create']): SessionStore => ({
    create: createImpl,
    read: async () => null,
    update: async () => false,
    delete: async () => false,
    listByUser: async () => [],
    deleteByUser: async () => 0,
  });
  const baseRecord: SessionRecord<Record<string, unknown>> = {
    meta: {
      id: 'orig'.padEnd(43, 'a'),
      createdAt: 1,
      lastSeenAt: 1,
      expiresAt: 100,
      csrf: 'c'.repeat(43),
      v: 1,
    },
    data: {},
  };

  it('should write the record on the first try and return it', async () => {
    let written: SessionRecord<Record<string, unknown>> | undefined;
    const store = buildStore(async (r) => {
      written = r;
    });
    const out = await persistWithRetry(store, baseRecord, () => baseRecord);
    expect(out).toBe(baseRecord);
    expect(written).toBe(baseRecord);
  });

  it('should retry once on CONFLICT and use the replacement', async () => {
    let calls = 0;
    const replacement = {
      ...baseRecord,
      meta: { ...baseRecord.meta, id: 'replaced'.padEnd(43, 'a') },
    };
    const store = buildStore(async () => {
      calls++;
      if (calls === 1) throw new SessionError('CONFLICT', 'collision');
    });
    const out = await persistWithRetry(store, baseRecord, () => replacement);
    expect(calls).toBe(2);
    expect(out).toBe(replacement);
  });

  it('should propagate non-CONFLICT errors without retrying', async () => {
    let calls = 0;
    const store = buildStore(async () => {
      calls++;
      throw new SessionError('STORE_UNAVAILABLE', 'down');
    });
    await expect(persistWithRetry(store, baseRecord, () => baseRecord)).rejects.toThrowError(
      SessionError,
    );
    expect(calls).toBe(1);
  });

  it('should propagate a CONFLICT thrown on the second attempt', async () => {
    const store = buildStore(async () => {
      throw new SessionError('CONFLICT', 'collision');
    });
    await expect(persistWithRetry(store, baseRecord, () => baseRecord)).rejects.toThrowError(
      /collision/,
    );
  });
});
