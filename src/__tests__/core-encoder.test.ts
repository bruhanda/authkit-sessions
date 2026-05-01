import { describe, expect, it } from 'vitest';
import {
  decodeRecord,
  encodeRecord,
  encodeRecordBounded,
  parseMetadataBlob,
} from '../core/encoder.js';
import { SessionError } from '../errors/base.js';
import type { SessionRecord } from '../types/session.js';

const validRecord: SessionRecord<{ user: string }> = {
  meta: {
    id: 'a'.repeat(43),
    userId: 'user_42',
    createdAt: 1_700_000_000,
    lastSeenAt: 1_700_000_100,
    expiresAt: 1_700_086_400,
    csrf: 'b'.repeat(43),
    v: 1,
  },
  data: { user: 'alice' },
};

describe('encodeRecord', () => {
  it('should produce a base64url string with no padding or non-URL chars', () => {
    const blob = encodeRecord(validRecord);
    expect(blob).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should round-trip through decodeRecord preserving meta and data', () => {
    const blob = encodeRecord(validRecord);
    const decoded = decodeRecord<{ user: string }>(blob);
    expect(decoded).not.toBeNull();
    expect(decoded?.meta.id).toBe(validRecord.meta.id);
    expect(decoded?.meta.csrf).toBe(validRecord.meta.csrf);
    expect(decoded?.meta.v).toBe(1);
    expect(decoded?.data).toEqual({ user: 'alice' });
  });
});

describe('decodeRecord', () => {
  it('should return null for malformed base64url', () => {
    expect(decodeRecord('!!! not base64 !!!')).toBeNull();
  });

  it('should return null when the JSON is malformed', () => {
    const blob = btoa('not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeRecord(blob)).toBeNull();
  });

  it('should return null when v is not 1', () => {
    const envelope = JSON.stringify({ v: 2, meta: validRecord.meta, data: validRecord.data });
    const blob = btoa(envelope).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeRecord(blob)).toBeNull();
  });

  it('should return null when meta is missing required fields', () => {
    const broken = { v: 1, meta: { id: 'x', v: 1 }, data: {} };
    const blob = btoa(JSON.stringify(broken)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeRecord(blob)).toBeNull();
  });

  it('should return null when data is undefined', () => {
    const broken = { v: 1, meta: validRecord.meta };
    const blob = btoa(JSON.stringify(broken)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(decodeRecord(blob)).toBeNull();
  });

  it('should accept records with empty data objects', () => {
    const r: SessionRecord<Record<string, unknown>> = {
      meta: validRecord.meta,
      data: {},
    };
    const decoded = decodeRecord(encodeRecord(r));
    expect(decoded?.data).toEqual({});
  });
});

describe('parseMetadataBlob', () => {
  it('should parse a JSON string blob into SessionMetadata', () => {
    const meta = parseMetadataBlob(JSON.stringify(validRecord.meta));
    expect(meta?.id).toBe(validRecord.meta.id);
  });

  it('should accept an already-parsed object (Postgres jsonb path)', () => {
    expect(parseMetadataBlob(validRecord.meta)?.expiresAt).toBe(validRecord.meta.expiresAt);
  });

  it('should return null on malformed JSON', () => {
    expect(parseMetadataBlob('{ not json')).toBeNull();
  });

  it('should return null when expiresAt is missing', () => {
    const broken = { ...validRecord.meta } as Partial<typeof validRecord.meta>;
    delete broken.expiresAt;
    expect(parseMetadataBlob(broken)).toBeNull();
  });

  it('should return null when csrf is missing', () => {
    const { csrf: _csrf, ...rest } = validRecord.meta;
    expect(parseMetadataBlob(rest)).toBeNull();
  });

  it('should return null when v is not 1', () => {
    expect(parseMetadataBlob({ ...validRecord.meta, v: 2 })).toBeNull();
  });

  it('should return null on null input', () => {
    expect(parseMetadataBlob(null)).toBeNull();
  });

  it('should return null on undefined input', () => {
    expect(parseMetadataBlob(undefined)).toBeNull();
  });

  it('should return null on numeric input', () => {
    expect(parseMetadataBlob(42)).toBeNull();
  });
});

describe('encodeRecordBounded', () => {
  it('should return the encoded blob when below the ceiling', () => {
    const blob = encodeRecordBounded(validRecord, 4096);
    expect(typeof blob).toBe('string');
  });

  it('should throw PAYLOAD_TOO_LARGE when over the ceiling', () => {
    expect(() => encodeRecordBounded(validRecord, 16)).toThrowError(SessionError);
    try {
      encodeRecordBounded(validRecord, 16);
    } catch (err) {
      expect((err as SessionError).code).toBe('PAYLOAD_TOO_LARGE');
    }
  });
});
