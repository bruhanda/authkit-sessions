import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  base64urlDecode,
  base64urlDecodeString,
  base64urlEncode,
  base64urlEncodeString,
} from '../utils/base64url.js';

describe('base64urlEncode', () => {
  it('should produce URL-safe alphabet without padding when encoding bytes', () => {
    const out = base64urlEncode(new Uint8Array([1, 2, 3]));
    expect(out).toBe('AQID');
    expect(out).not.toMatch(/[+/=]/);
  });

  it('should encode an empty array to an empty string', () => {
    expect(base64urlEncode(new Uint8Array(0))).toBe('');
  });

  it('should round-trip arbitrary bytes when paired with decode', () => {
    const bytes = new Uint8Array([0, 255, 128, 64, 32, 16, 8, 4, 2, 1, 250, 251, 252]);
    const encoded = base64urlEncode(bytes);
    expect(base64urlDecode(encoded)).toEqual(bytes);
  });

  it('should encode payloads larger than the 0x8000 chunk threshold without RangeError', () => {
    const bytes = new Uint8Array(0x8000 * 3 + 17);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i % 256;
    const encoded = base64urlEncode(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(base64urlDecode(encoded)).toEqual(bytes);
  });

  it('should not contain `+`, `/`, or `=` for inputs that would yield them in standard base64', () => {
    const bytes = new Uint8Array([0xff, 0xff, 0xff]);
    const encoded = base64urlEncode(bytes);
    expect(encoded).toBe('____');
  });

  it('should accept Uint8Array typed inputs', () => {
    expectTypeOf(base64urlEncode).parameter(0).toEqualTypeOf<Uint8Array>();
    expectTypeOf(base64urlEncode).returns.toEqualTypeOf<string>();
  });
});

describe('base64urlDecode', () => {
  it('should decode a string back to the original bytes', () => {
    expect(base64urlDecode('AQID')).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('should accept input that needs padding to align to a 4-char boundary', () => {
    // 'AQI' encodes [1, 2] but is 3 chars long; the function must add `=` to align.
    expect(base64urlDecode('AQI')).toEqual(new Uint8Array([1, 2]));
  });

  it('should accept input with `-` and `_` instead of `+` and `/`', () => {
    expect(base64urlDecode('____')).toEqual(new Uint8Array([0xff, 0xff, 0xff]));
  });

  it('should return an empty array when given an empty string', () => {
    expect(base64urlDecode('')).toEqual(new Uint8Array(0));
  });
});

describe('base64urlEncodeString', () => {
  it('should encode an ASCII string to base64url', () => {
    expect(base64urlEncodeString('hi')).toBe('aGk');
  });

  it('should round-trip a unicode string when paired with the decoder', () => {
    const input = 'héllo 🌍 ünïcödé';
    expect(base64urlDecodeString(base64urlEncodeString(input))).toBe(input);
  });
});

describe('base64urlDecodeString', () => {
  it('should decode the canonical encoding back to the original UTF-8 string', () => {
    expect(base64urlDecodeString('aGk')).toBe('hi');
  });
});
