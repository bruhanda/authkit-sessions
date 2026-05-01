import { describe, expect, it } from 'vitest';
import {
  DEFAULT_COOKIE_OPTIONS,
  parseCookie,
  prefixedName,
  serializeCookie,
} from '../core/cookie.js';
import { SessionError } from '../errors/base.js';

describe('serializeCookie happy paths', () => {
  it('should produce a Set-Cookie line with documented defaults', () => {
    const out = serializeCookie('sid', 'abc', 3600);
    expect(out).toMatch(/^sid=abc; /);
    expect(out).toContain('Path=/');
    expect(out).toContain('Max-Age=3600');
    expect(out).toContain('SameSite=Lax');
    expect(out).toContain('Secure');
    expect(out).toContain('HttpOnly');
    expect(out).not.toContain('Domain=');
  });

  it('should clamp negative Max-Age to 0', () => {
    expect(serializeCookie('sid', 'x', -10)).toContain('Max-Age=0');
  });

  it('should floor a fractional Max-Age', () => {
    expect(serializeCookie('sid', 'x', 1.7)).toContain('Max-Age=1');
  });

  it('should include Domain when supplied with a valid label', () => {
    expect(serializeCookie('sid', 'v', 60, { domain: 'example.com' })).toContain('Domain=example.com');
  });

  it('should support an explicit __Secure- prefix', () => {
    const out = serializeCookie('sid', 'v', 60, { prefix: '__Secure-' });
    expect(out).toMatch(/^__Secure-sid=v; /);
  });

  it('should support an explicit __Host- prefix without a Domain attribute', () => {
    const out = serializeCookie('sid', 'v', 60, { prefix: '__Host-' });
    expect(out).toMatch(/^__Host-sid=v; /);
    expect(out).not.toContain('Domain=');
  });

  it('should add Partitioned when partitioned: true', () => {
    expect(serializeCookie('sid', 'v', 60, { partitioned: true })).toContain('Partitioned');
  });

  it('should not add Partitioned by default', () => {
    expect(serializeCookie('sid', 'v', 60)).not.toContain('Partitioned');
  });

  it('should drop HttpOnly when httpOnly: false', () => {
    expect(serializeCookie('sid', 'v', 60, { httpOnly: false })).not.toContain('HttpOnly');
  });

  it('should drop Secure when secure: false', () => {
    expect(serializeCookie('sid', 'v', 60, { secure: false })).not.toContain('Secure');
  });
});

describe('serializeCookie validation', () => {
  it('should throw CONFIG_INVALID for an invalid cookie name', () => {
    expect(() => serializeCookie('bad name', 'v', 60)).toThrowError(SessionError);
    try {
      serializeCookie('bad;name', 'v', 60);
    } catch (err) {
      expect((err as SessionError).code).toBe('CONFIG_INVALID');
    }
  });

  it('should throw when __Host- prefix is paired with Path other than /', () => {
    expect(() =>
      serializeCookie('sid', 'v', 60, { prefix: '__Host-', path: '/foo' }),
    ).toThrowError(/__Host- cookies require Path=\//);
  });

  it('should throw when __Host- prefix is paired with secure: false', () => {
    expect(() =>
      serializeCookie('sid', 'v', 60, { prefix: '__Host-', secure: false }),
    ).toThrowError(/__Host- cookies require Secure/);
  });

  it('should throw when __Host- is paired with a Domain attribute', () => {
    expect(() =>
      serializeCookie('sid', 'v', 60, { prefix: '__Host-', domain: 'example.com' }),
    ).toThrowError(/__Host- cookies must not set Domain/);
  });

  it('should throw when __Secure- is paired with secure: false', () => {
    expect(() =>
      serializeCookie('sid', 'v', 60, { prefix: '__Secure-', secure: false }),
    ).toThrowError(/__Secure- cookies require Secure/);
  });

  it('should throw when SameSite=None is paired with secure: false', () => {
    expect(() =>
      serializeCookie('sid', 'v', 60, { sameSite: 'None', secure: false }),
    ).toThrowError(/SameSite=None requires Secure/);
  });

  it('should reject CR / LF in domain (header injection guard)', () => {
    expect(() => serializeCookie('sid', 'v', 60, { domain: 'evil.com\r\nX: 1' })).toThrowError(
      /illegal characters/,
    );
  });

  it('should reject `;` in domain', () => {
    expect(() => serializeCookie('sid', 'v', 60, { domain: 'evil.com;X=Y' })).toThrowError(
      /illegal characters/,
    );
  });

  it('should reject whitespace in path', () => {
    expect(() => serializeCookie('sid', 'v', 60, { path: '/foo bar' })).toThrowError(
      /illegal characters/,
    );
  });

  it('should reject `;` in path', () => {
    expect(() => serializeCookie('sid', 'v', 60, { path: '/foo;bar' })).toThrowError(
      /illegal characters/,
    );
  });

  it('should reject control bytes in path', () => {
    expect(() => serializeCookie('sid', 'v', 60, { path: '/foo\x01' })).toThrowError(
      /illegal characters/,
    );
  });

  it('should reject a malformed domain even after passing the injection guard', () => {
    // Underscore is not a valid DNS label character.
    expect(() => serializeCookie('sid', 'v', 60, { domain: 'bad_label.com' })).toThrowError(
      /invalid cookie domain/,
    );
  });

  it('should accept a leading dot on domain (legacy cookie semantics)', () => {
    expect(() => serializeCookie('sid', 'v', 60, { domain: '.example.com' })).not.toThrow();
  });
});

describe('parseCookie', () => {
  it('should parse a single name=value pair', () => {
    const map = parseCookie('a=1');
    expect(map.get('a')).toBe('1');
  });

  it('should parse multiple cookies separated by `; `', () => {
    const map = parseCookie('a=1; b=two; c=three');
    expect(map.get('a')).toBe('1');
    expect(map.get('b')).toBe('two');
    expect(map.get('c')).toBe('three');
  });

  it('should return an empty map for null / undefined / empty header', () => {
    expect(parseCookie(null).size).toBe(0);
    expect(parseCookie(undefined).size).toBe(0);
    expect(parseCookie('').size).toBe(0);
  });

  it('should ignore pairs missing `=`', () => {
    const map = parseCookie('foo; bar=ok');
    expect(map.has('foo')).toBe(false);
    expect(map.get('bar')).toBe('ok');
  });

  it('should keep the first occurrence on duplicate names (header smuggling defence)', () => {
    const map = parseCookie('sid=safe; sid=injected');
    expect(map.get('sid')).toBe('safe');
  });

  it('should trim leading/trailing whitespace around names and values', () => {
    const map = parseCookie('  a = 1 ;  b=2');
    expect(map.get('a')).toBe('1');
    expect(map.get('b')).toBe('2');
  });

  it('should allow values containing `=`', () => {
    const map = parseCookie('token=abc=def=ghi');
    expect(map.get('token')).toBe('abc=def=ghi');
  });

  it('should ignore empty pairs (caused by stray `;`)', () => {
    const map = parseCookie(';; a=1;;; b=2 ;;');
    expect(map.get('a')).toBe('1');
    expect(map.get('b')).toBe('2');
  });
});

describe('prefixedName', () => {
  it('should return the bare name when prefix is false', () => {
    expect(prefixedName('sid', { prefix: false })).toBe('sid');
  });

  it('should return the bare name when prefix is undefined', () => {
    expect(prefixedName('sid')).toBe('sid');
  });

  it('should return __Host-sid for prefix: __Host-', () => {
    expect(prefixedName('sid', { prefix: '__Host-' })).toBe('__Host-sid');
  });

  it('should return __Secure-sid for prefix: __Secure-', () => {
    expect(prefixedName('sid', { prefix: '__Secure-' })).toBe('__Secure-sid');
  });
});

describe('DEFAULT_COOKIE_OPTIONS', () => {
  it('should expose secure-by-default values', () => {
    expect(DEFAULT_COOKIE_OPTIONS.path).toBe('/');
    expect(DEFAULT_COOKIE_OPTIONS.secure).toBe(true);
    expect(DEFAULT_COOKIE_OPTIONS.httpOnly).toBe(true);
    expect(DEFAULT_COOKIE_OPTIONS.sameSite).toBe('Lax');
    expect(DEFAULT_COOKIE_OPTIONS.prefix).toBe(false);
    expect(DEFAULT_COOKIE_OPTIONS.partitioned).toBe(false);
  });
});
