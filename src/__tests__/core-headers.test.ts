import { describe, expect, it } from 'vitest';
import { appendSetCookie, extractCookie, extractCookies } from '../core/headers.js';

describe('extractCookie', () => {
  it('should pull a named cookie out of a Request', () => {
    const req = new Request('https://example.com', { headers: { cookie: 'sid=abc; foo=bar' } });
    expect(extractCookie(req, 'sid')).toBe('abc');
    expect(extractCookie(req, 'foo')).toBe('bar');
  });

  it('should return undefined when the header is missing', () => {
    const req = new Request('https://example.com');
    expect(extractCookie(req, 'sid')).toBeUndefined();
  });

  it('should return undefined when the named cookie is absent', () => {
    const req = new Request('https://example.com', { headers: { cookie: 'foo=bar' } });
    expect(extractCookie(req, 'sid')).toBeUndefined();
  });
});

describe('extractCookies', () => {
  it('should return a Map of every cookie pair', () => {
    const req = new Request('https://example.com', { headers: { cookie: 'a=1; b=2' } });
    const map = extractCookies(req);
    expect(map.get('a')).toBe('1');
    expect(map.get('b')).toBe('2');
  });

  it('should return an empty map when no cookie header is present', () => {
    expect(extractCookies(new Request('https://example.com')).size).toBe(0);
  });
});

describe('appendSetCookie', () => {
  it('should append without clobbering existing Set-Cookie entries', () => {
    const headers = new Headers();
    appendSetCookie(headers, 'a=1; Path=/');
    appendSetCookie(headers, 'b=2; Path=/');
    const all = headers.getSetCookie();
    expect(all.length).toBe(2);
    expect(all).toContain('a=1; Path=/');
    expect(all).toContain('b=2; Path=/');
  });

  it('should return the same Headers reference for chaining', () => {
    const headers = new Headers();
    expect(appendSetCookie(headers, 'a=1')).toBe(headers);
  });
});
