import { describe, expect, expectTypeOf, it } from 'vitest';
import { SessionError } from '../errors/base.js';
import { SESSION_ERROR_CODES, type SessionErrorCode } from '../errors/codes.js';

describe('SessionError constructor', () => {
  it('should expose code, name, message, and publicMessage', () => {
    const err = new SessionError('NOT_FOUND', 'no session');
    expect(err.name).toBe('SessionError');
    expect(err.code).toBe('NOT_FOUND');
    expect(err.message).toBe('no session');
    expect(err.publicMessage).toBe('no session');
    expect(err).toBeInstanceOf(Error);
  });

  it('should attach the optional cause when provided', () => {
    const cause = new Error('underlying');
    const err = new SessionError('STORE_UNAVAILABLE', 'store down', cause);
    expect(err.cause).toBe(cause);
  });

  it('should leave cause undefined when omitted', () => {
    const err = new SessionError('NOT_FOUND', 'no session');
    expect(err.cause).toBeUndefined();
  });

  it('should set name read-only to SessionError', () => {
    const err = new SessionError('CONFIG_INVALID', 'bad');
    expect(err.name).toBe('SessionError');
  });
});

describe('SessionError.is', () => {
  it('should recognise its own instances', () => {
    const err = new SessionError('NOT_FOUND', 'x');
    expect(SessionError.is(err)).toBe(true);
  });

  it('should recognise structurally-similar values from another realm', () => {
    const fromOtherRealm = {
      name: 'SessionError',
      code: 'EXPIRED',
      message: 'old',
    };
    expect(SessionError.is(fromOtherRealm)).toBe(true);
  });

  it('should reject plain Error instances', () => {
    expect(SessionError.is(new Error('plain'))).toBe(false);
  });

  it('should reject non-objects', () => {
    expect(SessionError.is(null)).toBe(false);
    expect(SessionError.is(undefined)).toBe(false);
    expect(SessionError.is('string')).toBe(false);
    expect(SessionError.is(42)).toBe(false);
  });

  it('should reject objects with the right name but unknown code', () => {
    expect(SessionError.is({ name: 'SessionError', code: 'NOT_A_REAL_CODE' })).toBe(false);
  });

  it('should reject objects with the right code but wrong name', () => {
    expect(SessionError.is({ name: 'Error', code: 'NOT_FOUND' })).toBe(false);
  });

  it('should reject objects without a string code', () => {
    expect(SessionError.is({ name: 'SessionError', code: 42 })).toBe(false);
  });

  it('should narrow the type after a successful check', () => {
    const value: unknown = new SessionError('NOT_FOUND', 'x');
    if (SessionError.is(value)) {
      expectTypeOf(value).toEqualTypeOf<SessionError>();
    }
  });
});

describe('SESSION_ERROR_CODES', () => {
  it('should expose every documented code as a literal tuple', () => {
    expect(SESSION_ERROR_CODES).toContain('NOT_FOUND');
    expect(SESSION_ERROR_CODES).toContain('CONFLICT');
    expect(SESSION_ERROR_CODES).toContain('SECRET_TOO_SHORT');
    expect(SESSION_ERROR_CODES).toContain('CONFIG_INVALID');
  });

  it('should export the SessionErrorCode type matching the tuple union', () => {
    const code: SessionErrorCode = 'NOT_FOUND';
    expectTypeOf(code).toEqualTypeOf<SessionErrorCode>();
  });
});
