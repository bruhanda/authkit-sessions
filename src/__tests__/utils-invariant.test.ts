import { describe, expect, it } from 'vitest';
import { SessionError } from '../errors/base.js';
import { invariant } from '../utils/invariant.js';

describe('invariant', () => {
  it('should not throw when the condition is truthy', () => {
    expect(() => invariant(true, 'CONFIG_INVALID', 'should not fire')).not.toThrow();
    expect(() => invariant(1, 'CONFIG_INVALID', 'should not fire')).not.toThrow();
    expect(() => invariant('non-empty', 'CONFIG_INVALID', 'should not fire')).not.toThrow();
  });

  it('should throw a SessionError carrying the supplied code and message when the condition is falsy', () => {
    expect(() => invariant(false, 'CONFIG_INVALID', 'oops')).toThrowError(SessionError);
    try {
      invariant(0, 'SECRET_TOO_SHORT', 'too short');
      expect.fail('should have thrown');
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
      const e = err as SessionError;
      expect(e.code).toBe('SECRET_TOO_SHORT');
      expect(e.message).toBe('too short');
    }
  });

  it('should narrow the asserted type after passing', () => {
    const value: string | undefined = 'hello';
    invariant(value !== undefined, 'CONFIG_INVALID', 'no value');
    // Type-narrowed: TS sees `value: string` here.
    expect(value.length).toBe(5);
  });

  it('should treat null/undefined/empty string as falsy', () => {
    expect(() => invariant(null, 'NOT_FOUND', 'null')).toThrow();
    expect(() => invariant(undefined, 'NOT_FOUND', 'undef')).toThrow();
    expect(() => invariant('', 'NOT_FOUND', 'empty')).toThrow();
  });
});
