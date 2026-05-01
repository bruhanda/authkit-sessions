import { describe, expect, it } from 'vitest';
import { revokeBySessionId, revokeByUser } from '../core/revoke.js';
import { SessionError } from '../errors/base.js';
import type { SessionStore } from '../types/store.js';

const makeStore = (overrides: Partial<SessionStore> = {}): SessionStore => ({
  create: async () => undefined,
  read: async () => null,
  update: async () => false,
  delete: async () => false,
  listByUser: async () => [],
  deleteByUser: async () => 0,
  ...overrides,
});

describe('revokeBySessionId helper', () => {
  it('should return true when the store reports a removal', async () => {
    const store = makeStore({ delete: async () => true });
    expect(await revokeBySessionId(store, 'id')).toBe(true);
  });

  it('should pass through SessionError instances unchanged', async () => {
    const original = new SessionError('NOT_FOUND', 'gone');
    const store = makeStore({
      delete: async () => {
        throw original;
      },
    });
    await expect(revokeBySessionId(store, 'id')).rejects.toBe(original);
  });

  it('should re-wrap other errors as STORE_UNAVAILABLE', async () => {
    const store = makeStore({
      delete: async () => {
        throw new Error('redis down');
      },
    });
    try {
      await revokeBySessionId(store, 'id');
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
      expect((err as SessionError).code).toBe('STORE_UNAVAILABLE');
      expect((err as SessionError).cause).toBeInstanceOf(Error);
    }
  });
});

describe('revokeByUser helper', () => {
  it('should return the count from the store', async () => {
    const store = makeStore({ deleteByUser: async () => 3 });
    expect(await revokeByUser(store, 'user_42')).toBe(3);
  });

  it('should re-wrap thrown plain errors as STORE_UNAVAILABLE', async () => {
    const store = makeStore({
      deleteByUser: async () => {
        throw new Error('boom');
      },
    });
    try {
      await revokeByUser(store, 'user_42');
    } catch (err) {
      expect(SessionError.is(err)).toBe(true);
      expect((err as SessionError).code).toBe('STORE_UNAVAILABLE');
    }
  });

  it('should pass through SessionError instances unchanged', async () => {
    const original = new SessionError('CONFLICT', 'race');
    const store = makeStore({
      deleteByUser: async () => {
        throw original;
      },
    });
    await expect(revokeByUser(store, 'user_42')).rejects.toBe(original);
  });
});
