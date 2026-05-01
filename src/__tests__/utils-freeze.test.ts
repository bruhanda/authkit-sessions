import { describe, expect, expectTypeOf, it } from 'vitest';
import { deepFreeze } from '../utils/freeze.js';

describe('deepFreeze', () => {
  it('should freeze the top-level object', () => {
    const obj = deepFreeze({ a: 1 });
    expect(Object.isFrozen(obj)).toBe(true);
  });

  it('should recursively freeze nested plain objects', () => {
    const obj = deepFreeze({ outer: { inner: { leaf: 1 } } });
    expect(Object.isFrozen(obj.outer)).toBe(true);
    expect(Object.isFrozen(obj.outer.inner)).toBe(true);
  });

  it('should recursively freeze arrays', () => {
    const obj = deepFreeze({ list: [{ x: 1 }, { y: 2 }] });
    expect(Object.isFrozen(obj.list)).toBe(true);
    expect(Object.isFrozen(obj.list[0])).toBe(true);
  });

  it('should return the same reference', () => {
    const obj = { a: 1 };
    expect(deepFreeze(obj)).toBe(obj);
  });

  it('should pass through primitive scalars unchanged', () => {
    expect(deepFreeze(42 as unknown as object)).toBe(42);
    expect(deepFreeze('hi' as unknown as object)).toBe('hi');
    expect(deepFreeze(null as unknown as object)).toBe(null);
  });

  it('should not freeze non-plain objects (Map/Set/Date) so internal mutators keep working', () => {
    const map = new Map<string, number>();
    deepFreeze({ map });
    expect(Object.isFrozen(map)).toBe(false);
    map.set('a', 1);
    expect(map.get('a')).toBe(1);
  });

  it('should tolerate cycles via the visited set', () => {
    type Node = { self?: Node };
    const obj: Node = {};
    obj.self = obj;
    expect(() => deepFreeze(obj)).not.toThrow();
    expect(Object.isFrozen(obj)).toBe(true);
  });

  it('should preserve the input type', () => {
    const x = deepFreeze({ a: 1, b: 'two' });
    expectTypeOf(x).toEqualTypeOf<{ a: number; b: string }>();
  });

  it('should freeze objects with a null prototype', () => {
    const obj = Object.create(null) as { x: number };
    obj.x = 1;
    deepFreeze(obj);
    expect(Object.isFrozen(obj)).toBe(true);
  });
});
