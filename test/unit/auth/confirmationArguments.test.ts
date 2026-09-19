import { describe, expect, it, vi } from 'vitest';
import { canonicalJson, sha256 } from '../../../src/auth/confirmationArguments.ts';

describe('confirmation argument hashes', () => {
  it('ignores object key order recursively, including numeric-looking keys', () => {
    const first = { z: [{ b: 2, a: 1 }], '10': true, '2': null };
    const second = { '2': null, '10': true, z: [{ a: 1, b: 2 }] };
    expect(canonicalJson(first)).toBe('{"10":true,"2":null,"z":[{"a":1,"b":2}]}');
    expect(sha256(canonicalJson(first))).toBe(sha256(canonicalJson(second)));
  });

  it.each([
    [{ amount: 1 }, { amount: '1' }],
    [{ amount: 1 }, { amount: 2 }],
    [{ amount: null }, {}],
    [{ names: ['a', 'b'] }, { names: ['b', 'a'] }],
    [{ name: 'meal' }, { name: 'meal ' }],
    [{ name: '\u00e9' }, { name: 'e\u0301' }],
  ])('distinguishes different JSON arguments', (first, second) => {
    expect(sha256(canonicalJson(first))).not.toBe(sha256(canonicalJson(second)));
  });

  it.each([
    undefined,
    NaN,
    Infinity,
    -Infinity,
    1n,
    Symbol('x'),
    () => null,
    new Date(),
    new Map(),
    { a: undefined },
    new Array(2),
  ])('refuses values JSON would omit or silently convert: %s', (value) => {
    expect(() => canonicalJson(value)).toThrow(TypeError);
  });

  it('refuses accessors without invoking them, including array entries', () => {
    const get = vi.fn(() => 'changed');
    const object = Object.defineProperty({}, 'food', { get, enumerable: true });
    const array = Object.defineProperty([1], '0', { get, enumerable: true });
    expect(() => canonicalJson(object)).toThrow(TypeError);
    expect(() => canonicalJson(array)).toThrow(TypeError);
    expect(get).not.toHaveBeenCalled();
  });

  it('refuses symbol keys and hidden data instead of dropping them', () => {
    expect(() => canonicalJson({ [Symbol('food')]: 'meal' })).toThrow(TypeError);
    expect(() => canonicalJson(Object.defineProperty({}, 'food', { value: 'meal' }))).toThrow(
      TypeError
    );
  });

  it('limits bytes, nesting, and the number of values', () => {
    expect(() => canonicalJson({ food: 'x'.repeat(16_384) })).toThrow(TypeError);
    expect(() => canonicalJson('x'.repeat(16_385))).toThrow(TypeError);
    expect(() => canonicalJson(Array.from({ length: 4097 }, () => null))).toThrow(TypeError);
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalJson(cyclic)).toThrow(TypeError);
  });

  it('preserves prototype-looking keys as data', () => {
    const json: unknown = JSON.parse('{"__proto__":{"food":"meal"},"constructor":null}');
    expect(canonicalJson(json)).toBe('{"__proto__":{"food":"meal"},"constructor":null}');
    expect(canonicalJson(Object.assign(Object.create(null) as object, { food: 'meal' }))).toBe(
      '{"food":"meal"}'
    );
  });

  it('uses SHA-256, not an implementation-dependent hash', () => {
    expect(sha256('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
});
