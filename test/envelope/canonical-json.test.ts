/**
 * Tests for the canonical-JSON helper (AW-2): the recursive key-sort rule the
 * in-toto Statement payload is serialized under before DSSE PAE + signing.
 *
 * Covers each exported function across happy / error / edge: deterministic key
 * order at every depth, array-order preservation, primitive pass-through,
 * `undefined`-dropping, and byte output. ≥3 tests per exported function.
 */
import { describe, it, expect } from 'vitest';
import {
  sortObjectKeys,
  canonicalJSONStringify,
  canonicalJSONBytes,
  type JsonValue,
} from '../../src/envelope/canonical-json.js';

describe('[UNIT] sortObjectKeys', () => {
  it('sorts object keys ascending at the top level (happy)', () => {
    expect(sortObjectKeys({ b: 1, a: 2, c: 3 })).toEqual({ a: 2, b: 1, c: 3 });
    expect(Object.keys(sortObjectKeys({ b: 1, a: 2 }) as object)).toEqual(['a', 'b']);
  });

  it('sorts keys recursively at every depth (happy)', () => {
    const input: JsonValue = { z: { y: 1, x: 2 }, a: { d: 3, c: 4 } };
    const out = sortObjectKeys(input) as Record<string, Record<string, number>>;
    expect(Object.keys(out)).toEqual(['a', 'z']);
    expect(Object.keys(out['a']!)).toEqual(['c', 'd']);
    expect(Object.keys(out['z']!)).toEqual(['x', 'y']);
  });

  it('preserves array element order (arrays are ordered data) (edge)', () => {
    const input: JsonValue = { list: [{ b: 1, a: 2 }, 3, 'x'] };
    const out = sortObjectKeys(input) as { list: JsonValue[] };
    expect(out.list[1]).toBe(3);
    expect(out.list[2]).toBe('x');
    expect(Object.keys(out.list[0] as object)).toEqual(['a', 'b']);
  });

  it('returns primitives and null unchanged (edge)', () => {
    expect(sortObjectKeys(null)).toBeNull();
    expect(sortObjectKeys(42)).toBe(42);
    expect(sortObjectKeys('s')).toBe('s');
    expect(sortObjectKeys(true)).toBe(true);
  });

  it('drops undefined object properties (error-tolerance / JSON has no undefined)', () => {
    const input = { a: 1, b: undefined } as unknown as JsonValue;
    expect(sortObjectKeys(input)).toEqual({ a: 1 });
  });
});

describe('[UNIT] canonicalJSONStringify', () => {
  it('produces key-sorted minimal JSON (happy)', () => {
    expect(canonicalJSONStringify({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('is deterministic regardless of input key order (happy)', () => {
    const a = canonicalJSONStringify({ x: 1, y: { q: 2, p: 3 } });
    const b = canonicalJSONStringify({ y: { p: 3, q: 2 }, x: 1 });
    expect(a).toBe(b);
  });

  it('emits no extra whitespace (edge)', () => {
    expect(canonicalJSONStringify([1, 2, 3])).toBe('[1,2,3]');
    expect(canonicalJSONStringify({ a: [] })).toBe('{"a":[]}');
  });
});

describe('[UNIT] canonicalJSONBytes', () => {
  it('returns the UTF-8 bytes of the canonical string (happy)', () => {
    const bytes = canonicalJSONBytes({ b: 1, a: 2 });
    expect(Buffer.from(bytes).toString('utf8')).toBe('{"a":2,"b":1}');
  });

  it('counts multibyte characters as multiple bytes (edge)', () => {
    // "é" (U+00E9) is two UTF-8 bytes.
    const bytes = canonicalJSONBytes({ k: 'é' });
    expect(Buffer.from(bytes).toString('utf8')).toBe('{"k":"é"}');
    // {"k":"é"} = 8 ASCII chars + 2 bytes for é = 10 bytes.
    expect(bytes.length).toBe(10);
  });

  it('round-trips back to the same value via JSON.parse (edge)', () => {
    const value: JsonValue = { a: [1, { c: 3, b: 2 }], z: null };
    const parsed = JSON.parse(Buffer.from(canonicalJSONBytes(value)).toString('utf8'));
    expect(parsed).toEqual(value);
  });
});
