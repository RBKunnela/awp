/**
 * Tests for the RFC 9162 RFC9162_SHA256 raw-byte Merkle hashing core.
 *
 * Covers leaf/node domain separation, the empty-tree hash, the Merkle Tree Hash
 * recursion, the split-point helper, and the hex/equality utilities — happy,
 * error, and edge paths (≥3 per function).
 */
import { describe, it, expect } from 'vitest';
import {
  LEAF_PREFIX,
  NODE_PREFIX,
  HASH_SIZE,
  emptyTreeHash,
  hashLeaf,
  hashNode,
  hashNodeUtf8Hex,
  largestPowerOfTwoBelow,
  merkleTreeHash,
  toHex,
  fromHex,
  hashesEqual,
} from '../../src/log/index.js';
import { createHash } from 'node:crypto';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const leaves = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => enc(`leaf-${i}`));

describe('constants', () => {
  it('uses RFC 6962/9162 domain-separation prefixes and SHA-256 size', () => {
    expect(LEAF_PREFIX).toBe(0x00);
    expect(NODE_PREFIX).toBe(0x01);
    expect(HASH_SIZE).toBe(32);
  });
});

describe('emptyTreeHash', () => {
  it('equals SHA-256 of the empty string (RFC 9162 §2.1.1)', () => {
    expect(toHex(emptyTreeHash())).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('is 32 bytes', () => {
    expect(emptyTreeHash().length).toBe(32);
  });

  it('is NOT domain-separated (differs from hashLeaf of empty input)', () => {
    expect(hashesEqual(emptyTreeHash(), hashLeaf(new Uint8Array()))).toBe(false);
  });
});

describe('hashLeaf', () => {
  it('prefixes the entry with 0x00 before SHA-256 (happy)', () => {
    const expected = new Uint8Array(
      createHash('sha256').update(Uint8Array.of(0x00)).update(enc('a')).digest(),
    );
    expect(hashesEqual(hashLeaf(enc('a')), expected)).toBe(true);
  });

  it('produces distinct hashes for distinct entries', () => {
    expect(toHex(hashLeaf(enc('a')))).not.toBe(toHex(hashLeaf(enc('b'))));
  });

  it('handles an empty entry (edge)', () => {
    expect(hashLeaf(new Uint8Array()).length).toBe(32);
  });
});

describe('hashNode', () => {
  it('prefixes 0x01 and concatenates RAW child bytes (happy)', () => {
    const a = hashLeaf(enc('a'));
    const b = hashLeaf(enc('b'));
    const expected = new Uint8Array(
      createHash('sha256').update(Uint8Array.of(0x01)).update(a).update(b).digest(),
    );
    expect(hashesEqual(hashNode(a, b), expected)).toBe(true);
  });

  it('is order-sensitive (left,right) != (right,left)', () => {
    const a = hashLeaf(enc('a'));
    const b = hashLeaf(enc('b'));
    expect(toHex(hashNode(a, b))).not.toBe(toHex(hashNode(b, a)));
  });

  it('throws when a child is not exactly 32 bytes (error)', () => {
    const a = hashLeaf(enc('a'));
    expect(() => hashNode(a, enc('short'))).toThrow(RangeError);
    expect(() => hashNode(new Uint8Array(31), new Uint8Array(32))).toThrow(/32 raw bytes/);
  });
});

describe('hashNodeUtf8Hex (non-standard, divergence-only)', () => {
  it('produces a DIFFERENT root than the raw-byte rule for the same children', () => {
    const a = hashLeaf(enc('a'));
    const b = hashLeaf(enc('b'));
    expect(toHex(hashNodeUtf8Hex(a, b))).not.toBe(toHex(hashNode(a, b)));
  });

  it('matches a manual 0x01 + 128-hex-char utf8 hash', () => {
    const a = hashLeaf(enc('a'));
    const b = hashLeaf(enc('b'));
    const manual = new Uint8Array(
      createHash('sha256')
        .update(Uint8Array.of(0x01))
        .update(Buffer.from(toHex(a), 'utf8'))
        .update(Buffer.from(toHex(b), 'utf8'))
        .digest(),
    );
    expect(hashesEqual(hashNodeUtf8Hex(a, b), manual)).toBe(true);
  });

  it('is deterministic', () => {
    const a = hashLeaf(enc('x'));
    const b = hashLeaf(enc('y'));
    expect(toHex(hashNodeUtf8Hex(a, b))).toBe(toHex(hashNodeUtf8Hex(a, b)));
  });
});

describe('largestPowerOfTwoBelow', () => {
  it('returns the largest 2^x strictly below n (happy)', () => {
    expect(largestPowerOfTwoBelow(5)).toBe(4);
    expect(largestPowerOfTwoBelow(7)).toBe(4);
    expect(largestPowerOfTwoBelow(8)).toBe(4);
    expect(largestPowerOfTwoBelow(9)).toBe(8);
  });

  it('returns 1 for n=2 (edge)', () => {
    expect(largestPowerOfTwoBelow(2)).toBe(1);
  });

  it('throws for n < 2 or non-integer (error)', () => {
    expect(() => largestPowerOfTwoBelow(1)).toThrow(RangeError);
    expect(() => largestPowerOfTwoBelow(0)).toThrow(RangeError);
    expect(() => largestPowerOfTwoBelow(2.5)).toThrow(RangeError);
  });
});

describe('merkleTreeHash', () => {
  it('MTH({}) is the empty-tree hash (edge)', () => {
    expect(hashesEqual(merkleTreeHash([]), emptyTreeHash())).toBe(true);
  });

  it('MTH({d0}) is hashLeaf(d0) (edge)', () => {
    expect(hashesEqual(merkleTreeHash([enc('a')]), hashLeaf(enc('a')))).toBe(true);
  });

  it('MTH of two leaves is hashNode(leaf,leaf) (happy)', () => {
    const expected = hashNode(hashLeaf(enc('a')), hashLeaf(enc('b')));
    expect(hashesEqual(merkleTreeHash([enc('a'), enc('b')]), expected)).toBe(true);
  });

  it('is left-full: MTH of 3 splits at k=2', () => {
    const es = leaves(3);
    const expected = hashNode(
      hashNode(hashLeaf(es[0]!), hashLeaf(es[1]!)),
      hashLeaf(es[2]!),
    );
    expect(hashesEqual(merkleTreeHash(es), expected)).toBe(true);
  });

  it('changes when any leaf changes', () => {
    const a = toHex(merkleTreeHash(leaves(5)));
    const mutated = leaves(5);
    mutated[2] = enc('changed');
    expect(toHex(merkleTreeHash(mutated))).not.toBe(a);
  });
});

describe('toHex / fromHex', () => {
  it('round-trips bytes (happy)', () => {
    const b = hashLeaf(enc('z'));
    expect(hashesEqual(fromHex(toHex(b)), b)).toBe(true);
  });

  it('fromHex throws on odd-length or non-hex (error)', () => {
    expect(() => fromHex('abc')).toThrow();
    expect(() => fromHex('zz')).toThrow();
  });

  it('handles empty string (edge)', () => {
    expect(fromHex('').length).toBe(0);
  });
});

describe('hashesEqual', () => {
  it('true for identical bytes (happy)', () => {
    expect(hashesEqual(enc('abc'), enc('abc'))).toBe(true);
  });

  it('false for different lengths (edge)', () => {
    expect(hashesEqual(enc('ab'), enc('abc'))).toBe(false);
  });

  it('false for same length different content (error path)', () => {
    expect(hashesEqual(enc('abc'), enc('abd'))).toBe(false);
  });
});
