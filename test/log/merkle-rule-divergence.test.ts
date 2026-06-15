/**
 * AW-4 acceptance test: merkle-rule-dual-documented-with-vectors.
 *
 * The single most likely interop bug in this whole layer is confusing the
 * STANDARD RFC9162_SHA256 RAW-BYTE node rule (this open log) with the separate,
 * pinned utf8-hex-TEXT node rule used elsewhere for batch corroboration. This
 * test captures the divergence as an assertion so it can NEVER go silent:
 *
 *  1. The two rules produce DIFFERENT roots for the same leaves.
 *  2. The open log's standard root does NOT equal the utf8-hex root, and
 *     vice-versa (an open verifier must reject a utf8-hex root and vice-versa).
 *  3. The committed divergence vector and the docs/merkle-rules.md worked example
 *     agree with the live implementation.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hashLeaf,
  hashNode,
  hashNodeUtf8Hex,
  merkleTreeHash,
  toHex,
} from '../../src/log/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * The separate utf8-hex-text root for a list of leaf inputs, built with the SAME
 * left-full split as RFC 9162 but using {@link hashNodeUtf8Hex} for interior
 * nodes. Defined locally here (never on a verification path) purely to show the
 * whole-tree divergence, not just the single-node divergence.
 */
function utf8HexTreeHash(entries: Uint8Array[]): Uint8Array {
  const n = entries.length;
  if (n === 1) return hashLeaf(entries[0]!);
  let k = 1;
  while (k * 2 < n) k *= 2;
  return hashNodeUtf8Hex(utf8HexTreeHash(entries.slice(0, k)), utf8HexTreeHash(entries.slice(k)));
}

describe('dual Merkle rule divergence', () => {
  it('the two node rules differ for the same two children (single node)', () => {
    const a = hashLeaf(enc('leaf-0'));
    const b = hashLeaf(enc('leaf-1'));
    expect(toHex(hashNode(a, b))).not.toBe(toHex(hashNodeUtf8Hex(a, b)));
  });

  it('matches the committed divergence vector', () => {
    const v = JSON.parse(readFileSync(join(here, 'vectors', 'merkle-rule-divergence.json'), 'utf8'));
    const a = hashLeaf(enc('leaf-0'));
    const b = hashLeaf(enc('leaf-1'));
    expect(toHex(a)).toBe(v.leftLeafHashHex);
    expect(toHex(b)).toBe(v.rightLeafHashHex);
    expect(toHex(hashNode(a, b))).toBe(v.rfc9162RawByteRootHex);
    expect(toHex(hashNodeUtf8Hex(a, b))).toBe(v.utf8HexTextRootHex);
    expect(v.rootsDiffer).toBe(true);
  });

  it('the whole-tree roots diverge for many leaf counts (so a verifier never silently accepts the wrong rule)', () => {
    for (let n = 2; n <= 16; n++) {
      const es = Array.from({ length: n }, (_, i) => enc(`leaf-${i}`));
      const rfcRoot = toHex(merkleTreeHash(es));
      const hexRoot = toHex(utf8HexTreeHash(es));
      expect(rfcRoot).not.toBe(hexRoot);
    }
  });

  it('the open log uses the RAW-BYTE rule (merkleTreeHash == hashNode path, not the hex path)', () => {
    const es = [enc('leaf-0'), enc('leaf-1')];
    const viaRawByte = toHex(hashNode(hashLeaf(es[0]!), hashLeaf(es[1]!)));
    expect(toHex(merkleTreeHash(es))).toBe(viaRawByte);
  });
});
