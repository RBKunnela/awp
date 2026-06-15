/**
 * Tests for RFC 9162 inclusion and consistency proof build + verify.
 *
 * Includes the AW-4 acceptance tests:
 *  - rfc9162-inclusion-known-answer (vector-backed),
 *  - rfc9162-consistency-append-only-pass,
 *  - rfc9162-consistency-detects-rewrite,
 * plus an exhaustive cross-size sweep so the algorithms are pinned for all
 * m,n up to a bound (not just the committed vectors).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  merkleTreeHash,
  hashLeaf,
  buildInclusionProof,
  verifyInclusion,
  buildConsistencyProof,
  verifyConsistency,
  toHex,
  fromHex,
} from '../../src/log/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vec = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(here, 'vectors', name), 'utf8'));

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const leaves = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => enc(`leaf-${i}`));

describe('buildInclusionProof', () => {
  it('builds a proof carrying index, treeSize, leafHash, siblings (happy)', () => {
    const es = leaves(7);
    const proof = buildInclusionProof(es, 3);
    expect(proof.leafIndex).toBe(3);
    expect(proof.treeSize).toBe(7);
    expect(toHex(proof.leafHash)).toBe(toHex(hashLeaf(es[3]!)));
    expect(proof.siblings.length).toBeGreaterThan(0);
  });

  it('returns an empty path for a single-leaf tree (edge)', () => {
    const proof = buildInclusionProof(leaves(1), 0);
    expect(proof.siblings).toEqual([]);
  });

  it('throws for an out-of-range index (error)', () => {
    expect(() => buildInclusionProof(leaves(3), 3)).toThrow(RangeError);
    expect(() => buildInclusionProof(leaves(3), -1)).toThrow(RangeError);
  });
});

describe('verifyInclusion', () => {
  it('rfc9162-inclusion-known-answer: matches the committed vector', () => {
    const v = vec('inclusion-known-answer.json');
    const es = leaves(v.leafCount as number);
    const root = merkleTreeHash(es);
    expect(toHex(root)).toBe(v.rootHex);
    const proof = buildInclusionProof(es, v.leafIndex as number);
    expect(toHex(proof.leafHash)).toBe(v.leafHashHex);
    expect(verifyInclusion(proof.leafHash, proof, fromHex(v.rootHex as string))).toBe(true);
  });

  it('verifies every leaf index of a 7-leaf tree (happy sweep)', () => {
    const es = leaves(7);
    const root = merkleTreeHash(es);
    for (let i = 0; i < 7; i++) {
      const proof = buildInclusionProof(es, i);
      expect(verifyInclusion(proof.leafHash, proof, root)).toBe(true);
    }
  });

  it('fails against the wrong root (error)', () => {
    const es = leaves(5);
    const proof = buildInclusionProof(es, 2);
    const wrongRoot = merkleTreeHash(leaves(6));
    expect(verifyInclusion(proof.leafHash, proof, wrongRoot)).toBe(false);
  });

  it('fails when the supplied leaf hash does not match the proof (edge)', () => {
    const es = leaves(5);
    const root = merkleTreeHash(es);
    const proof = buildInclusionProof(es, 2);
    expect(verifyInclusion(hashLeaf(enc('not-the-leaf')), proof, root)).toBe(false);
  });

  it('exhaustive: build+verify holds for all indices, sizes 1..32', () => {
    for (let n = 1; n <= 32; n++) {
      const es = leaves(n);
      const root = merkleTreeHash(es);
      for (let i = 0; i < n; i++) {
        const proof = buildInclusionProof(es, i);
        expect(verifyInclusion(proof.leafHash, proof, root)).toBe(true);
      }
    }
  });
});

describe('buildConsistencyProof', () => {
  it('builds a proof with first/second/path (happy)', () => {
    const es = leaves(7);
    const proof = buildConsistencyProof(es, 4);
    expect(proof.first).toBe(4);
    expect(proof.second).toBe(7);
    expect(Array.isArray(proof.path)).toBe(true);
  });

  it('produces an empty path when first==second (edge)', () => {
    const es = leaves(4);
    const proof = buildConsistencyProof(es, 4);
    expect(proof.path).toEqual([]);
  });

  it('throws when first is out of range (error)', () => {
    expect(() => buildConsistencyProof(leaves(4), 0)).toThrow(RangeError);
    expect(() => buildConsistencyProof(leaves(4), 5)).toThrow(RangeError);
  });
});

describe('verifyConsistency', () => {
  it('rfc9162-consistency-append-only-pass: matches the committed vector', () => {
    const v = vec('consistency-append-only.json');
    const es = leaves(v.second as number);
    const oldRoot = merkleTreeHash(es.slice(0, v.first as number));
    const newRoot = merkleTreeHash(es);
    expect(toHex(oldRoot)).toBe(v.oldRootHex);
    expect(toHex(newRoot)).toBe(v.newRootHex);
    const proof = buildConsistencyProof(es, v.first as number);
    expect(verifyConsistency(proof, oldRoot, newRoot)).toBe(true);
  });

  it('rfc9162-consistency-detects-rewrite: an early-leaf rewrite FAILS against the old root', () => {
    const v = vec('consistency-rewrite-detected.json');
    const original = leaves(7);
    const rewritten = leaves(7);
    rewritten[v.rewrittenLeafIndex as number] = enc('REWRITTEN');

    const origRootM = merkleTreeHash(original.slice(0, v.first as number));
    const rewrittenRootN = merkleTreeHash(rewritten);
    expect(toHex(origRootM)).toBe(v.originalSize4RootHex);
    expect(toHex(rewrittenRootN)).toBe(v.rewrittenSize7RootHex);

    // Honest proof over the REWRITTEN tree, checked against the ORIGINAL size-4
    // root: the rewrite makes the recomputed old root diverge → FAIL.
    const proofRewritten = buildConsistencyProof(rewritten, v.first as number);
    expect(verifyConsistency(proofRewritten, origRootM, rewrittenRootN)).toBe(false);
  });

  it('rfc9162-consistency-detects-rewrite (non-power-of-two old tree): the hash1==oldRoot check is the catcher', () => {
    // `first = 3` is NOT a power of two, so the alignment loop leaves node > 0 and
    // verifyConsistency RECONSTRUCTS the size-3 old root from the proof nodes
    // (proofs.ts seeds hash1 = path[0]) rather than seeding it from the passed
    // oldRoot (the power-of-two case, e.g. first=4, which makes hash1==oldRoot
    // tautological). So here the final `hashesEqual(hash1, oldRoot)` check is the
    // specific assertion that catches an early-leaf rewrite — the exact path the
    // first=4 acceptance test above never exercises.
    const first = 3;
    const original = leaves(7);
    const rewritten = leaves(7);
    rewritten[1] = enc('REWRITTEN'); // an early leaf INSIDE the size-3 old subtree

    const originalOldRoot = merkleTreeHash(original.slice(0, first)); // unrewritten size-3 root
    const rewrittenNewRoot = merkleTreeHash(rewritten); // rewritten size-7 root

    // Honest proof over the REWRITTEN tree: its hash2 reproduces rewrittenNewRoot
    // (the new-root check PASSES), and the size-3 old root it reconstructs is the
    // *rewritten* one — which diverges from the ORIGINAL old root we check against.
    // So the ONLY failing check is `hash1 == oldRoot` → the proof FAILS.
    const proof = buildConsistencyProof(rewritten, first);
    expect(verifyConsistency(proof, originalOldRoot, rewrittenNewRoot)).toBe(false);

    // Guard: the proof DOES verify against its own (rewritten) old root — proving
    // the FALSE above is the old-root mismatch (hash1==oldRoot), not a malformed
    // proof or a hash2/path failure.
    const rewrittenOldRoot = merkleTreeHash(rewritten.slice(0, first));
    expect(verifyConsistency(proof, rewrittenOldRoot, rewrittenNewRoot)).toBe(true);
  });

  it('passes for append-only growth across many m,n (happy sweep)', () => {
    const es = leaves(13);
    const rootN = merkleTreeHash(es);
    for (let m = 1; m <= 13; m++) {
      const rootM = merkleTreeHash(es.slice(0, m));
      const proof = buildConsistencyProof(es, m);
      expect(verifyConsistency(proof, rootM, rootN)).toBe(true);
    }
  });

  it('fails against a tampered new root (error)', () => {
    const es = leaves(7);
    const rootM = merkleTreeHash(es.slice(0, 4));
    const proof = buildConsistencyProof(es, 4);
    const tamperedN = merkleTreeHash([...es.slice(0, 6), enc('tampered')]);
    expect(verifyConsistency(proof, rootM, tamperedN)).toBe(false);
  });

  it('rejects first>second and an oversize first (edge)', () => {
    const es = leaves(5);
    const rootN = merkleTreeHash(es);
    expect(verifyConsistency({ first: 6, second: 5, path: [] }, rootN, rootN)).toBe(false);
    expect(verifyConsistency({ first: 5, second: 5, path: [] }, rootN, rootN)).toBe(true);
  });

  it('exhaustive: append-only proofs verify for all m<=n, sizes 1..40', () => {
    for (let n = 1; n <= 40; n++) {
      const es = leaves(n);
      const rootN = merkleTreeHash(es);
      for (let m = 1; m <= n; m++) {
        const rootM = merkleTreeHash(es.slice(0, m));
        const proof = buildConsistencyProof(es, m);
        expect(verifyConsistency(proof, rootM, rootN)).toBe(true);
        // Negative: any early-leaf rewrite must be detected.
        if (m >= 1 && n > m) {
          const rw = leaves(n);
          rw[0] = enc('RW');
          const proofRw = buildConsistencyProof(rw, m);
          expect(verifyConsistency(proofRw, rootM, merkleTreeHash(rw))).toBe(false);
        }
      }
    }
  });
});
