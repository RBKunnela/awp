/**
 * Tests for the reference append-only log (AW-6 store.ts): append-only behavior,
 * RFC 9162 roots + inclusion proofs derived from the leaves, checkpoint cadence,
 * and input guards. ≥3 cases per surface (happy / error / edge).
 */
import { describe, it, expect } from 'vitest';
import {
  ReferenceLog,
  DEFAULT_CHECKPOINT_EVERY,
  merkleTreeHash,
  hashLeaf,
  verifyInclusion,
  emptyTreeHash,
  toHex,
} from '../../src/log/index.js';

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('ReferenceLog — construction', () => {
  it('builds with a default cadence', () => {
    const log = new ReferenceLog('awp.example/log');
    expect(log.origin).toBe('awp.example/log');
    expect(log.size()).toBe(0);
    expect(DEFAULT_CHECKPOINT_EVERY).toBeGreaterThan(0);
  });

  it('rejects an empty or multiline origin', () => {
    expect(() => new ReferenceLog('')).toThrow(/non-empty single line/);
    expect(() => new ReferenceLog('a\nb')).toThrow(/non-empty single line/);
  });

  it('rejects a non-positive / non-integer cadence', () => {
    expect(() => new ReferenceLog('o', { checkpointEvery: 0 })).toThrow(/positive integer/);
    expect(() => new ReferenceLog('o', { checkpointEvery: -2 })).toThrow(/positive integer/);
    expect(() => new ReferenceLog('o', { checkpointEvery: 1.5 })).toThrow(/positive integer/);
  });
});

describe('ReferenceLog — append (append-only)', () => {
  it('appends and returns stable 0-based indices', () => {
    const log = new ReferenceLog('o');
    expect(log.append(enc('a'))).toBe(0);
    expect(log.append(enc('b'))).toBe(1);
    expect(log.append(enc('c'))).toBe(2);
    expect(log.size()).toBe(3);
  });

  it('refuses a zero-length leaf', () => {
    const log = new ReferenceLog('o');
    expect(() => log.append(new Uint8Array(0))).toThrow(/zero-length leaf/);
  });

  it('defensively copies the leaf so a later caller mutation cannot rewrite it', () => {
    const log = new ReferenceLog('o');
    const buf = Uint8Array.from(enc('original'));
    log.append(buf);
    const rootBefore = log.rootHex();
    buf.fill(0); // mutate the caller's buffer after appending
    expect(log.rootHex()).toBe(rootBefore); // unchanged — append-only holds
    expect(new TextDecoder().decode(log.leaf(0))).toBe('original');
  });
});

describe('ReferenceLog — root', () => {
  it('returns the RFC 9162 empty-tree hash when empty', () => {
    const log = new ReferenceLog('o');
    expect(toHex(log.root())).toBe(toHex(emptyTreeHash()));
  });

  it('matches merkleTreeHash over the appended leaves', () => {
    const log = new ReferenceLog('o');
    const leaves = [enc('a'), enc('b'), enc('c'), enc('d'), enc('e')];
    for (const l of leaves) log.append(l);
    expect(toHex(log.root())).toBe(toHex(merkleTreeHash(leaves)));
  });

  it('changes as leaves are appended (single → multi)', () => {
    const log = new ReferenceLog('o');
    log.append(enc('only'));
    expect(toHex(log.root())).toBe(toHex(hashLeaf(enc('only'))));
    log.append(enc('second'));
    expect(toHex(log.root())).not.toBe(toHex(hashLeaf(enc('only'))));
  });
});

describe('ReferenceLog — inclusionProof', () => {
  it('produces proofs that verify against the root for every leaf', () => {
    const log = new ReferenceLog('o');
    const leaves = [enc('a'), enc('b'), enc('c'), enc('d'), enc('e'), enc('f'), enc('g')];
    for (const l of leaves) log.append(l);
    const root = log.root();
    for (let i = 0; i < leaves.length; i++) {
      const proof = log.inclusionProof(i);
      expect(verifyInclusion(hashLeaf(leaves[i]!), proof, root)).toBe(true);
      expect(toHex(proof.leafHash)).toBe(toHex(hashLeaf(leaves[i]!)));
      expect(proof.treeSize).toBe(leaves.length);
    }
  });

  it('throws for an out-of-range index', () => {
    const log = new ReferenceLog('o');
    log.append(enc('a'));
    expect(() => log.inclusionProof(1)).toThrow(/out of range/);
    expect(() => log.inclusionProof(-1)).toThrow(/out of range/);
  });

  it('leafHash(i) equals hashLeaf of the stored leaf', () => {
    const log = new ReferenceLog('o');
    log.append(enc('x'));
    log.append(enc('y'));
    expect(toHex(log.leafHash(1))).toBe(toHex(hashLeaf(enc('y'))));
  });

  it('leaf(i) throws out of range', () => {
    const log = new ReferenceLog('o');
    expect(() => log.leaf(0)).toThrow(/out of range/);
  });
});

describe('ReferenceLog — checkpoint cadence', () => {
  it('is not due before `checkpointEvery` appends, and due at it', () => {
    const log = new ReferenceLog('o', { checkpointEvery: 3 });
    log.append(enc('a'));
    expect(log.shouldCheckpoint()).toBe(false);
    log.append(enc('b'));
    expect(log.shouldCheckpoint()).toBe(false);
    log.append(enc('c'));
    expect(log.shouldCheckpoint()).toBe(true);
  });

  it('resets after markCheckpoint and bounds by the cadence again', () => {
    const log = new ReferenceLog('o', { checkpointEvery: 2 });
    log.append(enc('a'));
    log.append(enc('b'));
    expect(log.shouldCheckpoint()).toBe(true);
    expect(log.markCheckpoint()).toBe(2);
    expect(log.checkpointSize()).toBe(2);
    expect(log.shouldCheckpoint()).toBe(false); // counter reset
    log.append(enc('c'));
    expect(log.shouldCheckpoint()).toBe(false); // 1 pending < 2
    log.append(enc('d'));
    expect(log.shouldCheckpoint()).toBe(true); // 2 pending
  });

  it('is never due with zero pending leaves', () => {
    const log = new ReferenceLog('o', { checkpointEvery: 1 });
    expect(log.shouldCheckpoint()).toBe(false); // empty
    log.append(enc('a'));
    log.markCheckpoint();
    expect(log.shouldCheckpoint()).toBe(false); // nothing new since checkpoint
  });
});
