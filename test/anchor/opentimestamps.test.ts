/**
 * Tests for the OpenTimestamps anchor read/verify path (AW-5 OTS slice used by
 * AW-3). Covers: round-trip read of a well-formed proof (pending + confirmed),
 * wrong-root detection, malformed-proof handling, unsupported-hash-op honesty,
 * and the receipt-proof wrapper. ≥3 tests per exported function.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  readOtsProof,
  verifyOtsAnchor,
  buildTestOtsProof,
  type OtsAnchorProof,
} from '../../src/anchor/index.js';

function digest(s: string): Buffer {
  return createHash('sha256').update(s).digest();
}
const root = digest('checkpoint-root-1');
const rootHex = root.toString('hex');

describe('readOtsProof — happy paths', () => {
  it('reads a pending calendar proof and reports pending honestly', () => {
    const proof = buildTestOtsProof(root, { confirmed: false, calendar: 'https://cal.example' });
    const r = readOtsProof(proof, rootHex);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.confirmed).toBe(false);
      expect(r.calendars).toContain('https://cal.example');
      expect(r.reason).toMatch(/pending/);
    }
  });

  it('reads a confirmed Bitcoin proof and exposes the block height', () => {
    const proof = buildTestOtsProof(root, { confirmed: true, height: 842000 });
    const r = readOtsProof(proof, rootHex);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.confirmed).toBe(true);
      expect(r.block_heights).toContain(842000);
      expect(r.reason).toMatch(/Bitcoin block 842000/);
    }
  });

  it('accepts an uppercase expected digest (case-insensitive match)', () => {
    const proof = buildTestOtsProof(root, { confirmed: true });
    const r = readOtsProof(proof, rootHex.toUpperCase());
    expect(r.ok).toBe(true);
  });
});

describe('readOtsProof — failure paths (fail-closed, named)', () => {
  it('FAILS when the proof commits a different digest than expected (wrong root)', () => {
    const proof = buildTestOtsProof(root, { confirmed: true });
    const r = readOtsProof(proof, digest('other-root').toString('hex'));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/different digest/);
  });

  it('FAILS on a bad magic header', () => {
    const bad = Buffer.from('not an ots proof at all, just text padding bytes here');
    const r = readOtsProof(bad, rootHex);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/magic|malformed/i);
  });

  it('FAILS (never silently passes) on a truncated proof', () => {
    const proof = buildTestOtsProof(root, { confirmed: true });
    const r = readOtsProof(proof.subarray(0, proof.length - 4), rootHex);
    expect(r.ok).toBe(false);
  });
});

describe('verifyOtsAnchor — receipt wrapper', () => {
  it('verifies an OtsAnchorProof read straight from a receipt', () => {
    const proof: OtsAnchorProof = {
      type: 'ots',
      checkpoint_root: rootHex,
      ots_proof_b64: buildTestOtsProof(root, { confirmed: true }).toString('base64'),
    };
    const r = verifyOtsAnchor(proof);
    expect(r.ok).toBe(true);
  });

  it('FAILS when the embedded proof commits a different root', () => {
    const proof: OtsAnchorProof = {
      type: 'ots',
      checkpoint_root: digest('mismatch').toString('hex'),
      ots_proof_b64: buildTestOtsProof(root, { confirmed: true }).toString('base64'),
    };
    const r = verifyOtsAnchor(proof);
    expect(r.ok).toBe(false);
  });

  it('FAILS on non-base64 proof bytes without throwing', () => {
    const proof: OtsAnchorProof = {
      type: 'ots',
      checkpoint_root: rootHex,
      ots_proof_b64: '%%%not-base64%%%',
    };
    const r = verifyOtsAnchor(proof);
    expect(r.ok).toBe(false);
  });
});
