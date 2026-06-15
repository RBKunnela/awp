/**
 * Tests for the producer-side checkpoint() op (AW-6 ops/checkpoint.ts): it seals
 * the current log state into a signed C2SP note that verifyNote accepts, commits
 * the correct root + size, marks the cadence, and round-trips through parse.
 * ≥3 cases (happy / error / edge).
 */
import { describe, it, expect } from 'vitest';
import { checkpoint } from '../../src/ops/index.js';
import {
  ReferenceLog,
  createTestNoteSigner,
  verifyNote,
  parseCheckpoint,
  toHex,
} from '../../src/log/index.js';

function enc(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

const ORIGIN = 'awp.example/log';

function freshLog(n: number): ReferenceLog {
  const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
  for (let i = 0; i < n; i++) log.append(enc(`leaf-${i}`));
  return log;
}

describe('checkpoint() — happy path', () => {
  it('produces a signed note that verifyNote accepts and that parses to (root,size,origin)', () => {
    const log = freshLog(3);
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, signer);

    expect(cp.origin).toBe(ORIGIN);
    expect(cp.size).toBe(3);
    expect(cp.rootHex).toBe(log.rootHex());

    const v = verifyNote(cp.note, verifier);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const parsed = parseCheckpoint(v.text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.checkpoint.origin).toBe(ORIGIN);
    expect(parsed.checkpoint.size).toBe(3);
    expect(toHex(parsed.checkpoint.root)).toBe(cp.rootHex);
  });

  it('commits the empty-tree root + size 0 for an empty log', () => {
    const log = new ReferenceLog(ORIGIN);
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, signer);
    expect(cp.size).toBe(0);
    expect(verifyNote(cp.note, verifier).ok).toBe(true);
  });

  it('marks the cadence so the same leaves are not re-checkpointed', () => {
    const log = freshLog(4);
    expect(log.shouldCheckpoint()).toBe(true);
    const { signer } = createTestNoteSigner(ORIGIN);
    checkpoint(log, signer);
    expect(log.checkpointSize()).toBe(4);
    expect(log.shouldCheckpoint()).toBe(false);
  });
});

describe('checkpoint() — tamper / wrong key', () => {
  it('a flipped byte in the checkpoint body breaks the note signature', () => {
    const log = freshLog(2);
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, signer);
    // Tamper the size digit inside the note text → signature no longer matches.
    const tampered = cp.note.replace(/\n2\n/, '\n9\n');
    expect(tampered).not.toBe(cp.note);
    const v = verifyNote(tampered, verifier);
    expect(v.ok).toBe(false);
  });

  it('a different key fails verification (key-id / signature)', () => {
    const log = freshLog(2);
    const { signer } = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, signer);
    const other = createTestNoteSigner(ORIGIN); // same name, different key
    const v = verifyNote(cp.note, other.verifier);
    expect(v.ok).toBe(false);
  });
});

describe('checkpoint() — extensions (edge)', () => {
  it('carries opaque extension lines that survive the round-trip', () => {
    const log = freshLog(1);
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, signer, ['Timestamp: 2026-06-11T00:00:00Z']);
    const v = verifyNote(cp.note, verifier);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    const parsed = parseCheckpoint(v.text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.checkpoint.extensions).toContain('Timestamp: 2026-06-11T00:00:00Z');
  });

  it('rejects an invalid (empty) extension line via encodeCheckpoint', () => {
    const log = freshLog(1);
    const { signer } = createTestNoteSigner(ORIGIN);
    expect(() => checkpoint(log, signer, [''])).toThrow();
  });
});
