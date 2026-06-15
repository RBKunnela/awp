/**
 * Tests for the producer-side proof(id) op (AW-6 ops/proof.ts): it assembles a
 * self-contained Receipt bundle whose inclusion proof targets the record's
 * canonical Statement leaf and folds to the checkpoint root, refuses to emit an
 * incoherent bundle, serializes the proof to hex wire form, and round-trips
 * through `verify`. ≥3 cases (happy / error / edge).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { proof, checkpoint, toWireInclusion } from '../../src/ops/index.js';
import { verify } from '../../src/verify/index.js';
import {
  ReferenceLog,
  createTestNoteSigner,
  buildInclusionProof,
  toHex,
} from '../../src/log/index.js';
import {
  signEnvelope,
  createTestSigner,
  buildStatement,
  statementPayloadBytes,
} from '../../src/envelope/index.js';
import { buildTestOtsProof } from '../../src/anchor/index.js';
import type { WitnessRecord } from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');
function loadRecord(name: string): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, name), 'utf8')) as WitnessRecord;
}

const ORIGIN = 'awp.example/log';

/** Build a 4-leaf log with `record` at index 1, plus its signed checkpoint. The
 * committed leaf is the EXACT signed payload bytes (validated record). */
function buildScenario(record: WitnessRecord) {
  const { signer: envSigner, publicKey } = createTestSigner('env-key');
  const envelope = signEnvelope(record, envSigner);
  const leafBytes = Buffer.from((envelope as { payload: string }).payload, 'base64');

  const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
  log.append(new TextEncoder().encode('sibling-0'));
  const index = log.append(leafBytes);
  log.append(new TextEncoder().encode('sibling-2'));
  log.append(new TextEncoder().encode('sibling-3'));

  const note = createTestNoteSigner(ORIGIN);
  const cp = checkpoint(log, note.signer);

  return { log, index, envelope, publicKey, logPub: note.publicKey, cp };
}

describe('proof() — happy path + round-trip', () => {
  it('assembles a bundle that verify() accepts end-to-end (no anchor)', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const receipt = proof(s.index, {
      store: s.log,
      record,
      envelope: s.envelope,
      signerPublicKey: s.logPub,
      checkpoint: s.cp,
    });
    expect(receipt.inclusion?.leafIndex).toBe(1);
    expect(receipt.inclusion?.treeSize).toBe(4);
    expect(receipt.checkpoint?.keyName).toBe(ORIGIN);
    expect(receipt.checkpoint_root).toBe(s.cp.rootHex);

    const report = verify(receipt, { publicKey: s.publicKey });
    expect(report.ok).toBe(true);
    for (const c of report.checks) expect(c.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'inclusion')?.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'checkpoint')?.ok).toBe(true);
  });

  it('round-trips WITH an OTS anchor over the checkpoint root', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const anchors = [
      {
        type: 'ots' as const,
        checkpoint_root: s.cp.rootHex,
        ots_proof_b64: buildTestOtsProof(Buffer.from(s.cp.rootHex, 'hex'), { confirmed: true, height: 800001 }).toString('base64'),
        pending: false,
      },
    ];
    const receipt = proof(s.index, {
      store: s.log,
      record,
      envelope: s.envelope,
      signerPublicKey: s.logPub,
      checkpoint: s.cp,
      anchors,
    });
    const report = verify(receipt, { publicKey: s.publicKey });
    expect(report.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/time bound/);
  });

  it('optionally includes the legacy record_commitment when asked', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const receipt = proof(s.index, {
      store: s.log,
      record,
      envelope: s.envelope,
      signerPublicKey: s.logPub,
      checkpoint: s.cp,
      includeLegacyCommitment: true,
    });
    expect(receipt.record_commitment).toMatch(/^[a-f0-9]{64}$/);
    expect(verify(receipt, { publicKey: s.publicKey }).ok).toBe(true);
  });
});

describe('proof() — refuses incoherent bundles (error)', () => {
  it('throws when the leaf at id is not the record’s Statement bytes', () => {
    const record = loadRecord('valid-pay.json');
    const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
    // Append a WRONG leaf at the index we will reference.
    log.append(new TextEncoder().encode('not-the-record'));
    const note = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, note.signer);
    const { signer } = createTestSigner('env-key');
    expect(() =>
      proof(0, {
        store: log,
        record,
        envelope: signEnvelope(record, signer),
        signerPublicKey: note.publicKey,
        checkpoint: cp,
      }),
    ).toThrow(/does not equal the record's canonical \(validated\) Statement bytes/);
  });

  it('throws when the checkpoint root disagrees with the proof root (stale checkpoint)', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    // A checkpoint sealed at a DIFFERENT (smaller) size has a different root.
    const log2 = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
    log2.append(statementPayloadBytes(buildStatement(record)));
    const staleCp = checkpoint(log2, createTestNoteSigner(ORIGIN).signer);
    const { signer } = createTestSigner('env-key');
    expect(() =>
      proof(s.index, {
        store: s.log,
        record,
        envelope: signEnvelope(record, signer),
        signerPublicKey: s.logPub,
        checkpoint: staleCp,
      }),
    ).toThrow(/does not match checkpoint root/);
  });

  it('throws (RangeError) for an out-of-range id', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const { signer } = createTestSigner('env-key');
    expect(() =>
      proof(99, {
        store: s.log,
        record,
        envelope: signEnvelope(record, signer),
        signerPublicKey: s.logPub,
        checkpoint: s.cp,
      }),
    ).toThrow();
  });

  it('throws when the record does not validate (cannot build a leaf)', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const broken = { ...record, profile: 'not-a-real-profile' } as unknown as WitnessRecord;
    const { signer } = createTestSigner('env-key');
    expect(() =>
      proof(s.index, {
        store: s.log,
        record: broken,
        envelope: signEnvelope(record, signer),
        signerPublicKey: s.logPub,
        checkpoint: s.cp,
      }),
    ).toThrow(/does not validate/);
  });

  it('throws when the checkpoint size disagrees with the proof tree size (forged checkpoint)', () => {
    const record = loadRecord('valid-pay.json');
    const s = buildScenario(record);
    const { signer } = createTestSigner('env-key');
    // Same root (so the root-equality guard passes) but a mismatched size.
    const forged = { ...s.cp, size: s.cp.size + 1 };
    expect(() =>
      proof(s.index, {
        store: s.log,
        record,
        envelope: signEnvelope(record, signer),
        signerPublicKey: s.logPub,
        checkpoint: forged,
      }),
    ).toThrow(/tree size .* does not match checkpoint size/);
  });
});

describe('toWireInclusion (edge)', () => {
  it('serializes hashes to lowercase hex preserving index/size/positions', () => {
    const leaves = [
      new TextEncoder().encode('a'),
      new TextEncoder().encode('b'),
      new TextEncoder().encode('c'),
    ];
    const inMemory = buildInclusionProof(leaves, 2);
    const wire = toWireInclusion(inMemory);
    expect(wire.leafIndex).toBe(2);
    expect(wire.treeSize).toBe(3);
    expect(wire.leafHash).toBe(toHex(inMemory.leafHash));
    expect(wire.siblings.length).toBe(inMemory.siblings.length);
    for (let i = 0; i < wire.siblings.length; i++) {
      expect(wire.siblings[i]!.hash).toBe(toHex(inMemory.siblings[i]!.hash));
      expect(wire.siblings[i]!.position).toBe(inMemory.siblings[i]!.position);
    }
  });
});
