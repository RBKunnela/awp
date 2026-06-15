/**
 * Tests for the individual verify checks (AW-3 checks.ts). ≥3 tests per check:
 * schema/profile, signature, claim-class honesty, chain-link, anchor, plus the
 * record-commitment helper and the verbatim honesty-boundary line.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  checkSchemaAndProfile,
  checkSignature,
  checkClaimClassHonesty,
  checkChainLink,
  checkAnchor,
  recordCommitment,
  HONESTY_BOUNDARY_LINE,
} from '../../src/verify/checks.js';
import { signEnvelope, createTestSigner } from '../../src/envelope/index.js';
import { buildTestOtsProof, type Receipt } from '../../src/anchor/index.js';
import type { WitnessRecord } from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');
function loadRecord(name: string): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, name), 'utf8')) as WitnessRecord;
}

// ---------------------------------------------------------------------------
// checkSchemaAndProfile
// ---------------------------------------------------------------------------
describe('checkSchemaAndProfile', () => {
  it('passes schema + profile for a valid pay record', () => {
    const { checks, record } = checkSchemaAndProfile(loadRecord('valid-pay.json'));
    expect(record).toBeDefined();
    expect(checks.find((c) => c.name === 'schema')?.ok).toBe(true);
    expect(checks.find((c) => c.name === 'profile')?.ok).toBe(true);
  });

  it('fails schema (and skips profile) for a non-record', () => {
    const { checks, record } = checkSchemaAndProfile({ not: 'a record' });
    expect(record).toBeUndefined();
    expect(checks.find((c) => c.name === 'schema')?.ok).toBe(false);
    expect(checks.find((c) => c.name === 'profile')?.ok).toBe(false);
  });

  it('passes schema but fails profile when minimums are unmet', () => {
    const rec = loadRecord('valid-pay.json');
    delete (rec as { verifications?: unknown }).verifications; // pay needs ≥1 verification
    const { checks } = checkSchemaAndProfile(rec);
    expect(checks.find((c) => c.name === 'schema')?.ok).toBe(true);
    const profile = checks.find((c) => c.name === 'profile');
    expect(profile?.ok).toBe(false);
    expect(profile?.reason).toMatch(/VERIFICATION_REQUIRED/);
  });
});

// ---------------------------------------------------------------------------
// checkSignature
// ---------------------------------------------------------------------------
describe('checkSignature', () => {
  it('passes for a correctly signed envelope and returns the record', () => {
    const rec = loadRecord('valid-pay.json');
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(rec, signer);
    const { checks, record } = checkSignature(env, publicKey);
    expect(record).toBeDefined();
    expect(checks.find((c) => c.name === 'signature')?.ok).toBe(true);
  });

  it('fails for a wrong key', () => {
    const rec = loadRecord('valid-pay.json');
    const { signer } = createTestSigner();
    const env = signEnvelope(rec, signer);
    const other = createTestSigner();
    const { checks, record } = checkSignature(env, other.publicKey);
    expect(record).toBeUndefined();
    expect(checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });

  it('fails for a tampered payload', () => {
    const rec = loadRecord('valid-pay.json');
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(rec, signer);
    const decoded = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    decoded.predicate.intent.target_ref = 'order:TAMPERED';
    decoded.subject[0].name = 'order:TAMPERED';
    env.payload = Buffer.from(JSON.stringify(decoded)).toString('base64');
    const { checks } = checkSignature(env, publicKey);
    expect(checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// checkClaimClassHonesty
// ---------------------------------------------------------------------------
describe('checkClaimClassHonesty', () => {
  it('passes when every claim_class is within the honesty boundary', () => {
    const r = checkClaimClassHonesty(loadRecord('valid-pay.json'));
    expect(r.ok).toBe(true);
  });

  it('passes (integrity-only) when there are no verification entries', () => {
    const r = checkClaimClassHonesty(loadRecord('valid-doc.json'));
    expect(r.ok).toBe(true);
    expect(r.reason).toMatch(/integrity-since-witness/);
  });

  it('FAILS the overclaim: verified-against with a non-pass result', () => {
    const rec = loadRecord('valid-pay.json');
    rec.verifications![0]!.result = 'unverifiable';
    const r = checkClaimClassHonesty(rec);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/overclaim/);
  });

  it('FAILS a claim_class outside the closed set', () => {
    const rec = loadRecord('valid-pay.json');
    // Force an out-of-band value (the schema enum would reject it upstream, but
    // this check is the explicit, named restatement of the boundary).
    (rec.verifications![0] as { claim_class: string }).claim_class = 'authenticity-at-origin';
    const r = checkClaimClassHonesty(rec);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/honesty boundary/);
  });
});

// ---------------------------------------------------------------------------
// checkChainLink
// ---------------------------------------------------------------------------
describe('checkChainLink', () => {
  it('passes when no predecessor supplied and the field is well-formed', () => {
    const r = checkChainLink(loadRecord('valid-pay.json'));
    expect(r.ok).toBe(true);
  });

  it('passes when the supplied predecessor matches', () => {
    const rec = loadRecord('valid-pay.json');
    const r = checkChainLink(rec, rec.chain.prev_record_hash);
    expect(r.ok).toBe(true);
  });

  it('FAILS when the supplied predecessor does not match (AC5)', () => {
    const rec = loadRecord('valid-pay.json');
    const r = checkChainLink(rec, 'f'.repeat(64));
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/does not match/);
  });
});

// ---------------------------------------------------------------------------
// checkAnchor
// ---------------------------------------------------------------------------
describe('checkAnchor', () => {
  function receiptWithAnchor(rec: WitnessRecord, confirmed: boolean): Receipt {
    const root = recordCommitment(rec);
    return {
      envelope: {},
      checkpoint_root: root,
      record_commitment: root,
      anchors: [
        {
          type: 'ots',
          checkpoint_root: root,
          ots_proof_b64: buildTestOtsProof(Buffer.from(root, 'hex'), { confirmed }).toString('base64'),
        },
      ],
    };
  }

  it('passes "not present" when there are no anchors (no silent skip)', () => {
    const rec = loadRecord('valid-pay.json');
    const r = checkAnchor({ envelope: {} }, rec);
    expect(r.ok).toBe(true);
    expect(r.reason).toMatch(/no external anchor/);
  });

  it('passes a confirmed OTS anchor and reports trust-minimized weight', () => {
    const rec = loadRecord('valid-pay.json');
    const r = checkAnchor(receiptWithAnchor(rec, true), rec);
    expect(r.ok).toBe(true);
    expect(r.reason).toMatch(/trust-minimized/);
    expect(r.reason).not.toMatch(/qualified/);
  });

  it('FAILS when record_commitment does not bind the record', () => {
    const rec = loadRecord('valid-pay.json');
    const receipt = receiptWithAnchor(rec, true);
    receipt.record_commitment = 'a'.repeat(64);
    const r = checkAnchor(receipt, rec);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/record_commitment/);
  });

  it('FAILS a present-but-unverifiable reserved RFC 3161 anchor (never passes it)', () => {
    const rec = loadRecord('valid-pay.json');
    const root = recordCommitment(rec);
    const receipt: Receipt = {
      envelope: {},
      checkpoint_root: root,
      record_commitment: root,
      anchors: [{ type: 'rfc3161', checkpoint_root: root, tst_der_b64: 'AAAA' }],
    };
    const r = checkAnchor(receipt, rec);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/RFC 3161|qualified/);
  });
});

// ---------------------------------------------------------------------------
// recordCommitment + honesty boundary
// ---------------------------------------------------------------------------
describe('recordCommitment + boundary', () => {
  it('recordCommitment is a stable sha256 hex of the canonical statement', () => {
    const rec = loadRecord('valid-pay.json');
    const c1 = recordCommitment(rec);
    const c2 = recordCommitment(rec);
    expect(c1).toBe(c2);
    expect(c1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('HONESTY_BOUNDARY_LINE states integrity-since-witness and disclaims completeness/identity', () => {
    expect(HONESTY_BOUNDARY_LINE).toMatch(/integrity-since-witness only/);
    expect(HONESTY_BOUNDARY_LINE).toMatch(/completeness/);
    expect(HONESTY_BOUNDARY_LINE).toMatch(/identity/);
  });
});
