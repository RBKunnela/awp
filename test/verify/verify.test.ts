/**
 * Tests for the verify orchestrator (AW-3 verify.ts) and its acceptance
 * criteria: PASS path, tamper path naming the failed check, per-check
 * legibility (no bare booleans), chain-link mismatch, and the OFFLINE guarantee
 * (a test asserts zero network access during verify).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { verify, asReceipt } from '../../src/verify/index.js';
import { signEnvelope, createTestSigner } from '../../src/envelope/index.js';
import { recordCommitment } from '../../src/verify/checks.js';
import { buildTestOtsProof, type Receipt } from '../../src/anchor/index.js';
import type { WitnessRecord } from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');
function loadRecord(name: string): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, name), 'utf8')) as WitnessRecord;
}

function signedReceipt(rec: WitnessRecord, withAnchor: boolean): { receipt: Receipt; publicKey: ReturnType<typeof createTestSigner>['publicKey'] } {
  const { signer, publicKey } = createTestSigner('test-key');
  const envelope = signEnvelope(rec, signer);
  if (!withAnchor) return { receipt: { envelope }, publicKey };
  const root = recordCommitment(rec);
  return {
    receipt: {
      envelope,
      checkpoint_root: root,
      record_commitment: root,
      anchors: [
        {
          type: 'ots',
          checkpoint_root: root,
          ots_proof_b64: buildTestOtsProof(Buffer.from(root, 'hex'), { confirmed: true }).toString('base64'),
        },
      ],
    },
    publicKey,
  };
}

describe('asReceipt — input normalization', () => {
  it('wraps a bare DSSE envelope as an anchorless receipt', () => {
    const env = { payload: 'x', payloadType: 'y', signatures: [{ sig: 'z' }] };
    expect(asReceipt(env)?.envelope).toBe(env);
  });
  it('passes a receipt through unchanged', () => {
    const receipt = { envelope: {}, anchors: [] };
    expect(asReceipt(receipt)).toBe(receipt);
  });
  it('returns undefined for a non-envelope, non-receipt value', () => {
    expect(asReceipt({ hello: 'world' })).toBeUndefined();
    expect(asReceipt(null)).toBeUndefined();
    expect(asReceipt(42)).toBeUndefined();
  });
});

describe('verify — PASS path (AC1)', () => {
  it('passes every check for a valid signed receipt with an anchor and exits ok', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    expect(report.profile).toBe('pay');
    for (const c of report.checks) expect(c.ok).toBe(true);
  });

  it('passes a bare signed envelope (no anchor) — anchor reported "not present"', () => {
    const rec = loadRecord('valid-doc.json');
    const { receipt, publicKey } = signedReceipt(rec, false);
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/no external anchor/);
  });
});

describe('verify — tamper path (AC2) names the failed check', () => {
  it('FAILS and names "signature" when a payload byte is flipped', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const env = receipt.envelope as { payload: string };
    const decoded = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    decoded.predicate.intent.params_hash = 'b' + decoded.predicate.intent.params_hash.slice(1);
    env.payload = Buffer.from(JSON.stringify(decoded)).toString('base64');
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    const sig = report.checks.find((c) => c.name === 'signature');
    expect(sig?.ok).toBe(false);
  });

  it('FAILS for a wrong key and names "signature"', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt } = signedReceipt(rec, true);
    const wrong = createTestSigner().publicKey;
    const report = verify(receipt, { publicKey: wrong });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });
});

describe('verify — per-check legibility (AC4)', () => {
  it('every check has a name, an ok boolean, and a non-empty reason (never a bare boolean)', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey });
    expect(report.checks.length).toBeGreaterThanOrEqual(6);
    for (const c of report.checks) {
      expect(typeof c.name).toBe('string');
      expect(typeof c.ok).toBe('boolean');
      expect(c.reason.length).toBeGreaterThan(0);
    }
    expect(report.boundary).toMatch(/integrity-since-witness only/);
  });

  it('reports later checks as skipped (not dropped) when signature fails — no silent partial verification', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey: createTestSigner().publicKey });
    for (const name of ['schema', 'profile', 'claim-class', 'chain-link', 'anchor']) {
      const c = report.checks.find((x) => x.name === name);
      expect(c).toBeDefined();
      expect(c?.reason).toMatch(/skipped/);
    }
  });

  it('FAILS the input check for a value that is neither envelope nor receipt', () => {
    const report = verify({ nope: true }, { publicKey: createTestSigner().publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks[0]?.name).toBe('input');
  });
});

describe('verify — chain-link mismatch (AC5)', () => {
  it('FAILS chain-link when expectedPrevRecordHash does not match', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey, expectedPrevRecordHash: 'c'.repeat(64) });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'chain-link')?.ok).toBe(false);
  });

  it('PASSES chain-link when expectedPrevRecordHash matches', () => {
    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey, expectedPrevRecordHash: rec.chain.prev_record_hash });
    expect(report.checks.find((c) => c.name === 'chain-link')?.ok).toBe(true);
  });
});

describe('verify — OFFLINE guarantee (AC3): zero network access', () => {
  afterEach(() => vi.restoreAllMocks());

  it('makes no socket / connect / DNS / http(s) request during verify', () => {
    const guards = [
      vi.spyOn(net, 'connect').mockImplementation(() => { throw new Error('NETWORK: net.connect'); }),
      vi.spyOn(net, 'createConnection').mockImplementation(() => { throw new Error('NETWORK: net.createConnection'); }),
      vi.spyOn(tls, 'connect').mockImplementation(() => { throw new Error('NETWORK: tls.connect'); }),
      vi.spyOn(http, 'request').mockImplementation(() => { throw new Error('NETWORK: http.request'); }),
      vi.spyOn(https, 'request').mockImplementation(() => { throw new Error('NETWORK: https.request'); }),
      vi.spyOn(http, 'get').mockImplementation(() => { throw new Error('NETWORK: http.get'); }),
      vi.spyOn(https, 'get').mockImplementation(() => { throw new Error('NETWORK: https.get'); }),
      vi.spyOn(dns, 'lookup').mockImplementation(() => { throw new Error('NETWORK: dns.lookup'); }),
    ];

    const rec = loadRecord('valid-pay.json');
    const { receipt, publicKey } = signedReceipt(rec, true);
    const report = verify(receipt, { publicKey });

    expect(report.ok).toBe(true);
    for (const g of guards) expect(g).not.toHaveBeenCalled();
  });
});
