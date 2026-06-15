/**
 * AW-6 full-receipt verify integration tests — the Phase-2 gate. Asserts the
 * acceptance criteria over a receipt produced by proof():
 *   - full-receipt-verifies-offline-pass (AC1)
 *   - flip-one-byte-fails-and-names-check across the WHOLE layer matrix (AC2):
 *       artifact hash → signature; checkpoint root → checkpoint; a tree sibling →
 *       inclusion; an anchor byte → anchor.
 *   - receipt-is-self-contained-no-network (AC3): zero network during verify.
 *   - proof-bundle-roundtrips (AC4).
 *   - checkpoint-cadence-bounds-record-time (AC5): the report phrases time as a
 *     BOUND by the checkpoint anchor, never a per-record qualified time, and
 *     labels the anchor weight honestly. Also exercises the RFC 3161 anchor path
 *     (qualified ONLY when the trust anchor declares it).
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
import { verify } from '../../src/verify/index.js';
import { proof, checkpoint } from '../../src/ops/index.js';
import {
  ReferenceLog,
  createTestNoteSigner,
  hashLeaf,
  toHex,
  fromHex,
} from '../../src/log/index.js';
import {
  signEnvelope,
  createTestSigner,
  buildStatement,
  statementPayloadBytes,
} from '../../src/envelope/index.js';
import { buildTestOtsProof } from '../../src/anchor/index.js';
import { buildTimeStampToken, makeTsaKeyPair } from '../anchor/rfc3161-fixture.js';
import type { WitnessRecord } from '../../src/schema/index.js';
import type { FullReceipt } from '../../src/ops/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');
function loadRecord(name: string): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, name), 'utf8')) as WitnessRecord;
}

const ORIGIN = 'awp.example/witness-log';

/** Build a full receipt with an OTS anchor; `record` sits at leaf 1 of 4. The
 * committed leaf is the EXACT signed payload bytes (validated record). */
function buildFullReceipt(record: WitnessRecord, opts: { confirmed?: boolean } = {}) {
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

  const anchors = [
    {
      type: 'ots' as const,
      checkpoint_root: cp.rootHex,
      ots_proof_b64: buildTestOtsProof(Buffer.from(cp.rootHex, 'hex'), {
        confirmed: opts.confirmed ?? true,
        height: 842000,
      }).toString('base64'),
      pending: !(opts.confirmed ?? true),
    },
  ];

  const receipt = proof(index, {
    store: log,
    record,
    envelope,
    signerPublicKey: note.publicKey,
    checkpoint: cp,
    anchors,
  });
  return { receipt, publicKey };
}

describe('AC1 — full receipt verifies offline (PASS)', () => {
  it('passes every layer: signature, statement, schema, profile, claim-class, chain, checkpoint, inclusion, anchor', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    for (const name of ['signature', 'schema', 'profile', 'claim-class', 'chain-link', 'checkpoint', 'inclusion', 'anchor']) {
      const c = report.checks.find((x) => x.name === name);
      expect(c, `check ${name} present`).toBeDefined();
      expect(c?.ok, `check ${name} PASS`).toBe(true);
    }
  });

  it('works for the composite profile too', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-composite.json'));
    expect(verify(receipt, { publicKey }).ok).toBe(true);
  });
});

describe('AC2 — one-byte tamper fails and names the broken check (layer matrix)', () => {
  it('artifact/intent hash flip → FAIL names "signature"', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const env = receipt.envelope as { payload: string };
    const decoded = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    decoded.predicate.intent.params_hash = 'b' + decoded.predicate.intent.params_hash.slice(1);
    env.payload = Buffer.from(JSON.stringify(decoded)).toString('base64');
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });

  it('inclusion sibling flip → FAIL names "inclusion" (checkpoint still PASSES)', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const sib = receipt.inclusion!.siblings[0]!;
    sib.hash = (sib.hash[0] === 'a' ? 'b' : 'a') + sib.hash.slice(1);
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'inclusion')?.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'checkpoint')?.ok).toBe(true);
  });

  it('checkpoint-root flip (inside the signed note) → FAIL names "checkpoint"', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    // Flip a char in the base64 root line of the signed note → note signature breaks.
    const note = receipt.checkpoint!.note;
    const lines = note.split('\n');
    // line index 2 is the base64 root (origin, size, root).
    const ch = lines[2]![0] === 'A' ? 'B' : 'A';
    lines[2] = ch + lines[2]!.slice(1);
    receipt.checkpoint!.note = lines.join('\n');
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'checkpoint')?.ok).toBe(false);
  });

  it('checkpoint_root convenience field flipped (note intact) → FAIL names "checkpoint" (field≠signed root)', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    receipt.checkpoint_root = (receipt.checkpoint_root![0] === 'a' ? 'b' : 'a') + receipt.checkpoint_root!.slice(1);
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'checkpoint')?.ok).toBe(false);
  });

  it('anchor proof byte flip → FAIL names "anchor"', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const a = receipt.anchors![0] as { ots_proof_b64: string };
    const buf = Buffer.from(a.ots_proof_b64, 'base64');
    buf[buf.length - 1] = (buf[buf.length - 1] ?? 0) ^ 0xff; // corrupt the attestation tail
    a.ots_proof_b64 = buf.toString('base64');
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'anchor')?.ok).toBe(false);
  });

  it('anchor checkpoint_root pointed elsewhere → FAIL names "anchor"', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const a = receipt.anchors![0] as { checkpoint_root: string };
    a.checkpoint_root = 'f'.repeat(64);
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'anchor')?.ok).toBe(false);
  });
});

describe('AC3 — self-contained, zero network during verify', () => {
  afterEach(() => vi.restoreAllMocks());

  it('makes no socket / connect / DNS / http(s) request verifying the full receipt', () => {
    const guards = [
      vi.spyOn(net, 'connect').mockImplementation(() => { throw new Error('NETWORK'); }),
      vi.spyOn(net, 'createConnection').mockImplementation(() => { throw new Error('NETWORK'); }),
      vi.spyOn(tls, 'connect').mockImplementation(() => { throw new Error('NETWORK'); }),
      vi.spyOn(http, 'request').mockImplementation(() => { throw new Error('NETWORK'); }),
      vi.spyOn(https, 'request').mockImplementation(() => { throw new Error('NETWORK'); }),
      vi.spyOn(dns, 'lookup').mockImplementation(() => { throw new Error('NETWORK'); }),
    ];
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    for (const g of guards) expect(g).not.toHaveBeenCalled();
  });

  it('verifies from a JSON round-trip with NO external input beyond the receipt itself', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    // Serialize → parse, proving the receipt is fully self-describing.
    const roundTripped = JSON.parse(JSON.stringify(receipt)) as FullReceipt;
    expect(verify(roundTripped, { publicKey }).ok).toBe(true);
  });
});

describe('AC4 — proof bundle round-trips through verify', () => {
  it('every applicable check passes and the report is fully legible', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    for (const c of report.checks) {
      expect(typeof c.name).toBe('string');
      expect(typeof c.ok).toBe('boolean');
      expect(c.reason.length).toBeGreaterThan(0);
    }
  });
});

describe('AC5 — time is bounded and stated honestly', () => {
  it('phrases the record time as BOUNDED by the checkpoint anchor (not a per-record time)', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'), { confirmed: true });
    const report = verify(receipt, { publicKey });
    const anchor = report.checks.find((c) => c.name === 'anchor');
    expect(anchor?.reason).toMatch(/existed no later than the checkpoint/);
    expect(anchor?.reason).toMatch(/trust-minimized/);
    expect(anchor?.reason).not.toMatch(/qualified/); // OTS is never qualified
  });

  it('labels a pending OTS anchor honestly (calendar-pending, not block-confirmed)', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'), { confirmed: false });
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/pending|not yet block-confirmed/);
  });

  it('the report always carries the verbatim honesty-boundary line', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    const report = verify(receipt, { publicKey });
    expect(report.boundary).toMatch(/integrity-since-witness only/);
    expect(report.boundary).toMatch(/does NOT prove completeness/);
  });
});

describe('RFC 3161 anchor path — qualified ONLY when the trust anchor declares it', () => {
  /** A full receipt whose anchor is a REAL RFC 3161 token over the checkpoint root. */
  function buildRfc3161Receipt() {
    const record = loadRecord('valid-pay.json');
    const { signer: envSigner, publicKey } = createTestSigner('env-key');
    const envelope = signEnvelope(record, envSigner);
    const log = new ReferenceLog(ORIGIN, { checkpointEvery: 2 });
    const index = log.append(Buffer.from((envelope as { payload: string }).payload, 'base64'));
    log.append(new TextEncoder().encode('sibling-1'));
    const note = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, note.signer);

    const tsa = makeTsaKeyPair('rsa');
    const { base64 } = buildTimeStampToken({
      data: fromHex(cp.rootHex),
      tsa,
      genTime: new Date('2026-06-11T12:00:00Z'),
    });
    const receipt = proof(index, {
      store: log,
      record,
      envelope,
      signerPublicKey: note.publicKey,
      checkpoint: cp,
      anchors: [{ type: 'rfc3161', checkpoint_root: cp.rootHex, tst_der_b64: base64 }],
    });
    return { receipt, publicKey, tsaPem: tsa.publicKeyPem };
  }

  it('verifies and reports a plain TIMESTAMP against a non-qualified anchor', () => {
    const { receipt, publicKey, tsaPem } = buildRfc3161Receipt();
    const report = verify(receipt, {
      publicKey,
      rfc3161TrustAnchor: { publicKey: tsaPem, qualified: false },
    });
    expect(report.ok).toBe(true);
    const anchor = report.checks.find((c) => c.name === 'anchor');
    expect(anchor?.reason).toMatch(/timestamp \(non-qualified TSA\)/);
    expect(anchor?.reason).toMatch(/genTime 2026-06-11T12:00:00/);
    expect(anchor?.reason).not.toMatch(/eIDAS/);
  });

  it('reports QUALIFIED weight only when the operator declares the anchor qualified', () => {
    const { receipt, publicKey, tsaPem } = buildRfc3161Receipt();
    const report = verify(receipt, {
      publicKey,
      rfc3161TrustAnchor: { publicKey: tsaPem, qualified: true },
    });
    expect(report.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/qualified \(eIDAS Art\. 41 presumption\)/);
  });

  it('FAILS the anchor when an RFC 3161 token is present but no trust anchor is supplied', () => {
    const { receipt, publicKey } = buildRfc3161Receipt();
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/no trust anchor supplied/);
  });

  it('reads an embedded rfc3161_trust_anchor so the receipt is self-contained', () => {
    const { receipt, publicKey, tsaPem } = buildRfc3161Receipt();
    (receipt as unknown as Record<string, unknown>)['rfc3161_trust_anchor'] = {
      public_key_pem: tsaPem,
      qualified: true,
      name: 'Test QTSP',
    };
    const report = verify(receipt, { publicKey }); // no trust anchor in options
    expect(report.ok).toBe(true);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/qualified/);
  });

  it('FAILS the anchor when the RFC 3161 token signature is corrupt (named sub-check)', () => {
    const record = loadRecord('valid-pay.json');
    const { signer: envSigner, publicKey } = createTestSigner('env-key');
    const envelope = signEnvelope(record, envSigner);
    const log = new ReferenceLog(ORIGIN, { checkpointEvery: 2 });
    const index = log.append(Buffer.from((envelope as { payload: string }).payload, 'base64'));
    log.append(new TextEncoder().encode('sibling-1'));
    const note = createTestNoteSigner(ORIGIN);
    const cp = checkpoint(log, note.signer);
    const tsa = makeTsaKeyPair('rsa');
    const { base64 } = buildTimeStampToken({ data: fromHex(cp.rootHex), tsa, corruptSignature: true });
    const receipt = proof(index, {
      store: log,
      record,
      envelope,
      signerPublicKey: note.publicKey,
      checkpoint: cp,
      anchors: [{ type: 'rfc3161', checkpoint_root: cp.rootHex, tst_der_b64: base64 }],
    });
    const report = verify(receipt, { publicKey, rfc3161TrustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/RFC 3161 anchor failed/);
  });
});

describe('anchor — unrecognized type is fail-closed (never reported as passed)', () => {
  it('FAILS the anchor for an unknown anchor type', () => {
    const { receipt, publicKey } = buildFullReceipt(loadRecord('valid-pay.json'));
    // Replace the OTS anchor with a bogus type the verifier does not recognize.
    (receipt.anchors as unknown[]) = [{ type: 'simile', checkpoint_root: receipt.checkpoint_root }];
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === 'anchor')?.reason).toMatch(/unrecognized anchor type/);
  });
});

describe('committed sample + fixtures match the spec walkthrough', () => {
  const samples = join(here, '..', '..', 'samples');
  const fixtures = join(here, 'fixtures');

  it('samples/receipt.json verifies PASS with its embedded key', () => {
    const receipt = JSON.parse(readFileSync(join(samples, 'receipt.json'), 'utf8')) as FullReceipt & {
      public_key_raw_base64: string;
    };
    const publicKey = new Uint8Array(Buffer.from(receipt.public_key_raw_base64, 'base64'));
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(true);
    // The sample exercises every full-receipt layer.
    for (const name of ['checkpoint', 'inclusion', 'anchor']) {
      expect(report.checks.find((c) => c.name === name)?.ok).toBe(true);
    }
  });

  it('full-receipt-tampered.json FAILS and names "inclusion"', () => {
    const receipt = JSON.parse(readFileSync(join(fixtures, 'full-receipt-tampered.json'), 'utf8')) as FullReceipt & {
      public_key_raw_base64: string;
    };
    const publicKey = new Uint8Array(Buffer.from(receipt.public_key_raw_base64, 'base64'));
    const report = verify(receipt, { publicKey });
    expect(report.ok).toBe(false);
    const failed = report.checks.filter((c) => !c.ok).map((c) => c.name);
    expect(failed).toContain('inclusion');
  });

  it('the sample fold uses the documented leaf rule (hashLeaf of statement bytes) — auditor-reproducible', () => {
    const receipt = JSON.parse(readFileSync(join(samples, 'receipt.json'), 'utf8')) as FullReceipt;
    const env = receipt.envelope as { payload: string };
    const statement = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    const record = statement.predicate as WitnessRecord;
    // Recompute the committed leaf the way an auditor would (decode record → build
    // Statement → canonical bytes → hashLeaf) and confirm it equals the inclusion
    // proof's leafHash. This pins "no hidden canonicalization".
    const leafBytes = statementPayloadBytes(buildStatement(record));
    expect(toHex(hashLeaf(leafBytes))).toBe(receipt.inclusion?.leafHash);
  });
});
