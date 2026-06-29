/**
 * generate-paybotfin-scenarios.mjs
 *
 * Mint REAL composite witness receipts for the 3 NEW PayBotFin demo scenarios
 * (fintech vendor pay, gaming in-game currency grant, e-commerce checkout).
 * The existing bank/refund scenario is NOT touched (it has a confirmed OTS
 * anchor and stays as-is).
 *
 * For each scenario we write three sidecar files into the demo folder:
 *   composite-receipt-<scenario>.json                  genuine  → verify PASS
 *   composite-receipt-<scenario>-tampered.json         sigTamper → FAIL @ signature
 *   composite-receipt-<scenario>-tampered-inclusion.json inclTamper → FAIL @ inclusion ONLY
 *
 * HONESTY: the OTS anchor for these NEW scenarios is a genuine *pending* calendar
 * attestation (confirmed:false). `awp verify` reports it as "calendar-pending,
 * not yet block-confirmed" — NOT a fabricated Bitcoin block. The demo UI must say
 * "timestamp pending" for these scenarios.
 *
 * Deterministic Ed25519 seeds → reproducible. Crypto comes entirely from AWP
 * (no hand-rolled signing/Merkle/anchor).
 *
 *   node tools/generate-paybotfin-scenarios.mjs
 */
import { writeFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import {
  signEnvelope,
  signerFromPrivateKey,
  ReferenceLog,
  checkpoint,
  proof,
  buildTestOtsProof,
  validateWitnessRecord,
} from '../dist/index.js';

const DEMO_DIR = 'D:/1.GITHUB/AIOX-Enterprise/docs/partnerships/paybotfin-deploy/demo';

/** Deterministic Ed25519 keypair from a >=32-byte seed string (PKCS#8 DER wrap). */
function ed25519FromSeed(seedText) {
  const seed = Buffer.from(seedText, 'utf8').subarray(0, 32);
  if (seed.length !== 32) throw new Error('seed must be >=32 bytes: ' + seedText);
  const privDer = Buffer.concat([
    Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
    seed,
  ]);
  const privateKey = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey);
  const rawPub = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  return { privateKey, publicKey, rawPub };
}

const sha256hex = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Build one composite WitnessRecord from scenario params. Modeled on the
 * existing (passing) refund composite receipt: intent + mandate-class
 * authorization + artifact + 2 verifications.
 */
function buildRecord(s) {
  const artifactBytes = Buffer.from(s.artifactText, 'utf8');
  const artifactHash = sha256hex(artifactBytes);
  const paramsHash = sha256hex(Buffer.from(s.paramsText, 'utf8'));
  const policyHash = sha256hex(Buffer.from(s.policyId, 'utf8'));
  const assertionHash = sha256hex(Buffer.from(s.scenario + ':mandate-assertion', 'utf8'));
  const hitlSubjectHash = sha256hex(Buffer.from(s.scenario + ':hitl-approval', 'utf8'));

  return {
    profile: 'composite',
    deployment: {
      log_id: 'log:paybotfin-demo-eu-1',
      node_key_fpr: 'SHA256:demodeploymentkeyfingerprint000000000001',
      software: { name: 'paybot', version: '1.4.0-demo' },
    },
    intent: {
      agent: {
        agent_id: s.agentId,
        agent_key_fpr: 'SHA256:demoagentkeyfpr' + s.scenario.padEnd(4, '0').slice(0, 4),
        runtime_ref: 'runtime:node22-demo',
      },
      action: s.action,
      target_ref: s.targetRef,
      params_hash: paramsHash,
      started_at: s.startedAt,
      ended_at: s.endedAt,
      policy: {
        policy_id: s.policyId,
        policy_hash: policyHash,
        decision: s.decision,
      },
    },
    authorization: {
      principal_ref: 'principal:opaque-approver-demo',
      credential: {
        type: 'ap2-mandate',
        issuer: 'did:web:approvals.acme-demo.example',
        assertion_hash: assertionHash,
        status_check: {
          method: 'token-status-list',
          checked_at: s.startedAt,
          result: 'valid',
        },
        trust_anchor:
          'jwks:https://approvals.acme-demo.example/.well-known/jwks.json@' + s.startedAt,
        verified: true,
        verifier_policy_version: 'vp:2026.6',
      },
    },
    artifacts: [
      {
        role: 'output',
        digest: { alg: 'sha256', value: artifactHash },
        media_type: 'application/pdf',
        size: artifactBytes.length,
        pii_bearing: false,
        provenance: {
          c2pa_manifest_hash: null,
          c2pa_validation: 'absent',
          origin_claims: [
            { claim: 'issued-by-acme-demo', asserted_by: 'acme-demo', verified: false },
          ],
        },
      },
    ],
    verifications: [
      {
        check: 'ap2.payment_mandate.sd_jwt_signature',
        subject_hash: assertionHash,
        issuer: 'did:web:approvals.acme-demo.example',
        method: 'jwks-fetch',
        result: 'pass',
        claim_class: 'verified-against',
      },
      {
        check: 'hitl.human_approval.recorded',
        subject_hash: hitlSubjectHash,
        issuer: 'acme-demo:approval-flow',
        method: 'dashboard-hitl-approval',
        result: 'pass',
        claim_class: 'asserted-by',
      },
    ],
    chain: {
      prev_record_hash: '0'.repeat(64),
    },
  };
}

/** Decode the base64 DSSE payload to a JS object. */
function decodePayload(b64) {
  return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}
/** Encode a JS object back to base64 (raw bytes of compact JSON the signer used). */

function mintScenario(s) {
  const env = ed25519FromSeed(`paybotfin-demo-${s.scenario}-envelope-seed-32bytes!!!!`);
  const logKey = ed25519FromSeed(`paybotfin-demo-${s.scenario}-logsign-seed-32bytes!!!!`);

  const record = buildRecord(s);
  const validation = validateWitnessRecord(record);
  if (!validation.ok) {
    console.error(`[${s.scenario}] schema invalid:`, validation.errors);
    process.exit(1);
  }

  const envelopeSigner = signerFromPrivateKey(env.privateKey, 'paybotfin-demo-witness-key');
  const envelope = signEnvelope(validation.record, envelopeSigner);

  // 4-leaf log so the inclusion proof has real siblings (our record at index 1).
  const ORIGIN = 'paybotfin.demo/witness-log';
  const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
  const ourLeaf = Buffer.from(envelope.payload, 'base64');
  log.append(Buffer.from(`paybotfin-${s.scenario}-sibling-0`, 'utf8'));
  const ourIndex = log.append(ourLeaf);
  log.append(Buffer.from(`paybotfin-${s.scenario}-sibling-2`, 'utf8'));
  log.append(Buffer.from(`paybotfin-${s.scenario}-sibling-3`, 'utf8'));

  const noteSigner = {
    name: ORIGIN,
    publicKey: logKey.rawPub,
    sign: (bytes) => new Uint8Array(edSign(null, bytes, logKey.privateKey)),
  };
  const cp = checkpoint(log, noteSigner);

  // HONEST anchor: pending calendar attestation (NOT a fabricated Bitcoin block).
  const otsProof = buildTestOtsProof(Buffer.from(cp.rootHex, 'hex'), { confirmed: false });
  const anchors = [
    {
      type: 'ots',
      checkpoint_root: cp.rootHex,
      ots_proof_b64: otsProof.toString('base64'),
      pending: true,
    },
  ];

  const bundle = proof(ourIndex, {
    store: log,
    record: validation.record,
    envelope,
    signerPublicKey: logKey.rawPub,
    checkpoint: cp,
    anchors,
  });

  const publicKeyPem = env.publicKey.export({ type: 'spki', format: 'pem' });
  const publicKeyRawB64 = Buffer.from(env.rawPub).toString('base64');

  const genuine = {
    _comment: s.commentGenuine,
    public_key_pem: publicKeyPem,
    public_key_raw_base64: publicKeyRawB64,
    ...bundle,
    decoded: decodePayload(envelope.payload).predicate,
  };

  // ── sigTamper: flip ONE hex char in the signed artifact digest, keep the sig.
  const sig = JSON.parse(JSON.stringify(genuine));
  const p = decodePayload(sig.envelope.payload);
  const dv = p.predicate.artifacts[0].digest.value;
  p.predicate.artifacts[0].digest.value = (dv[0] === '0' ? '1' : '0') + dv.slice(1);
  sig.envelope.payload = Buffer.from(JSON.stringify(p), 'utf8').toString('base64');
  sig._comment = s.commentSig;
  // decoded panel stays the genuine view (the tamper is in the signed bytes only)

  // ── inclTamper: flip ONE hex char in inclusion.siblings[0].hash.
  const incl = JSON.parse(JSON.stringify(genuine));
  const sib0 = incl.inclusion.siblings[0].hash;
  incl.inclusion.siblings[0].hash = (sib0[0] === 'a' ? 'b' : 'a') + sib0.slice(1);
  incl._comment = s.commentIncl;

  const base = `${DEMO_DIR}/composite-receipt-${s.scenario}`;
  writeFileSync(`${base}.json`, JSON.stringify(genuine, null, 2) + '\n');
  writeFileSync(`${base}-tampered.json`, JSON.stringify(sig, null, 2) + '\n');
  writeFileSync(`${base}-tampered-inclusion.json`, JSON.stringify(incl, null, 2) + '\n');

  console.error(`[${s.scenario}] wrote 3 files (root ${cp.rootHex.slice(0, 12)}…, decision ${s.decision})`);
}

const SCENARIOS = [
  {
    scenario: 'fintech',
    agentId: 'agent:payout-bot',
    action: 'payment.vendor_payout',
    targetRef: 'invoice:INV-2026-0042',
    decision: 'allow',
    paramsText: 'fintech vendor payout EUR 1280.00 to vendor:acme-supplies invoice INV-2026-0042',
    policyId: 'policy:vendor-payout-with-invoice-v1',
    artifactText:
      'REMITTANCE ADVICE — PayBotFin demo\nVendor: ACME Supplies Oy\nInvoice: INV-2026-0042\nAmount: EUR 1280.00\nStatus: scheduled (testnet/mock)\n',
    startedAt: '2026-06-17T10:20:00Z',
    endedAt: '2026-06-17T10:20:05Z',
    commentGenuine:
      'PayBotFin demo composite receipt — FINTECH VENDOR PAY. One record binds: a payout agent intent (pay invoice INV-2026-0042, EUR 1280.00) + a remittance-advice artifact + a human HITL approval + an ap2-mandate verification. Signed DSSE envelope + RFC 9162 inclusion proof + signed C2SP checkpoint + OpenTimestamps PENDING calendar anchor (honest: not yet Bitcoin-confirmed). `awp verify` prints PASS offline; the anchor reports calendar-pending. HONESTY: integrity-since-witness only; HITL approval is asserted-by (not cryptographic principal binding); testnet/mock settlement, no real money; tamper-EVIDENT not tamper-proof; demo signing key.',
    commentSig:
      'PayBotFin demo TAMPERED (signature) — FINTECH. ONE flipped hex char in the remittance artifact digest inside the signed Statement. The Ed25519 DSSE signature no longer matches, so `awp verify` prints FAIL naming the "signature" check. Tamper-EVIDENT offline.',
    commentIncl:
      'PayBotFin demo TAMPERED (inclusion) — FINTECH. ONE flipped hex char in inclusion.siblings[0].hash. Record + signature untouched (those still PASS); the leaf no longer folds to the signed checkpoint root, so `awp verify` FAILs naming ONLY the "inclusion" check.',
  },
  {
    scenario: 'gaming',
    agentId: 'agent:economy-bot',
    action: 'wallet.currency_grant',
    targetRef: 'player:PL-88273',
    decision: 'deny',
    paramsText: 'in-game currency grant 50000 gold to player:PL-88273 exceeds per-grant ceiling 10000',
    policyId: 'policy:currency-grant-ceiling-v1',
    artifactText:
      'GRANT DECISION RECORD — PayBotFin demo\nPlayer: PL-88273\nRequested: 50000 gold\nPolicy ceiling: 10000 gold\nDecision: DENY (exceeds ceiling)\nReviewer: human moderator (recorded)\n',
    startedAt: '2026-06-17T11:05:00Z',
    endedAt: '2026-06-17T11:05:03Z',
    commentGenuine:
      'PayBotFin demo composite receipt — GAMING IN-GAME CURRENCY GRANT (DENY case). One record binds: an economy agent intent (grant 50000 gold) + a grant-decision artifact + a human moderator review + an ap2-mandate verification. The policy decision is DENY (the request exceeded the per-grant ceiling): this is the honest "deny" case backing the "allow + deny" copy — the witness record proves an out-of-policy action was correctly blocked and recorded. Signed DSSE envelope + RFC 9162 inclusion proof + signed C2SP checkpoint + OpenTimestamps PENDING calendar anchor (not yet Bitcoin-confirmed). `awp verify` prints PASS offline. HONESTY: integrity-since-witness only; HITL review asserted-by; testnet/mock; tamper-EVIDENT; demo key.',
    commentSig:
      'PayBotFin demo TAMPERED (signature) — GAMING. ONE flipped hex char in the grant-decision artifact digest inside the signed Statement → the DSSE signature no longer matches → `awp verify` FAILs naming the "signature" check.',
    commentIncl:
      'PayBotFin demo TAMPERED (inclusion) — GAMING. ONE flipped hex char in inclusion.siblings[0].hash → leaf no longer folds to the signed checkpoint root → `awp verify` FAILs naming ONLY the "inclusion" check.',
  },
  {
    scenario: 'ecom',
    agentId: 'agent:checkout-bot',
    action: 'payment.capture',
    targetRef: 'order:SHOP-55012',
    decision: 'allow',
    paramsText: 'e-commerce checkout capture EUR 219.90 for order SHOP-55012 (flagged high-value, human reviewed)',
    policyId: 'policy:checkout-capture-with-review-v1',
    artifactText:
      'ORDER CONFIRMATION — PayBotFin demo\nOrder: SHOP-55012\nAmount: EUR 219.90\nReview: high-value, human-approved\nStatus: captured (testnet/mock)\n',
    startedAt: '2026-06-17T12:40:00Z',
    endedAt: '2026-06-17T12:40:04Z',
    commentGenuine:
      'PayBotFin demo composite receipt — E-COMMERCE CHECKOUT. One record binds: a checkout agent intent (capture EUR 219.90 on order SHOP-55012) + an order-confirmation artifact + a human HITL approval (high-value review) + an ap2-mandate verification. Signed DSSE envelope + RFC 9162 inclusion proof + signed C2SP checkpoint + OpenTimestamps PENDING calendar anchor (not yet Bitcoin-confirmed). `awp verify` prints PASS offline; anchor reports calendar-pending. HONESTY: integrity-since-witness only; HITL asserted-by; testnet/mock; tamper-EVIDENT; demo key.',
    commentSig:
      'PayBotFin demo TAMPERED (signature) — E-COMMERCE. ONE flipped hex char in the order-confirmation artifact digest inside the signed Statement → DSSE signature mismatch → `awp verify` FAILs naming the "signature" check.',
    commentIncl:
      'PayBotFin demo TAMPERED (inclusion) — E-COMMERCE. ONE flipped hex char in inclusion.siblings[0].hash → leaf no longer folds to the signed checkpoint root → `awp verify` FAILs naming ONLY the "inclusion" check.',
  },
];

for (const s of SCENARIOS) mintScenario(s);
console.error('done — 9 files written to', DEMO_DIR);
