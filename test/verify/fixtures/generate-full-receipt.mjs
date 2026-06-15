/**
 * Regenerate the AW-6 FULL-receipt fixtures + the committed auditor sample from
 * the compiled library.
 *
 *   npm run build && node test/verify/fixtures/generate-full-receipt.mjs
 *
 * Produces:
 *   - ../../../samples/receipt.json          the auditor 10-minute walkthrough
 *                                            sample: a full, self-contained receipt
 *                                            (signed envelope + RFC 9162 inclusion
 *                                            proof + signed C2SP checkpoint + an
 *                                            OpenTimestamps anchor). `awp verify`
 *                                            prints PASS for it, offline.
 *   - full-receipt.json                      same content, used by the verify/CLI
 *                                            integration tests.
 *   - full-receipt-tampered.json             a byte-identical copy with ONE flipped
 *                                            hex char in the inclusion proof's root
 *                                            path — the inclusion check FAILs.
 *
 * Everything is DETERMINISTIC (fixed Ed25519 seeds), so the committed sample is
 * reproducible and an auditor can re-derive every value:
 *   - The log leaf for a record is the canonical in-toto Statement bytes the DSSE
 *     envelope signs: statementPayloadBytes(buildStatement(record)).
 *   - The Merkle root is RFC 9162 (raw-byte) over the four leaves.
 *   - The checkpoint is a C2SP signed note over (origin, size=4, root).
 *   - The OTS proof commits that root (a confirmed Bitcoin-block test attestation).
 *
 * The committed files are checked in; this script documents exactly how they were
 * made.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createPrivateKey, createPublicKey, sign as edSign } from 'node:crypto';
import {
  signEnvelope,
  signerFromPrivateKey,
  ReferenceLog,
  checkpoint,
  proof,
  buildTestOtsProof,
} from '../../../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', '..', 'schema', 'vectors');
const samplesDir = join(here, '..', '..', '..', 'samples');

/** Deterministic Ed25519 private key from a 32-byte seed (PKCS#8 DER wrap). */
function ed25519FromSeed(seedText) {
  const seed = Buffer.from(seedText, 'utf8').subarray(0, 32);
  if (seed.length !== 32) throw new Error('seed must be >=32 bytes');
  const privDer = Buffer.concat([
    Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
    seed,
  ]);
  const privateKey = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const publicKey = createPublicKey(privateKey);
  const rawPub = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  return { privateKey, publicKey, rawPub };
}

// ── 1. The witnessed record + its signing key (the envelope key). ────────────
const record = JSON.parse(readFileSync(join(schemaVectors, 'valid-pay.json'), 'utf8'));
const env = ed25519FromSeed('awp-aw6-envelope-key-seed-32bytes!!!');
const envelopeSigner = signerFromPrivateKey(env.privateKey, 'awp-aw6-envelope-key');
const envelope = signEnvelope(record, envelopeSigner);
const publicKeyPem = env.publicKey.export({ type: 'spki', format: 'pem' });
const publicKeyRawB64 = Buffer.from(env.rawPub).toString('base64');

// ── 2. A reference append-only log with FOUR leaves (non-trivial tree). ──────
// Three "other" records flank ours so the inclusion proof has real siblings. The
// other leaves are opaque-but-realistic bytes; only ours must be the canonical
// Statement bytes (proof() enforces that).
const ORIGIN = 'awp.example/witness-log';
const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });

// The canonical leaf is the EXACT signed payload bytes (validated record, schema
// defaults applied) — i.e. the envelope payload. Append those so the committed
// leaf equals what the verifier recomputes from the decoded record.
const ourLeaf = Buffer.from(envelope.payload, 'base64');
const otherLeaves = [
  Buffer.from('awp-sample-sibling-leaf-0', 'utf8'),
  Buffer.from('awp-sample-sibling-leaf-2', 'utf8'),
  Buffer.from('awp-sample-sibling-leaf-3', 'utf8'),
];
log.append(otherLeaves[0]); // index 0
const ourIndex = log.append(ourLeaf); // index 1 — our record
log.append(otherLeaves[1]); // index 2
log.append(otherLeaves[2]); // index 3

// ── 3. Seal a signed checkpoint over the size-4 tree. ────────────────────────
const logKey = ed25519FromSeed('awp-aw6-logsign-key-seed-32bytes!!!!');
const noteSigner = {
  name: ORIGIN,
  publicKey: logKey.rawPub,
  sign: (bytes) => new Uint8Array(edSign(null, bytes, logKey.privateKey)),
};
const cp = checkpoint(log, noteSigner);

// ── 4. OpenTimestamps anchor over the checkpoint root (confirmed test proof). ─
const otsProof = buildTestOtsProof(Buffer.from(cp.rootHex, 'hex'), {
  confirmed: true,
  height: 842000,
});
const anchors = [
  {
    type: 'ots',
    checkpoint_root: cp.rootHex,
    ots_proof_b64: otsProof.toString('base64'),
    pending: false,
  },
];

// ── 5. Assemble the full receipt via the producer op. ────────────────────────
const bundle = proof(ourIndex, {
  store: log,
  record,
  envelope,
  signerPublicKey: logKey.rawPub,
  checkpoint: cp,
  anchors,
});

// Add the embedded public key (so `awp verify samples/receipt.json` is one step)
// and a human comment. The key fields sit alongside the receipt body; the CLI
// reads them when --pubkey is omitted.
const receiptOut = {
  _comment:
    'AW-6 full receipt: signed DSSE envelope (valid-pay) + RFC 9162 inclusion proof (leaf 1 of 4) + signed C2SP checkpoint + OpenTimestamps anchor over the checkpoint root. `awp verify samples/receipt.json` prints PASS, offline. Reproduce with test/verify/fixtures/generate-full-receipt.mjs.',
  public_key_pem: publicKeyPem,
  public_key_raw_base64: publicKeyRawB64,
  ...bundle,
};

mkdirSync(samplesDir, { recursive: true });
writeFileSync(join(samplesDir, 'receipt.json'), JSON.stringify(receiptOut, null, 2) + '\n');
writeFileSync(join(here, 'full-receipt.json'), JSON.stringify(receiptOut, null, 2) + '\n');

// ── 6. Tampered: flip ONE hex char in the inclusion proof's first sibling. ───
// This changes the recomputed Merkle root, so the leaf no longer folds to the
// signed checkpoint root → the `inclusion` check FAILs with a named reason. The
// signature, checkpoint, and anchor still pass — proving the failure is isolated
// to the tampered layer (exactly the auditor's byte-flip demo on the tree path).
const tampered = JSON.parse(JSON.stringify(receiptOut));
const sib0 = tampered.inclusion.siblings[0].hash;
const flipped = (sib0[0] === 'a' ? 'b' : 'a') + sib0.slice(1);
tampered.inclusion.siblings[0].hash = flipped;
tampered._comment =
  'AW-6 tampered receipt: ONE flipped hex char in inclusion.siblings[0].hash. The leaf no longer folds to the signed checkpoint root, so `awp verify` prints FAIL naming the "inclusion" check (signature/checkpoint/anchor still pass). The byte-flip demo on the tree path.';
writeFileSync(join(here, 'full-receipt-tampered.json'), JSON.stringify(tampered, null, 2) + '\n');

console.log('wrote samples/receipt.json, full-receipt.json, full-receipt-tampered.json');
console.log('origin       =', ORIGIN);
console.log('checkpoint   = size', cp.size, 'root', cp.rootHex.slice(0, 16) + '…');
console.log('our leaf idx =', ourIndex, '(of', cp.size, 'leaves)');
console.log('tamper       : inclusion.siblings[0].hash %s… -> %s…', sib0.slice(0, 10), flipped.slice(0, 10));
