/**
 * Regenerate the AW-3 verify fixtures from the compiled library.
 *
 *   node test/verify/fixtures/generate-fixtures.mjs
 *
 * Produces, in this directory:
 *   - valid-receipt.json     a signed DSSE envelope over the canonical valid-pay
 *                            record, plus an OpenTimestamps anchor over the
 *                            record's checkpoint root, plus the embedded public
 *                            key (so `awp verify valid-receipt.json` is one step).
 *   - tampered-receipt.json  a byte-identical copy with ONE flipped hex char in
 *                            an artifact/intent digest — the byte-flip → FAIL demo.
 *
 * Run after `npm run build`. The fixtures are committed; this script documents
 * exactly how they were made (re-implementable by an auditor).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  signEnvelope,
  signerFromPrivateKey,
  statementPayloadBytes,
  buildStatement,
  buildTestOtsProof,
} from '../../../dist/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', '..', 'schema', 'vectors');

// Deterministic key from a fixed seed so the fixtures are reproducible.
const seed = Buffer.from('awp-aw3-fixture-key-seed-32bytes!', 'utf8').subarray(0, 32);
const privDer = Buffer.concat([
  Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
  seed,
]);
const { createPrivateKey, createPublicKey } = await import('node:crypto');
const privateKey = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey);
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const publicKeyRawB64 = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');

// Use the committed valid-pay record as the witnessed record.
const record = JSON.parse(readFileSync(join(schemaVectors, 'valid-pay.json'), 'utf8'));

const signer = signerFromPrivateKey(privateKey, 'awp-aw3-fixture-key');
const envelope = signEnvelope(record, signer);

// The Phase-1 record commitment + checkpoint root (record committed directly).
const payloadBytes = statementPayloadBytes(buildStatement(record));
const recordCommitment = createHash('sha256').update(payloadBytes).digest('hex');
const checkpointRoot = recordCommitment; // single-record checkpoint for the fixture
const otsProof = buildTestOtsProof(Buffer.from(checkpointRoot, 'hex'), {
  confirmed: true,
  height: 842000,
});

const validReceipt = {
  _comment:
    'AW-3 valid receipt: signed DSSE envelope over valid-pay, with an OpenTimestamps anchor over the checkpoint root. `awp verify valid-receipt.json` prints PASS. Reproduce with generate-fixtures.mjs.',
  public_key_pem: publicKeyPem,
  public_key_raw_base64: publicKeyRawB64,
  checkpoint_root: checkpointRoot,
  record_commitment: recordCommitment,
  anchors: [
    {
      type: 'ots',
      checkpoint_root: checkpointRoot,
      ots_proof_b64: otsProof.toString('base64'),
      pending: false,
    },
  ],
  envelope,
};

writeFileSync(join(here, 'valid-receipt.json'), JSON.stringify(validReceipt, null, 2) + '\n');

// Tampered: flip ONE hex character in the payload's intent.params_hash. We mutate
// the decoded payload, re-encode WITHOUT re-signing, so the signature no longer
// matches — exactly the byte-flip an auditor performs in the walkthrough.
const tampered = JSON.parse(JSON.stringify(validReceipt));
const decoded = JSON.parse(Buffer.from(tampered.envelope.payload, 'base64').toString('utf8'));
const original = decoded.predicate.intent.params_hash;
const flipped = (original[0] === 'a' ? 'b' : 'a') + original.slice(1);
decoded.predicate.intent.params_hash = flipped;
// Re-encode the mutated statement; signature stays the same → it will not verify.
tampered.envelope.payload = Buffer.from(JSON.stringify(decoded), 'utf8').toString('base64');
tampered._comment =
  'AW-3 tampered receipt: ONE flipped hex char in intent.params_hash inside the signed payload. The DSSE signature no longer verifies. `awp verify tampered-receipt.json` prints FAIL naming the signature check. The byte-flip demo.';

writeFileSync(join(here, 'tampered-receipt.json'), JSON.stringify(tampered, null, 2) + '\n');

console.log('wrote valid-receipt.json and tampered-receipt.json');
console.log('checkpoint_root =', checkpointRoot);
console.log('flipped params_hash: %s -> %s', original.slice(0, 10) + '…', flipped.slice(0, 10) + '…');
