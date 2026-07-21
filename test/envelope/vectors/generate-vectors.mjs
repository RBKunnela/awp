/**
 * Regenerate the committed envelope vectors from the compiled library.
 *
 *   npm run build && node test/envelope/vectors/generate-vectors.mjs
 *
 * Produces:
 *   - signed-envelope.json   valid DSSE envelope over valid-pay (deterministic key)
 *   - tampered-envelope.json same envelope with one payload byte flipped (sig fails)
 *   - wrong-key.json         same valid envelope + a different public key (sig fails)
 *
 * Uses the same Ed25519 private key PEM previously committed so auditors can
 * re-derive signatures. PAE known-answer vectors are independent of PREDICATE_TYPE
 * and are not rewritten here.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { signEnvelope, signerFromPrivateKey } from '../../../dist/envelope/dsse.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', '..', 'schema', 'vectors');

const privateKeyPem =
  '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICRmMPrizyFrceswMSJxU6T12j5753fdvbxjfK1hhH9X\n-----END PRIVATE KEY-----\n';
const publicKeyPem =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAiRjffwsYd57Y4Vrijhgu11ZGdYs4vt8Kiox++G/iF7g=\n-----END PUBLIC KEY-----\n';
const wrongPublicKeyPem =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQuKJ89IeLBqXEmTcr8lhvt5oV0Cvy0NXXLl0SEiw4eo=\n-----END PUBLIC KEY-----\n';

const privateKey = createPrivateKey(privateKeyPem);
const publicKey = createPublicKey(publicKeyPem);
const publicKeyRawB64 = Buffer.from(
  publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
).toString('base64');

const record = JSON.parse(readFileSync(join(schemaVectors, 'valid-pay.json'), 'utf8'));
const signer = signerFromPrivateKey(privateKey, 'awp-vector-key-1');
const envelope = signEnvelope(record, signer);

const signed = {
  _comment:
    'AW-2 valid signed DSSE envelope over the canonical valid-pay record. Verifies with public_key_pem. Reproducible: the canonical statement payload is fixed; signature is over PAE(payloadType, canonical-statement-bytes) with the committed key.',
  public_key_pem: publicKeyPem,
  public_key_raw_base64: publicKeyRawB64,
  private_key_pem: privateKeyPem,
  envelope,
};
writeFileSync(join(here, 'signed-envelope.json'), JSON.stringify(signed, null, 2) + '\n');

// Tamper: flip one byte of the base64-decoded payload, keep original signature.
const tamperedPayload = Buffer.from(envelope.payload, 'base64');
tamperedPayload[0] = tamperedPayload[0] ^ 0x01;
const tampered = {
  _comment:
    'AW-2 tamper vector: signed-envelope.json with one byte of the base64-decoded payload flipped. MUST fail the signature check against public_key_pem.',
  public_key_pem: publicKeyPem,
  envelope: {
    ...envelope,
    payload: tamperedPayload.toString('base64'),
  },
};
writeFileSync(join(here, 'tampered-envelope.json'), JSON.stringify(tampered, null, 2) + '\n');

const wrongKey = {
  _comment:
    'AW-2 wrong-key vector: the valid signed envelope verified against a DIFFERENT public key. MUST fail the signature check.',
  wrong_public_key_pem: wrongPublicKeyPem,
  envelope,
};
writeFileSync(join(here, 'wrong-key.json'), JSON.stringify(wrongKey, null, 2) + '\n');

console.log('wrote signed-envelope.json, tampered-envelope.json, wrong-key.json');
console.log('predicateType namespace is now baked into envelope.payload (base64)');
