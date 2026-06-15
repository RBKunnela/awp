/**
 * Tests for the DSSE v1.0 envelope (AW-2 dsse.ts) and the five acceptance
 * criteria:
 *   AC1 PAE known-answer vector (pinned, byte-exact);
 *   AC2 encode → decode round-trip (record deep-equals; statement intact);
 *   AC3 tamper detection (one-byte payload change fails `signature`);
 *   AC4 wrong-key detection;
 *   AC5 subject binds target_ref + params_hash (also covered in statement.test).
 *
 * ≥3 tests per exported function across happy / error / edge; fail-closed paths
 * asserted explicitly.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import {
  pae,
  encodePayload,
  statementPayloadBytes,
  signEnvelope,
  decodeEnvelope,
  verifyEnvelope,
  createTestSigner,
  signerFromPrivateKey,
  buildStatement,
  type DsseEnvelope,
} from '../../src/envelope/dsse.js';
import { PAYLOAD_TYPE, validateWitnessRecord, type WitnessRecord } from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');
const envVectors = join(here, 'vectors');

function payRecord(): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, 'valid-pay.json'), 'utf8')) as WitnessRecord;
}
function docRecord(): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, 'valid-doc.json'), 'utf8')) as WitnessRecord;
}

interface PaeCase {
  name: string;
  payloadType: string;
  payload_utf8: string;
  expected_type_byte_length: number;
  expected_payload_byte_length: number;
  pae_string: string;
  pae_hex: string;
}
function paeVectorCases(): PaeCase[] {
  const raw = JSON.parse(readFileSync(join(envVectors, 'pae-known-answer.json'), 'utf8'));
  return raw.cases as PaeCase[];
}

// ---------------------------------------------------------------------------
// AC1 — PAE is correct and pinned.
// ---------------------------------------------------------------------------

describe('[UNIT] pae — AC1 known-answer vectors', () => {
  it('matches every committed known-answer vector byte-for-byte (happy / AC1)', () => {
    for (const c of paeVectorCases()) {
      const payload = new TextEncoder().encode(c.payload_utf8);
      const out = pae(c.payloadType, payload);
      expect(Buffer.from(out).toString('utf8')).toBe(c.pae_string);
      expect(Buffer.from(out).toString('hex')).toBe(c.pae_hex);
    }
  });

  it('uses BYTE length, not character length, for a multibyte payload (edge / AC1)', () => {
    // "é" is one character, two UTF-8 bytes — LEN must be 2.
    const out = pae('text/plain', new TextEncoder().encode('é'));
    expect(Buffer.from(out).toString('utf8')).toBe('DSSEv1 10 text/plain 2 é');
  });

  it('handles an empty payload (LEN 0) (edge)', () => {
    const out = pae(PAYLOAD_TYPE, new Uint8Array(0));
    expect(Buffer.from(out).toString('utf8')).toBe(`DSSEv1 ${PAYLOAD_TYPE.length} ${PAYLOAD_TYPE} 0 `);
  });

  it('is deterministic for the same inputs (happy)', () => {
    const p = new TextEncoder().encode('{"x":1}');
    expect(Buffer.from(pae(PAYLOAD_TYPE, p))).toEqual(Buffer.from(pae(PAYLOAD_TYPE, p)));
  });
});

// ---------------------------------------------------------------------------
// statementPayloadBytes / encodePayload
// ---------------------------------------------------------------------------

describe('[UNIT] statementPayloadBytes', () => {
  it('returns canonical (key-sorted) JSON bytes of the statement (happy)', () => {
    const bytes = statementPayloadBytes(buildStatement(payRecord()));
    const str = Buffer.from(bytes).toString('utf8');
    // key-sorted: "_type" sorts before "predicate", "predicateType", "subject".
    expect(str.startsWith('{"_type":')).toBe(true);
    expect(JSON.parse(str)._type).toBe('https://in-toto.io/Statement/v1');
  });

  it('is deterministic for the same record (happy)', () => {
    const a = statementPayloadBytes(buildStatement(payRecord()));
    const b = statementPayloadBytes(buildStatement(payRecord()));
    expect(Buffer.from(a)).toEqual(Buffer.from(b));
  });

  it('changes when the record changes (edge)', () => {
    const a = statementPayloadBytes(buildStatement(payRecord()));
    const r = payRecord();
    r.intent.action = 'payment.capture';
    const b = statementPayloadBytes(buildStatement(r));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });
});

describe('[UNIT] encodePayload', () => {
  it('encodes a valid record to statement + payload bytes (happy)', () => {
    const result = encodePayload(payRecord());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.statement.predicate.profile).toBe('pay');
      expect(result.payload.length).toBeGreaterThan(0);
    }
  });

  it('fails closed for an invalid record (error)', () => {
    const bad = payRecord() as Partial<WitnessRecord>;
    delete bad.intent;
    const result = encodePayload(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.length).toBeGreaterThan(0);
  });

  it('fails closed for non-object input (edge)', () => {
    expect(encodePayload(undefined).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// signEnvelope
// ---------------------------------------------------------------------------

describe('[UNIT] signEnvelope', () => {
  it('produces a DSSE envelope with base64 payload + signature (happy)', () => {
    const { signer } = createTestSigner('key-1');
    const env = signEnvelope(payRecord(), signer);
    expect(env.payloadType).toBe(PAYLOAD_TYPE);
    expect(env.signatures).toHaveLength(1);
    expect(env.signatures[0]!.keyid).toBe('key-1');
    // base64 payload decodes to the canonical statement JSON.
    const decoded = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
    expect(decoded._type).toBe('https://in-toto.io/Statement/v1');
    // 64-byte Ed25519 signature → 88 base64 chars.
    expect(Buffer.from(env.signatures[0]!.sig, 'base64').length).toBe(64);
  });

  it('omits keyid when the signer has none (edge)', () => {
    const { signer } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    expect(env.signatures[0]!.keyid).toBeUndefined();
  });

  it('throws on an invalid record — cannot sign garbage (error)', () => {
    const { signer } = createTestSigner();
    const bad = payRecord() as Partial<WitnessRecord>;
    delete bad.deployment;
    expect(() => signEnvelope(bad as WitnessRecord, signer)).toThrow(/invalid WitnessRecord/);
  });
});

// ---------------------------------------------------------------------------
// AC2 — round-trip.
// ---------------------------------------------------------------------------

describe('[INTEGRATION] decodeEnvelope — AC2 round-trip', () => {
  it('encode → decode yields a record deep-equal to the original (happy / AC2)', () => {
    const { signer } = createTestSigner();
    const record = payRecord();
    const env = signEnvelope(record, signer);
    const decoded = decodeEnvelope(env);
    expect(decoded.ok).toBe(true);
    if (decoded.ok) {
      expect(decoded.record).toEqual(record);
      expect(decoded.statement._type).toBe('https://in-toto.io/Statement/v1');
      expect(decoded.statement.subject[0].name).toBe(record.intent.target_ref);
    }
  });

  it('round-trips a doc-profile record (against its validated, schema-normalized form) (happy)', () => {
    const { signer } = createTestSigner();
    const record = docRecord();
    // The AW-1 schema normalizes (e.g. injects artifacts[].pii_bearing=false).
    // The honest round-trip contract is that a VALIDATED record decodes to the
    // same validated record — so compare against the normalized form, not the
    // raw JSON that omits schema defaults.
    const normalized = (() => {
      const v = validateWitnessRecord(record);
      if (!v.ok) throw new Error(v.errors.join('; '));
      return v.record;
    })();
    const decoded = decodeEnvelope(signEnvelope(record, signer));
    expect(decoded.ok).toBe(true);
    if (decoded.ok) expect(decoded.record).toEqual(normalized);
  });

  it('rejects a wrong payloadType by name (error)', () => {
    const { signer } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const tampered: DsseEnvelope = { ...env, payloadType: 'application/json' };
    const decoded = decodeEnvelope(tampered);
    expect(decoded.ok).toBe(false);
    if (!decoded.ok) expect(decoded.reason).toMatch(/payloadType/);
  });

  it('rejects a malformed envelope shape (error)', () => {
    expect(decodeEnvelope({ payload: 123 }).ok).toBe(false);
    expect(decodeEnvelope(null).ok).toBe(false);
  });

  it('rejects payload that is not base64 JSON (edge)', () => {
    const { signer } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const broken: DsseEnvelope = { ...env, payload: Buffer.from('not json').toString('base64') };
    const decoded = decodeEnvelope(broken);
    expect(decoded.ok).toBe(false);
    if (!decoded.ok) expect(decoded.reason).toMatch(/Statement|JSON|object/);
  });
});

// ---------------------------------------------------------------------------
// verifyEnvelope — AC3 tamper, AC4 wrong key, plus per-check legibility.
// ---------------------------------------------------------------------------

describe('[INTEGRATION] verifyEnvelope', () => {
  it('verifies a freshly signed envelope and reports every check PASS (happy)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const result = verifyEnvelope(env, publicKey);
    expect(result.ok).toBe(true);
    if (result.ok) {
      const names = result.checks.map((c) => c.name);
      expect(names).toEqual(['envelope-shape', 'payloadType', 'signature', 'statement']);
      expect(result.checks.every((c) => c.ok && c.reason.length > 0)).toBe(true);
      expect(result.record.profile).toBe('pay');
    }
  });

  it('AC3 — detects a one-byte tampered payload and names "signature" failed', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    // Flip one byte of the decoded payload, re-encode (signature now stale).
    const bytes = Buffer.from(env.payload, 'base64');
    bytes[10] = bytes[10]! ^ 0x01;
    const tampered: DsseEnvelope = { ...env, payload: bytes.toString('base64') };
    const result = verifyEnvelope(tampered, publicKey);
    expect(result.ok).toBe(false);
    const sigCheck = result.checks.find((c) => c.name === 'signature');
    expect(sigCheck?.ok).toBe(false);
    expect(sigCheck?.reason).toMatch(/signature/i);
  });

  it('AC4 — fails against a public key that did not sign the envelope', () => {
    const { signer } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const otherKey = generateKeyPairSync('ed25519').publicKey;
    const result = verifyEnvelope(env, otherKey);
    expect(result.ok).toBe(false);
    const sigCheck = result.checks.find((c) => c.name === 'signature');
    expect(sigCheck?.ok).toBe(false);
  });

  it('accepts a raw 32-byte Ed25519 public key, not only a KeyObject (edge)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    const result = verifyEnvelope(env, new Uint8Array(rawPub));
    expect(result.ok).toBe(true);
  });

  it('fails the payloadType check (not signature) when payloadType is wrong (error)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const result = verifyEnvelope({ ...env, payloadType: 'application/json' }, publicKey);
    expect(result.ok).toBe(false);
    const ptCheck = result.checks.find((c) => c.name === 'payloadType');
    expect(ptCheck?.ok).toBe(false);
    // signature check should not have run yet (fail-fast after payloadType).
    expect(result.checks.find((c) => c.name === 'signature')).toBeUndefined();
  });

  it('fails envelope-shape for a non-envelope input (error)', () => {
    const { publicKey } = createTestSigner();
    const result = verifyEnvelope({ nope: true }, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.name).toBe('envelope-shape');
    expect(result.checks[0]!.ok).toBe(false);
  });

  it('fails envelope-shape when a signature keyid is not a string (error)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const bad = {
      ...env,
      signatures: [{ sig: env.signatures[0]!.sig, keyid: 123 }],
    };
    const result = verifyEnvelope(bad, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.name).toBe('envelope-shape');
    expect(result.checks[0]!.reason).toMatch(/keyid/);
  });

  it('fails envelope-shape when a signature is not an object (error)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const bad = { ...env, signatures: ['not-an-object'] };
    const result = verifyEnvelope(bad, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.reason).toMatch(/each signature must be an object/);
  });

  it('fails envelope-shape when a signature sig is not a string (error)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const bad = { ...env, signatures: [{ sig: 123 }] };
    const result = verifyEnvelope(bad, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.reason).toMatch(/base64 string "sig"/);
  });

  it('fails envelope-shape for an empty signatures array (error)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const result = verifyEnvelope({ ...env, signatures: [] }, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks[0]!.reason).toMatch(/non-empty array/);
  });

  it('accepts a DER-SPKI Uint8Array public key (edge)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const der = publicKey.export({ type: 'spki', format: 'der' });
    const result = verifyEnvelope(env, new Uint8Array(der));
    expect(result.ok).toBe(true);
  });

  it('accepts a PEM public-key string (edge)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const result = verifyEnvelope(env, pem);
    expect(result.ok).toBe(true);
  });

  it('fails the signature check with a clear reason for an unparseable public key (error)', () => {
    const { signer } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    const result = verifyEnvelope(env, 'not a key');
    expect(result.ok).toBe(false);
    const sigCheck = result.checks.find((c) => c.name === 'signature');
    expect(sigCheck?.ok).toBe(false);
    expect(sigCheck?.reason).toMatch(/public key/);
  });

  it('fails the statement check when the signed payload is valid-but-not-a-statement (edge)', () => {
    // Sign a non-statement payload directly so the signature passes but the
    // statement-shape check fails — proves the order signature→statement.
    const { signer, publicKey } = createTestSigner();
    // Re-sign arbitrary JSON that is not an AWP statement.
    const fakePayload = Buffer.from(JSON.stringify({ hello: 'world' }), 'utf8');
    const paeBytes = pae(PAYLOAD_TYPE, fakePayload);
    const sig = signer.sign(paeBytes);
    const forged: DsseEnvelope = {
      payload: fakePayload.toString('base64'),
      payloadType: PAYLOAD_TYPE,
      signatures: [{ sig: Buffer.from(sig).toString('base64') }],
    };
    const result = verifyEnvelope(forged, publicKey);
    expect(result.ok).toBe(false);
    expect(result.checks.find((c) => c.name === 'signature')?.ok).toBe(true);
    expect(result.checks.find((c) => c.name === 'statement')?.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Signers.
// ---------------------------------------------------------------------------

describe('[UNIT] createTestSigner', () => {
  it('returns a signer whose signatures verify with its public key (happy)', () => {
    const { signer, publicKey } = createTestSigner();
    const env = signEnvelope(payRecord(), signer);
    expect(verifyEnvelope(env, publicKey).ok).toBe(true);
  });

  it('stamps the keyid when provided (edge)', () => {
    const { signer } = createTestSigner('kid-7');
    expect(signer.keyid).toBe('kid-7');
  });

  it('produces 64-byte Ed25519 signatures (edge)', () => {
    const { signer } = createTestSigner();
    const sig = signer.sign(new TextEncoder().encode('abc'));
    expect(sig.length).toBe(64);
  });
});

describe('[UNIT] signerFromPrivateKey', () => {
  it('builds a working signer from an externally-held private key (happy)', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signer = signerFromPrivateKey(privateKey, 'ext-key');
    const env = signEnvelope(payRecord(), signer);
    expect(env.signatures[0]!.keyid).toBe('ext-key');
    expect(verifyEnvelope(env, publicKey).ok).toBe(true);
  });

  it('accepts a PEM private-key string (edge)', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const signer = signerFromPrivateKey(pem);
    const env = signEnvelope(payRecord(), signer);
    expect(verifyEnvelope(env, publicKey).ok).toBe(true);
  });

  it('omits keyid when not provided (edge)', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const signer = signerFromPrivateKey(privateKey);
    expect(signer.keyid).toBeUndefined();
  });
});
