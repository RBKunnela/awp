/**
 * Tests for the RFC 3161 timestamp VERIFY slot (AW-5 part b). Verifies a real
 * DER `TimeStampToken` (built by the test fixture, signed by a test TSA keypair —
 * no network, no committed binary) over a checkpoint root, and asserts the
 * tamper, wrong-key, imprint-mismatch, and honest evidentiary-weight behaviours.
 * The qualified-vendor drop-in is exercised by flipping ONLY the trust anchor's
 * `qualified` flag (config), never code. ≥3 tests per exported function.
 */
import { describe, it, expect } from 'vitest';
import { createHash, createPublicKey } from 'node:crypto';
import {
  verifyRfc3161Token,
  verifyRfc3161Anchor,
  parseTimeStampToken,
  type Rfc3161AnchorProof,
} from '../../src/anchor/index.js';
import { makeTsaKeyPair, buildTimeStampToken } from './rfc3161-fixture.js';

function rootBytes(s: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(s).digest());
}
const ROOT = rootBytes('checkpoint-root-rfc3161');
const ROOT_HEX = Buffer.from(ROOT).toString('hex');

describe('verifyRfc3161Token — verify against a test TSA (AC3)', () => {
  it('PASSES over the correct root and exposes genTime to the caller', () => {
    const tsa = makeTsaKeyPair('rsa');
    const genTime = new Date('2026-06-11T22:00:00Z');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, genTime, serial: 42 });

    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.info.genTime).toBe('2026-06-11T22:00:00.000Z');
      expect(r.info.imprintAlgorithm).toBe('sha256');
      expect(r.info.serialNumber).toBe('42');
      // Every sub-check reported by name and passing.
      for (const c of r.checks) expect(c.ok).toBe(true);
      expect(r.checks.map((c) => c.name)).toEqual(
        expect.arrayContaining(['parse', 'message-imprint', 'signed-attrs', 'signature', 'gen-time']),
      );
    }
  });

  it('verifies an ECDSA-signed token the same way (TSA-agnostic)', () => {
    const tsa = makeTsaKeyPair('ecdsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
  });

  it('verifies a SHA-512 message imprint', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, imprintAlg: 'sha512' });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.info.imprintAlgorithm).toBe('sha512');
  });

  it('verifies a token that includes an embedded certificates element (skipped, anchor still trusted)', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, includeCertificates: true });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
  });
});

describe('verifyRfc3161Token — tamper & failure paths (fail-closed, AC4)', () => {
  it('FAILS when the message imprint does not match the data (tampered imprint)', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, corruptImprint: true });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const imprint = r.checks.find((c) => c.name === 'message-imprint');
      expect(imprint?.ok).toBe(false);
    }
  });

  it('FAILS when verified against a DIFFERENT root than the token covers', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const other = rootBytes('a-different-checkpoint-root');
    const r = verifyRfc3161Token(der, other, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/imprint/i);
  });

  it('FAILS against the WRONG trust-anchor key (signature does not verify)', () => {
    const tsa = makeTsaKeyPair('rsa');
    const impostor = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: impostor.publicKeyPem } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const sig = r.checks.find((c) => c.name === 'signature');
      expect(sig?.ok).toBe(false);
    }
  });

  it('FAILS on malformed token bytes without throwing', () => {
    const tsa = makeTsaKeyPair('rsa');
    const r = verifyRfc3161Token(Buffer.from('this is not DER at all'), ROOT, {
      trustAnchor: { publicKey: tsa.publicKeyPem },
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.checks[0]?.name).toBe('parse');
  });

  it('FAILS when the signature value itself is corrupted (verify returns false, no throw)', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, corruptSignature: true });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const sig = r.checks.find((c) => c.name === 'signature');
      expect(sig?.ok).toBe(false);
    }
  });

  it('FAILS when the imprint algorithm is outside the accepted set', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, imprintAlg: 'sha512' });
    const r = verifyRfc3161Token(der, ROOT, {
      trustAnchor: { publicKey: tsa.publicKeyPem },
      allowedImprintAlgorithms: ['sha256'], // exclude sha512
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/disallowed|algorithm/i);
  });
});

describe('honest evidentiary weight — qualified ONLY by config, never inferred', () => {
  it('reports a plain "timestamp" (no eIDAS presumption) for a non-qualified anchor', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, {
      trustAnchor: { publicKey: tsa.publicKeyPem, name: 'freetsa.org' },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.weight).toBe('timestamp');
      expect(r.reason).toMatch(/NOT a qualified/i);
      expect(r.reason).not.toMatch(/Art\. 41 presumption[^—]*$/); // no bare presumption claim
    }
  });

  it('reports "qualified" (Art. 41) ONLY when the SAME token is verified against a qualified-flagged anchor', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    // Identical bytes, identical key — the ONLY change is the operator's config flag.
    const plain = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    const qualified = verifyRfc3161Token(der, ROOT, {
      trustAnchor: { publicKey: tsa.publicKeyPem, qualified: true, name: 'Test QTSP' },
    });
    expect(plain.ok && qualified.ok).toBe(true);
    if (plain.ok && qualified.ok) {
      expect(plain.weight).toBe('timestamp');
      expect(qualified.weight).toBe('qualified');
      expect(qualified.reason).toMatch(/qualified eIDAS/i);
    }
  });

  it('does not claim qualified weight just because the token verifies', () => {
    const tsa = makeTsaKeyPair('ecdsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.weight).not.toBe('qualified');
  });
});

describe('verifyRfc3161Anchor — receipt wrapper', () => {
  it('verifies an Rfc3161AnchorProof read straight from a receipt', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { base64 } = buildTimeStampToken({ data: ROOT, tsa });
    const proof: Rfc3161AnchorProof = { type: 'rfc3161', checkpoint_root: ROOT_HEX, tst_der_b64: base64 };
    const r = verifyRfc3161Anchor(proof, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(true);
  });

  it('FAILS when the proof checkpoint_root is not what the token covers', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { base64 } = buildTimeStampToken({ data: ROOT, tsa });
    const wrongHex = Buffer.from(rootBytes('wrong')).toString('hex');
    const proof: Rfc3161AnchorProof = { type: 'rfc3161', checkpoint_root: wrongHex, tst_der_b64: base64 };
    const r = verifyRfc3161Anchor(proof, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(false);
  });

  it('FAILS on a non-base64 token field without throwing', () => {
    const tsa = makeTsaKeyPair('rsa');
    const proof: Rfc3161AnchorProof = { type: 'rfc3161', checkpoint_root: ROOT_HEX, tst_der_b64: '%%%not base64%%%' };
    const r = verifyRfc3161Anchor(proof, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(r.ok).toBe(false);
  });
});

describe('trust-anchor key forms — PEM, DER SPKI, and KeyObject all accepted (config drop-in)', () => {
  it('accepts a Node KeyObject as the trust anchor', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: tsa.publicKey } });
    expect(r.ok).toBe(true);
  });

  it('accepts a DER SubjectPublicKeyInfo (Uint8Array) as the trust anchor', () => {
    const tsa = makeTsaKeyPair('ecdsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const spkiDer = createPublicKey(tsa.publicKeyPem).export({ format: 'der', type: 'spki' });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: new Uint8Array(spkiDer) } });
    expect(r.ok).toBe(true);
  });

  it('FAILS cleanly when the trust-anchor key bytes are not a valid SPKI', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const r = verifyRfc3161Token(der, ROOT, { trustAnchor: { publicKey: new Uint8Array([1, 2, 3, 4]) } });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const sig = r.checks.find((c) => c.name === 'signature');
      expect(sig?.ok).toBe(false);
    }
  });
});

describe('parseTimeStampToken — inspection without verification', () => {
  it('extracts genTime, imprint algorithm, and serial', () => {
    const tsa = makeTsaKeyPair('rsa');
    const genTime = new Date('2026-01-02T03:04:05Z');
    const { der } = buildTimeStampToken({ data: ROOT, tsa, genTime, serial: 7 });
    const info = parseTimeStampToken(der);
    expect(info.genTime).toBe('2026-01-02T03:04:05.000Z');
    expect(info.imprintAlgorithm).toBe('sha256');
    expect(info.serialNumber).toBe('7');
  });

  it('exposes the imprint hex matching SHA-256 of the data', () => {
    const tsa = makeTsaKeyPair('rsa');
    const { der } = buildTimeStampToken({ data: ROOT, tsa });
    const info = parseTimeStampToken(der);
    expect(info.imprintHex).toBe(createHash('sha256').update(Buffer.from(ROOT)).digest('hex'));
  });

  it('throws on structurally invalid token bytes', () => {
    expect(() => parseTimeStampToken(Buffer.from('nonsense'))).toThrow();
  });
});
