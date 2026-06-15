/**
 * Test-only RFC 3161 `TimeStampToken` builder. Produces a REAL, DER-encoded CMS
 * SignedData / TSTInfo token signed by a test TSA keypair (RSA or EC), so the
 * production verifier in `src/anchor/rfc3161.ts` parses and verifies genuine
 * bytes — no network, no committed binary needed, fully reproducible.
 *
 * The token is built to the same RFC 3161 (§2.4.2) + RFC 5652 (CMS) structure a
 * real TSA emits: ContentInfo(id-signedData) → SignedData → EncapsulatedContentInfo
 * (id-ct-TSTInfo, eContent = DER TSTInfo) + one SignerInfo whose signedAttrs carry
 * content-type + message-digest, with the signature computed over the DER-re-encoded
 * signedAttrs SET. This mirrors exactly what the verifier checks; it is a fixture,
 * not a re-implementation of the verifier's parsing.
 *
 * NOT shipped (test/ is excluded from the build). For fixtures/tests ONLY.
 */
import { createHash, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';

// ─────────────────────────── minimal DER encoders ───────────────────────────

/** Encode a definite DER length. */
function len(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Wrap content bytes in a TLV with the given tag. */
function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), len(content.length), content]);
}

const SEQ = 0x30;
const SET = 0x31;

function seq(...parts: Buffer[]): Buffer {
  return tlv(SEQ, Buffer.concat(parts));
}
function set(...parts: Buffer[]): Buffer {
  return tlv(SET, Buffer.concat(parts));
}
function oid(dotted: string): Buffer {
  const parts = dotted.split('.').map((p) => parseInt(p, 10));
  const first = (parts[0] as number) * 40 + (parts[1] as number);
  const body: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i] as number;
    const stack: number[] = [v & 0x7f];
    v = Math.floor(v / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    body.push(...stack);
  }
  return tlv(0x06, Buffer.from(body));
}
function integer(value: number | bigint): Buffer {
  let hex = BigInt(value).toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  let bytes = Buffer.from(hex, 'hex');
  // Ensure positive (prepend 0x00 if the high bit is set).
  if ((bytes[0] as number) & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  return tlv(0x02, bytes);
}
function octetString(content: Buffer): Buffer {
  return tlv(0x04, content);
}
function generalizedTime(d: Date): Buffer {
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  const s =
    `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}` +
    `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, Buffer.from(s, 'ascii'));
}
function contextExplicit(tagNumber: number, content: Buffer): Buffer {
  return tlv(0xa0 | tagNumber, content);
}

// Digest OIDs.
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
// CMS / RFC 3161 OIDs.
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_TSA_POLICY = '1.3.6.1.4.1.99999.1.1'; // arbitrary test policy

/** A digest-algorithm AlgorithmIdentifier (no params for SHA-2). */
function digestAlgId(digestOid: string): Buffer {
  return seq(oid(digestOid));
}

/** Build the TSTInfo eContent for a given imprint. */
function buildTstInfo(opts: {
  imprintDigestOid: string;
  imprintHashed: Buffer;
  genTime: Date;
  serial: number;
}): Buffer {
  return seq(
    integer(1), // version
    oid(OID_TSA_POLICY), // policy
    seq(digestAlgId(opts.imprintDigestOid), octetString(opts.imprintHashed)), // messageImprint
    integer(opts.serial), // serialNumber
    generalizedTime(opts.genTime), // genTime
  );
}

/** Build one Attribute (type OID + SET of values). */
function attribute(typeOid: string, value: Buffer): Buffer {
  return seq(oid(typeOid), set(value));
}

export interface TsaKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** PEM SubjectPublicKeyInfo for the verifier's trust anchor. */
  publicKeyPem: string;
  kind: 'rsa' | 'ecdsa';
}

/** Generate a test TSA keypair (RSA-2048 by default, or P-256 EC). */
export function makeTsaKeyPair(kind: 'rsa' | 'ecdsa' = 'rsa'): TsaKeyPair {
  const { publicKey, privateKey } =
    kind === 'rsa'
      ? generateKeyPairSync('rsa', { modulusLength: 2048 })
      : generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    publicKey,
    privateKey,
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }) as string,
    kind,
  };
}

export interface BuildTokenOptions {
  /** The data the TSA timestamps (the checkpoint root bytes). */
  data: Uint8Array;
  /** The TSA keypair to sign with. */
  tsa: TsaKeyPair;
  /** Imprint digest algorithm ('sha256' default | 'sha512'). */
  imprintAlg?: 'sha256' | 'sha512';
  /** genTime to embed (default: now). */
  genTime?: Date;
  /** Serial number (default: 1). */
  serial?: number;
  /**
   * Tamper hook: if `corruptImprint`, the imprint stored is hash(data) with one
   * byte flipped, so the verifier's message-imprint check must FAIL.
   */
  corruptImprint?: boolean;
  /**
   * Include a (placeholder) `certificates [0] IMPLICIT` element in SignedData,
   * as a real TSA does. The verifier ignores embedded certs (it trusts only the
   * supplied anchor); this exercises the optional-element skip path.
   */
  includeCertificates?: boolean;
  /** Tamper hook: flip a byte of the SIGNATURE so signature verification FAILS. */
  corruptSignature?: boolean;
}

/**
 * Build a real DER `TimeStampToken` over `data`, signed by the test TSA. Returns
 * the DER bytes (feed to `verifyRfc3161Token`) and the base64 (for an anchor proof).
 */
export function buildTimeStampToken(opts: BuildTokenOptions): { der: Buffer; base64: string } {
  const imprintAlg = opts.imprintAlg ?? 'sha256';
  const imprintOid = imprintAlg === 'sha512' ? OID_SHA512 : OID_SHA256;
  const sigOid = opts.tsa.kind === 'rsa' ? OID_RSA_SHA256 : OID_ECDSA_SHA256;
  const genTime = opts.genTime ?? new Date();
  const serial = opts.serial ?? 1;

  let imprintHashed = createHash(imprintAlg).update(Buffer.from(opts.data)).digest();
  if (opts.corruptImprint) {
    imprintHashed = Buffer.from(imprintHashed);
    imprintHashed[0] = (imprintHashed[0] ?? 0) ^ 0xff;
  }

  const tstInfo = buildTstInfo({ imprintDigestOid: imprintOid, imprintHashed, genTime, serial });

  // SignerInfo signedAttrs: content-type (= id-ct-TSTInfo) and message-digest (= SHA-256(eContent)).
  const eContentDigest = createHash('sha256').update(tstInfo).digest();
  const contentTypeAttr = attribute(OID_CONTENT_TYPE, oid(OID_TST_INFO));
  const messageDigestAttr = attribute(OID_MESSAGE_DIGEST, octetString(eContentDigest));

  // signedAttrs as the wire [0] IMPLICIT form AND the SET form that is signed.
  const attrsContent = Buffer.concat([contentTypeAttr, messageDigestAttr]);
  const signedAttrsImplicit = contextExplicit(0, attrsContent); // [0] IMPLICIT SET OF
  const signedAttrsForSig = tlv(SET, attrsContent); // universal SET (RFC 5652 §5.4)

  // Sign the DER of the SET form.
  let signature = signOver(opts.tsa, signedAttrsForSig);
  if (opts.corruptSignature) {
    signature = Buffer.from(signature);
    const last = signature.length - 1;
    signature[last] = (signature[last] ?? 0) ^ 0xff;
  }

  // SignerInfo ::= SEQ { version(1), sid, digestAlgorithm, [0] signedAttrs, sigAlg, signature }
  // sid = issuerAndSerialNumber: SEQ { Name (empty SEQ), CertificateSerialNumber }
  const sid = seq(seq(), integer(1));
  const signerInfo = seq(
    integer(1),
    sid,
    digestAlgId(OID_SHA256),
    signedAttrsImplicit,
    seq(oid(sigOid)),
    octetString(signature),
  );

  // EncapsulatedContentInfo ::= SEQ { eContentType, [0] EXPLICIT OCTET STRING eContent }
  const encap = seq(oid(OID_TST_INFO), contextExplicit(0, octetString(tstInfo)));

  // Optional certificates [0] IMPLICIT — a placeholder element a real TSA fills
  // with its signing chain. The verifier ignores it (trusts only the anchor).
  const certificates = opts.includeCertificates
    ? [contextExplicit(0, seq(integer(1)))] // [0] holding one trivial SEQUENCE
    : [];

  // SignedData ::= SEQ { version(3), digestAlgorithms SET, encap, [certs]?, signerInfos SET }
  const signedData = seq(integer(3), set(digestAlgId(OID_SHA256)), encap, ...certificates, set(signerInfo));

  // ContentInfo ::= SEQ { id-signedData, [0] EXPLICIT SignedData }
  const contentInfo = seq(oid(OID_SIGNED_DATA), contextExplicit(0, signedData));

  return { der: contentInfo, base64: contentInfo.toString('base64') };
}

/** Sign `data` with the TSA private key (RSA-SHA256 or ECDSA-SHA256, DER sig). */
function signOver(tsa: TsaKeyPair, data: Buffer): Buffer {
  const signer = createSign('SHA256');
  signer.update(data);
  signer.end();
  return signer.sign(tsa.privateKey);
}
