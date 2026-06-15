/**
 * @module anchor/rfc3161
 *
 * RFC 3161 timestamp VERIFY slot — a TSA-agnostic verifier for a `TimeStampToken`
 * over a checkpoint root, structured as a DROP-IN so a qualified eIDAS TSA vendor
 * is added LATER BY CONFIG (a trust anchor + a `qualified` flag), not by changing
 * code (AW-5 part b; ADR D-b2). The SAME code path verifies a free non-qualified
 * TSA token (freetsa.org, DigiCert) today and a qualified token tomorrow; only
 * the supplied {@link Rfc3161TrustAnchor} differs.
 *
 * What "verify a TimeStampToken" means here (RFC 3161 §2.4.2, with CMS per
 * RFC 5652), in the order this module checks it:
 *
 *  1. **Parse.** The token is a CMS `ContentInfo` whose `contentType` is
 *     `id-signedData (1.2.840.113549.1.7.2)`; inside, the `SignedData`'s
 *     `encapContentInfo` has `eContentType = id-ct-TSTInfo
 *     (1.2.840.113549.1.9.16.1.4)` and an `eContent` carrying the DER `TSTInfo`.
 *  2. **Message imprint.** `TSTInfo.messageImprint` = (hashAlgorithm,
 *     hashedMessage). The hashed message MUST equal `hash(checkpoint-root bytes)`
 *     under that algorithm. A token whose imprint does not match the data FAILS
 *     (AW-5 AC4). This module supports SHA-256/384/512 imprints; the AWP root is
 *     a 32-byte SHA-256 value, hashed by the TSA under one of these.
 *  3. **Signed attributes ↔ content.** When `SignerInfo.signedAttrs` are present
 *     (they are, for any conformant TSA), they MUST include a `message-digest`
 *     attribute equal to `hash(eContent)` and a `content-type` attribute equal to
 *     the eContentType. The SIGNATURE is then computed over the DER re-encoding of
 *     the `signedAttrs` SET (RFC 5652 §5.4), NOT over the eContent directly.
 *  4. **Signature.** Verify `SignerInfo.signature` over those signed-attrs bytes
 *     against the SUPPLIED trust-anchor public key (RSA PKCS#1 v1.5 or ECDSA),
 *     under the signature/digest algorithm the token names. The trust anchor is
 *     config: a raw SubjectPublicKeyInfo / PEM the operator pins for their TSA
 *     (or a vendor cert later). This module does NOT fetch or trust embedded
 *     certificates implicitly — the verifier must be handed the key it trusts.
 *  5. **genTime.** `TSTInfo.genTime` (a `GeneralizedTime`) is parsed to an ISO
 *     instant and EXPOSED to the caller (AW-5 AC3).
 *
 * Honest evidentiary weight (AW-5 threat model "overclaim of legal time"): the
 * result reports `qualified` ONLY when the supplied trust anchor is flagged
 * `qualified: true` (the operator's assertion that this key belongs to a QTSP on
 * an EU trusted list). Verified against a non-qualified anchor, the SAME valid
 * token is reported as a plain timestamp — never as carrying the eIDAS Art. 41
 * presumption. This module makes ZERO network calls and reads no trust list; the
 * `qualified` claim is an operator-supplied input, not something inferred here.
 *
 * Re-implementability (no hidden canonicalization): the DER reader below is a
 * plain TLV walk; the only "canonical" step is re-serializing the `signedAttrs`
 * SET with its explicit `[0] IMPLICIT` tag rewritten to the universal SET tag
 * (`0x31`) exactly as RFC 5652 §5.4 specifies — documented inline. An auditor can
 * re-derive every byte checked.
 *
 * Dependencies: Node `crypto` (RSA/ECDSA verify, SHA-2), `./types`. No ASN.1
 *   library (kept dependency-free and auditable like the rest of the package).
 * Used by: AW-6 wires this into `awp verify`; `./index` re-exports it.
 */

import { createHash, createVerify, createPublicKey, type KeyObject } from 'node:crypto';
import type { Rfc3161AnchorProof } from './types.js';

// ───────────────────────────── OIDs (dotted) ─────────────────────────────
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

/** Digest OIDs → Node hash name (the imprint + signed-attrs digest algorithms). */
const DIGEST_OID_TO_NAME: Readonly<Record<string, string>> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
  '1.3.14.3.2.26': 'sha1', // legacy; accepted for imprint parsing, flagged weak
};

/** Signature-algorithm OIDs → { kind, digest } for the SignerInfo signature. */
const SIG_OID: Readonly<Record<string, { kind: 'rsa' | 'ecdsa'; digest?: string }>> = {
  // RSA PKCS#1 v1.5 with explicit digest
  '1.2.840.113549.1.1.11': { kind: 'rsa', digest: 'sha256' },
  '1.2.840.113549.1.1.12': { kind: 'rsa', digest: 'sha384' },
  '1.2.840.113549.1.1.13': { kind: 'rsa', digest: 'sha512' },
  '1.2.840.113549.1.1.1': { kind: 'rsa' }, // rsaEncryption — digest taken from digestAlgorithm
  // ECDSA with explicit digest
  '1.2.840.10045.4.3.2': { kind: 'ecdsa', digest: 'sha256' },
  '1.2.840.10045.4.3.3': { kind: 'ecdsa', digest: 'sha384' },
  '1.2.840.10045.4.3.4': { kind: 'ecdsa', digest: 'sha512' },
  '1.2.840.10045.2.1': { kind: 'ecdsa' }, // id-ecPublicKey — digest from digestAlgorithm
};

/**
 * The trust anchor an operator pins for their TSA — CONFIG, not code. Supply the
 * TSA's signing public key (the key the `TimeStampToken` is signed with), as a
 * PEM/DER SubjectPublicKeyInfo or a Node {@link KeyObject}. Set `qualified: true`
 * ONLY for a key the operator asserts belongs to a QTSP on an EU trusted list —
 * that flag is the SOLE thing that lets the verifier report eIDAS-qualified
 * weight (it is never inferred from the token).
 */
export interface Rfc3161TrustAnchor {
  /**
   * The TSA signing public key: a PEM string, a DER `SubjectPublicKeyInfo`
   * buffer, or a Node public {@link KeyObject}.
   */
  publicKey: string | Uint8Array | KeyObject;
  /**
   * Whether this anchor is a qualified eIDAS TSA (QTSP on an EU trusted list).
   * Operator assertion; gates the `qualified` evidentiary-weight report. Default
   * `false` (plain timestamp).
   */
  qualified?: boolean;
  /** Optional human label for the anchor (e.g. "freetsa.org", "Evidency QTSP"). */
  name?: string;
}

/** Options for {@link verifyRfc3161Anchor} / {@link verifyRfc3161Token}. */
export interface Rfc3161VerifyOptions {
  /** The pinned TSA trust anchor (config). REQUIRED — the verifier trusts nothing implicitly. */
  trustAnchor: Rfc3161TrustAnchor;
  /**
   * Optional acceptable imprint hash names (default: sha256/384/512). A token
   * using an algorithm outside this set fails the imprint check honestly.
   */
  allowedImprintAlgorithms?: readonly string[];
}

/** The timestamp facts extracted from a verified `TSTInfo`. */
export interface TimeStampInfo {
  /** `TSTInfo.genTime` as an ISO-8601 UTC instant (e.g. `2026-06-11T22:00:00.000Z`). */
  genTime: string;
  /** The imprint hash algorithm name (e.g. `sha256`). */
  imprintAlgorithm: string;
  /** The imprint hashed-message bytes, lowercase hex. */
  imprintHex: string;
  /** The TSA policy OID under which the token was issued, if present. */
  policyOid?: string;
  /** The token serial number as a decimal string, if parseable. */
  serialNumber?: string;
}

/** One named sub-check of RFC 3161 verification (mirrors the package's report contract). */
export interface Rfc3161Check {
  /** Check name, e.g. `"parse"`, `"message-imprint"`, `"signature"`, `"gen-time"`. */
  name: string;
  /** Whether the check passed. */
  ok: boolean;
  /** One-line human reason (always present). */
  reason: string;
}

/** Result of {@link verifyRfc3161Token} / {@link verifyRfc3161Anchor}. */
export type Rfc3161VerifyResult =
  | {
      ok: true;
      /** Per-check report (parse, message-imprint, signed-attrs, signature, gen-time). */
      checks: Rfc3161Check[];
      /** The extracted timestamp facts (genTime exposed to the caller). */
      info: TimeStampInfo;
      /**
       * The HONEST evidentiary weight: `qualified` iff the trust anchor was
       * flagged qualified, else `timestamp` (a valid but non-qualified TSA time).
       */
      weight: 'qualified' | 'timestamp';
      /** One-line summary suitable for the verifier report. */
      reason: string;
    }
  | { ok: false; checks: Rfc3161Check[]; reason: string };

/**
 * Verify an {@link Rfc3161AnchorProof} from a receipt against a pinned trust
 * anchor: decode its base64 DER token and check it over the proof's
 * `checkpoint_root`. The drop-in entry point a receipt verifier (AW-6) calls.
 *
 * @param proof - The RFC 3161 anchor proof (checkpoint root + base64 DER token).
 * @param opts - The pinned TSA trust anchor (config) + imprint policy.
 * @returns An {@link Rfc3161VerifyResult}; never throws.
 *
 * @example
 * const r = verifyRfc3161Anchor(proof, { trustAnchor: { publicKey: tsaPem, qualified: true } });
 * if (r.ok) console.log(r.info.genTime, r.weight);
 */
export function verifyRfc3161Anchor(
  proof: Rfc3161AnchorProof,
  opts: Rfc3161VerifyOptions,
): Rfc3161VerifyResult {
  let der: Buffer;
  try {
    der = Buffer.from(proof.tst_der_b64, 'base64');
  } catch (err) {
    return {
      ok: false,
      checks: [{ name: 'parse', ok: false, reason: `tst_der_b64 is not valid base64: ${(err as Error).message}` }],
      reason: 'RFC 3161 token is not valid base64',
    };
  }
  return verifyRfc3161Token(der, hexToBytes(proof.checkpoint_root), opts);
}

/**
 * Verify a DER `TimeStampToken` over the given data bytes (the checkpoint root)
 * against a pinned trust anchor. This is the TSA-agnostic core: it checks the
 * message imprint matches `hash(data)`, the signed attributes bind to the
 * eContent, the TSA signature verifies against the supplied key, and exposes
 * genTime — reporting `qualified` weight ONLY if the anchor is flagged qualified.
 *
 * @param tokenDer - The DER-encoded RFC 3161 `TimeStampToken` (CMS SignedData).
 * @param data - The bytes the imprint must cover (the 32-byte checkpoint root).
 * @param opts - The pinned trust anchor (config) + imprint policy.
 * @returns An {@link Rfc3161VerifyResult}; never throws — all failures are
 *   reported as named, failing checks (fail-closed).
 *
 * @example
 * const r = verifyRfc3161Token(tokenDer, rootBytes, { trustAnchor: { publicKey: tsaKey } });
 */
export function verifyRfc3161Token(
  tokenDer: Uint8Array,
  data: Uint8Array,
  opts: Rfc3161VerifyOptions,
): Rfc3161VerifyResult {
  const checks: Rfc3161Check[] = [];

  // 1. Parse the CMS SignedData → SignerInfo + TSTInfo.
  let parsed: ParsedToken;
  try {
    parsed = parseTokenInternal(tokenDer);
  } catch (err) {
    checks.push({ name: 'parse', ok: false, reason: `malformed RFC 3161 token: ${(err as Error).message}` });
    return { ok: false, checks, reason: 'RFC 3161 token failed to parse' };
  }
  checks.push({ name: 'parse', ok: true, reason: 'CMS SignedData with TSTInfo eContent parsed' });

  // 2. Message imprint must equal hash(data) under the imprint algorithm.
  const allowed = new Set(opts.allowedImprintAlgorithms ?? ['sha256', 'sha384', 'sha512']);
  if (!allowed.has(parsed.tst.imprintAlgorithm)) {
    checks.push({
      name: 'message-imprint',
      ok: false,
      reason: `imprint algorithm "${parsed.tst.imprintAlgorithm}" is not in the accepted set {${[...allowed].join(', ')}}`,
    });
    return { ok: false, checks, reason: 'RFC 3161 imprint uses a disallowed hash algorithm' };
  }
  const expectedImprint = createHash(parsed.tst.imprintAlgorithm).update(Buffer.from(data)).digest();
  if (!timingSafeEqualHex(expectedImprint, parsed.tst.imprintHashed)) {
    checks.push({
      name: 'message-imprint',
      ok: false,
      reason: 'TSTInfo.messageImprint does not match hash(checkpoint root) — token does not cover this data',
    });
    return { ok: false, checks, reason: 'RFC 3161 message imprint does not match the checkpoint root' };
  }
  checks.push({
    name: 'message-imprint',
    ok: true,
    reason: `messageImprint = ${parsed.tst.imprintAlgorithm}(checkpoint root) matches`,
  });

  // 3. Signed attributes must bind to the eContent: content-type + message-digest.
  if (parsed.signer.signedAttrsDer === undefined) {
    checks.push({
      name: 'signed-attrs',
      ok: false,
      reason: 'SignerInfo has no signedAttrs (cannot bind the signature to the TSTInfo content)',
    });
    return { ok: false, checks, reason: 'RFC 3161 token lacks signed attributes' };
  }
  const ctAttr = parsed.signer.attrs[OID_CONTENT_TYPE];
  if (ctAttr === undefined || ctAttr.oid !== OID_TST_INFO) {
    checks.push({
      name: 'signed-attrs',
      ok: false,
      reason: 'signed content-type attribute missing or not id-ct-TSTInfo',
    });
    return { ok: false, checks, reason: 'RFC 3161 signed content-type attribute invalid' };
  }
  const mdAttr = parsed.signer.attrs[OID_MESSAGE_DIGEST];
  if (mdAttr === undefined || mdAttr.value === undefined) {
    checks.push({ name: 'signed-attrs', ok: false, reason: 'signed message-digest attribute missing' });
    return { ok: false, checks, reason: 'RFC 3161 signed message-digest attribute missing' };
  }
  const eContentDigest = createHash(parsed.signer.digestName).update(parsed.tst.eContent).digest();
  if (!timingSafeEqualHex(eContentDigest, mdAttr.value)) {
    checks.push({
      name: 'signed-attrs',
      ok: false,
      reason: 'signed message-digest does not equal hash(eContent) — signature does not cover this TSTInfo',
    });
    return { ok: false, checks, reason: 'RFC 3161 message-digest attribute does not match the TSTInfo' };
  }
  checks.push({
    name: 'signed-attrs',
    ok: true,
    reason: 'content-type and message-digest signed attributes bind the signature to the TSTInfo',
  });

  // 4. Verify the TSA signature over the DER-re-encoded signedAttrs SET.
  let key: KeyObject;
  try {
    key = toPublicKey(opts.trustAnchor.publicKey);
  } catch (err) {
    checks.push({ name: 'signature', ok: false, reason: `invalid trust-anchor public key: ${(err as Error).message}` });
    return { ok: false, checks, reason: 'RFC 3161 trust-anchor key could not be loaded' };
  }
  const sigOk = verifySignature(
    parsed.signer.signatureKind,
    parsed.signer.digestName,
    key,
    parsed.signer.signedAttrsDer,
    parsed.signer.signature,
  );
  if (!sigOk) {
    checks.push({
      name: 'signature',
      ok: false,
      reason: 'TSA signature did not verify over signedAttrs against the supplied trust anchor (wrong key or tampered token)',
    });
    return { ok: false, checks, reason: 'RFC 3161 TSA signature did not verify' };
  }
  checks.push({
    name: 'signature',
    ok: true,
    reason: `TSA ${parsed.signer.signatureKind.toUpperCase()} signature verified over signedAttrs against the pinned trust anchor`,
  });

  // 5. genTime exposed.
  checks.push({ name: 'gen-time', ok: true, reason: `genTime = ${parsed.tst.genTime}` });

  const qualified = opts.trustAnchor.qualified === true;
  const weight: 'qualified' | 'timestamp' = qualified ? 'qualified' : 'timestamp';
  const label = opts.trustAnchor.name ? ` (${opts.trustAnchor.name})` : '';
  const reason = qualified
    ? `qualified eIDAS timestamp${label}: genTime ${parsed.tst.genTime} (Art. 41 presumption — operator-asserted QTSP anchor)`
    : `timestamp${label}: genTime ${parsed.tst.genTime} (valid TSA token; NOT a qualified eIDAS time — no presumption)`;

  return {
    ok: true,
    checks,
    info: {
      genTime: parsed.tst.genTime,
      imprintAlgorithm: parsed.tst.imprintAlgorithm,
      imprintHex: parsed.tst.imprintHashed.toString('hex'),
      ...(parsed.tst.policyOid !== undefined ? { policyOid: parsed.tst.policyOid } : {}),
      ...(parsed.tst.serialNumber !== undefined ? { serialNumber: parsed.tst.serialNumber } : {}),
    },
    weight,
    reason,
  };
}

/**
 * Parse a DER `TimeStampToken` into its timestamp facts WITHOUT verifying the
 * signature — for inspection / debugging. Verification is {@link verifyRfc3161Token}.
 *
 * @param tokenDer - The DER-encoded RFC 3161 token.
 * @returns The extracted {@link TimeStampInfo}.
 * @throws {Error} If the token is not a parseable CMS-SignedData / TSTInfo.
 */
export function parseTimeStampToken(tokenDer: Uint8Array): TimeStampInfo {
  const parsed = parseTokenInternal(tokenDer);
  return {
    genTime: parsed.tst.genTime,
    imprintAlgorithm: parsed.tst.imprintAlgorithm,
    imprintHex: parsed.tst.imprintHashed.toString('hex'),
    ...(parsed.tst.policyOid !== undefined ? { policyOid: parsed.tst.policyOid } : {}),
    ...(parsed.tst.serialNumber !== undefined ? { serialNumber: parsed.tst.serialNumber } : {}),
  };
}

// ═══════════════════════════ internals: DER + CMS ═══════════════════════════

/** A parsed DER TLV: tag byte, header length, content view, and total length. */
interface Tlv {
  tag: number;
  /** Offset of the content within the parent buffer. */
  contentStart: number;
  /** Content length in bytes. */
  length: number;
  /** Total bytes consumed (header + content). */
  totalLength: number;
  /** The content bytes (subarray view). */
  content: Buffer;
  /** The full TLV bytes (header + content), for re-serialization. */
  full: Buffer;
}

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_GENERALIZED_TIME = 0x18;

/** Read one DER TLV at `offset`. Supports short and long definite-length forms. */
function readTlv(buf: Buffer, offset: number): Tlv {
  if (offset >= buf.length) throw new Error('unexpected end of DER (tag)');
  const tag = buf[offset] as number;
  if ((tag & 0x1f) === 0x1f) throw new Error('high-tag-number form not supported');
  let pos = offset + 1;
  if (pos >= buf.length) throw new Error('unexpected end of DER (length)');
  const first = buf[pos] as number;
  pos += 1;
  let length: number;
  if ((first & 0x80) === 0) {
    length = first; // short form
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0) throw new Error('indefinite-length DER not allowed');
    if (numBytes > 4) throw new Error('DER length field too large');
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      if (pos >= buf.length) throw new Error('unexpected end of DER (long length)');
      length = length * 256 + (buf[pos] as number);
      pos += 1;
    }
  }
  const contentStart = pos;
  if (contentStart + length > buf.length) throw new Error('DER content runs past end of buffer');
  const totalLength = contentStart - offset + length;
  return {
    tag,
    contentStart,
    length,
    totalLength,
    content: buf.subarray(contentStart, contentStart + length),
    full: buf.subarray(offset, offset + totalLength),
  };
}

/** Read every TLV in a content buffer, in order. */
function readChildren(content: Buffer): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < content.length) {
    const tlv = readTlv(content, off);
    out.push(tlv);
    off += tlv.totalLength;
  }
  return out;
}

/** Expect a TLV of a given tag, throwing a named error otherwise. */
function expectTag(tlv: Tlv, tag: number, what: string): Tlv {
  if (tlv.tag !== tag) {
    throw new Error(`expected ${what} (tag 0x${tag.toString(16)}) but found tag 0x${tlv.tag.toString(16)}`);
  }
  return tlv;
}

/** Decode a DER OBJECT IDENTIFIER content into dotted-decimal. */
function decodeOid(content: Buffer): string {
  if (content.length === 0) throw new Error('empty OID');
  const first = content[0] as number;
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    const b = content[i] as number;
    value = value * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Decode a DER INTEGER content to a decimal string (handles big serials). */
function decodeIntegerToDecimal(content: Buffer): string {
  // Interpret as a big-endian two's-complement integer; serials are positive.
  let hex = '';
  for (const b of content) hex += (b as number).toString(16).padStart(2, '0');
  if (hex.length === 0) return '0';
  return BigInt('0x' + hex).toString(10);
}

/**
 * Decode a DER `GeneralizedTime` (`YYYYMMDDHHMMSS[.fff]Z`) to an ISO instant.
 * RFC 3161 genTime is UTC ending in `Z`. Fractional seconds are preserved to ms.
 */
function decodeGeneralizedTime(content: Buffer): string {
  const s = content.toString('ascii');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
  if (!m) throw new Error(`unsupported GeneralizedTime format: ${JSON.stringify(s)}`);
  const [, yy, mo, dd, hh, mi, ss, frac] = m;
  const ms = frac ? Number(`0.${frac}`) * 1000 : 0;
  const date = new Date(
    Date.UTC(Number(yy), Number(mo) - 1, Number(dd), Number(hh), Number(mi), Number(ss), Math.round(ms)),
  );
  return date.toISOString();
}

/** A parsed SignerInfo (the bits needed to verify the TSA signature). */
interface ParsedSigner {
  digestName: string;
  signatureKind: 'rsa' | 'ecdsa';
  signature: Buffer;
  /** The DER of signedAttrs RE-ENCODED with the universal SET tag (RFC 5652 §5.4). */
  signedAttrsDer?: Buffer;
  /** Parsed signed attributes by OID. */
  attrs: Record<string, { oid?: string; value?: Buffer }>;
}

/** A parsed TSTInfo (the timestamp facts). */
interface ParsedTst {
  eContent: Buffer;
  genTime: string;
  imprintAlgorithm: string;
  imprintHashed: Buffer;
  policyOid?: string;
  serialNumber?: string;
}

/** The whole parsed token. */
interface ParsedToken {
  signer: ParsedSigner;
  tst: ParsedTst;
}

/**
 * Parse the CMS `ContentInfo`→`SignedData`→(SignerInfo + TSTInfo) needed to
 * verify an RFC 3161 token. Throws on any structural deviation.
 */
function parseTokenInternal(tokenDer: Uint8Array): ParsedToken {
  const buf = Buffer.from(tokenDer);
  const contentInfo = expectTag(readTlv(buf, 0), TAG_SEQUENCE, 'ContentInfo SEQUENCE');
  const ciChildren = readChildren(contentInfo.content);
  if (ciChildren.length < 2) throw new Error('ContentInfo must have contentType + content');
  const ctOid = decodeOid(expectTag(ciChildren[0] as Tlv, TAG_OID, 'ContentInfo.contentType').content);
  if (ctOid !== OID_SIGNED_DATA) throw new Error(`ContentInfo.contentType ${ctOid} is not id-signedData`);
  // content [0] EXPLICIT SignedData
  const contentExplicit = ciChildren[1] as Tlv;
  const signedData = expectTag(readChildren(contentExplicit.content)[0] as Tlv, TAG_SEQUENCE, 'SignedData SEQUENCE');
  const sdChildren = readChildren(signedData.content);
  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo, [certs], [crls], signerInfos SET }
  // Walk positionally, skipping optional [0]/[1] context tags.
  let idx = 0;
  expectTag(sdChildren[idx++] as Tlv, TAG_INTEGER, 'SignedData.version');
  expectTag(sdChildren[idx++] as Tlv, TAG_SET, 'SignedData.digestAlgorithms');
  const encap = expectTag(sdChildren[idx++] as Tlv, TAG_SEQUENCE, 'EncapsulatedContentInfo');
  // optional certificates [0] / crls [1]
  while (idx < sdChildren.length && ((sdChildren[idx] as Tlv).tag & 0xe0) === 0xa0) {
    idx += 1;
  }
  const signerInfos = expectTag(sdChildren[idx++] as Tlv, TAG_SET, 'SignedData.signerInfos');

  // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
  const encapChildren = readChildren(encap.content);
  const eContentType = decodeOid(expectTag(encapChildren[0] as Tlv, TAG_OID, 'eContentType').content);
  if (eContentType !== OID_TST_INFO) throw new Error(`eContentType ${eContentType} is not id-ct-TSTInfo`);
  if (encapChildren.length < 2) throw new Error('EncapsulatedContentInfo has no eContent');
  const eContentExplicit = encapChildren[1] as Tlv; // [0] EXPLICIT
  const eContentOctet = expectTag(readChildren(eContentExplicit.content)[0] as Tlv, TAG_OCTET_STRING, 'eContent OCTET STRING');
  const tst = parseTstInfo(eContentOctet.content);

  // Parse the FIRST SignerInfo.
  const firstSigner = expectTag(readChildren(signerInfos.content)[0] as Tlv, TAG_SEQUENCE, 'SignerInfo SEQUENCE');
  const signer = parseSignerInfo(firstSigner.content);

  return { signer, tst: { ...tst, eContent: Buffer.from(eContentOctet.content) } };
}

/**
 * Parse a TSTInfo. The argument is the eContent OCTET STRING's bytes, which ARE
 * the DER `TSTInfo` SEQUENCE (RFC 3161 §2.4.2) — so unwrap that SEQUENCE first,
 * then read its fields.
 */
function parseTstInfo(eContent: Buffer): Omit<ParsedTst, 'eContent'> {
  const tstSeq = expectTag(readTlv(eContent, 0), TAG_SEQUENCE, 'TSTInfo SEQUENCE');
  const children = readChildren(tstSeq.content);
  // TSTInfo ::= SEQUENCE { version INTEGER, policy OID, messageImprint, serialNumber INTEGER, genTime GeneralizedTime, ... }
  let i = 0;
  expectTag(children[i++] as Tlv, TAG_INTEGER, 'TSTInfo.version');
  const policyOid = decodeOid(expectTag(children[i++] as Tlv, TAG_OID, 'TSTInfo.policy').content);
  const messageImprint = expectTag(children[i++] as Tlv, TAG_SEQUENCE, 'TSTInfo.messageImprint');
  const serialNumber = decodeIntegerToDecimal(expectTag(children[i++] as Tlv, TAG_INTEGER, 'TSTInfo.serialNumber').content);
  const genTime = decodeGeneralizedTime(expectTag(children[i++] as Tlv, TAG_GENERALIZED_TIME, 'TSTInfo.genTime').content);

  // messageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  const miChildren = readChildren(messageImprint.content);
  const algId = expectTag(miChildren[0] as Tlv, TAG_SEQUENCE, 'messageImprint.hashAlgorithm');
  const algOid = decodeOid(expectTag(readChildren(algId.content)[0] as Tlv, TAG_OID, 'hashAlgorithm OID').content);
  const imprintAlgorithm = DIGEST_OID_TO_NAME[algOid];
  if (imprintAlgorithm === undefined) throw new Error(`unknown imprint hash OID ${algOid}`);
  const imprintHashed = Buffer.from(expectTag(miChildren[1] as Tlv, TAG_OCTET_STRING, 'hashedMessage').content);

  return { genTime, imprintAlgorithm, imprintHashed, policyOid, serialNumber };
}

/** Parse a SignerInfo body (DER SEQUENCE content). */
function parseSignerInfo(content: Buffer): ParsedSigner {
  const children = readChildren(content);
  // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm, [signedAttrs [0]], signatureAlgorithm, signature OCTET STRING, [unsignedAttrs [1]] }
  let i = 0;
  expectTag(children[i++] as Tlv, TAG_INTEGER, 'SignerInfo.version');
  i++; // sid (issuerAndSerialNumber SEQUENCE or subjectKeyIdentifier [0]) — not needed
  const digestAlg = expectTag(children[i++] as Tlv, TAG_SEQUENCE, 'SignerInfo.digestAlgorithm');
  const digestOid = decodeOid(expectTag(readChildren(digestAlg.content)[0] as Tlv, TAG_OID, 'digestAlgorithm OID').content);
  const digestName = DIGEST_OID_TO_NAME[digestOid];
  if (digestName === undefined) throw new Error(`unknown digestAlgorithm OID ${digestOid}`);

  // Optional signedAttrs [0] IMPLICIT SET OF Attribute.
  let signedAttrsDer: Buffer | undefined;
  const attrs: Record<string, { oid?: string; value?: Buffer }> = {};
  if (((children[i] as Tlv).tag & 0xe0) === 0xa0 && ((children[i] as Tlv).tag & 0x1f) === 0x00) {
    const signedAttrs = children[i++] as Tlv;
    // RFC 5652 §5.4: the signature is over the DER of the attrs as a SET (tag
    // 0x31), NOT the [0] IMPLICIT tag actually on the wire. Re-encode by
    // replacing the leading tag byte with the universal SET tag, preserving the
    // exact length octets and content bytes (no re-canonicalization of order —
    // a conformant TSA already DER-encodes signedAttrs in sorted order).
    signedAttrsDer = Buffer.concat([Buffer.from([TAG_SET]), signedAttrs.full.subarray(1)]);
    for (const attr of readChildren(signedAttrs.content)) {
      const attrChildren = readChildren(expectTag(attr, TAG_SEQUENCE, 'Attribute').content);
      const attrOid = decodeOid(expectTag(attrChildren[0] as Tlv, TAG_OID, 'Attribute.type').content);
      const valueSet = expectTag(attrChildren[1] as Tlv, TAG_SET, 'Attribute.values');
      const firstVal = readChildren(valueSet.content)[0] as Tlv | undefined;
      if (attrOid === OID_CONTENT_TYPE && firstVal) {
        attrs[attrOid] = { oid: decodeOid(firstVal.content) };
      } else if (firstVal) {
        attrs[attrOid] = { value: Buffer.from(firstVal.content) };
      }
    }
  }

  const sigAlg = expectTag(children[i++] as Tlv, TAG_SEQUENCE, 'SignerInfo.signatureAlgorithm');
  const sigOid = decodeOid(expectTag(readChildren(sigAlg.content)[0] as Tlv, TAG_OID, 'signatureAlgorithm OID').content);
  const sigSpec = SIG_OID[sigOid];
  if (sigSpec === undefined) throw new Error(`unknown signatureAlgorithm OID ${sigOid}`);
  const signature = Buffer.from(expectTag(children[i++] as Tlv, TAG_OCTET_STRING, 'SignerInfo.signature').content);

  return {
    digestName,
    signatureKind: sigSpec.kind,
    signature,
    ...(signedAttrsDer !== undefined ? { signedAttrsDer } : {}),
    attrs,
  };
}

/** Verify an RSA-PKCS1v15 or ECDSA signature over `data` with `key`. */
function verifySignature(
  kind: 'rsa' | 'ecdsa',
  digestName: string,
  key: KeyObject,
  data: Buffer,
  signature: Buffer,
): boolean {
  try {
    const algo = digestName.toUpperCase();
    const verifier = createVerify(kind === 'rsa' ? `RSA-${algo}` : algo === 'SHA256' ? 'SHA256' : algo);
    verifier.update(data);
    verifier.end();
    // For ECDSA, Node expects DER signatures by default (RFC 3161 SignerInfo
    // signature IS the DER ECDSA-Sig-Value), so no format hint is needed.
    return verifier.verify(key, signature);
  } catch {
    return false;
  }
}

/** Coerce a PEM / DER SPKI / KeyObject into a public {@link KeyObject}. */
function toPublicKey(input: string | Uint8Array | KeyObject): KeyObject {
  if (typeof input === 'object' && input !== null && 'asymmetricKeyType' in input) {
    return input as KeyObject;
  }
  if (typeof input === 'string') {
    return createPublicKey(input); // PEM (SPKI or certificate)
  }
  return createPublicKey({ key: Buffer.from(input as Uint8Array), format: 'der', type: 'spki' });
}

/** Constant-time equality on equal-length digests (length mismatch fails fast). */
function timingSafeEqualHex(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Decode a lowercase/uppercase hex string to bytes (the checkpoint root form). */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length % 2 !== 0) throw new Error('hex string has odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
