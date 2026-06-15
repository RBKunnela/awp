/**
 * @module envelope/dsse
 *
 * DSSE v1.0 (Dead Simple Signing Envelope) encode / decode / sign / verify for
 * AWP, plus the in-package PAE (Pre-Authentication Encoding) implementation.
 *
 * Why DSSE (AWP spec §2): the signature is computed over PAE, a ~5-line framing
 * with NO canonicalization — re-implementable by an auditor in 2036 from this
 * docstring alone. The only determinism AWP layers on top is recursive key-sort
 * of the in-toto Statement JSON (`./canonical-json`), so the same record always
 * produces the same payload bytes.
 *
 * PAE, byte-exact (DSSE v1.0):
 * ```
 *   PAE(payloadType, payload) =
 *     "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
 * ```
 *  - `SP` is a single ASCII space (0x20).
 *  - `LEN(x)` is the length of `x` IN BYTES, written as ASCII decimal.
 *  - `"DSSEv1"`, the spaces, and `payloadType` are ASCII/UTF-8 bytes.
 *  - `payload` is appended as raw bytes (here, the canonical-JSON UTF-8 of the
 *    in-toto Statement).
 * The Ed25519 signature is over exactly these bytes. No hashing-before-sign is
 * applied by us — Node's Ed25519 (PureEdDSA / Ed25519ph=no) hashes internally as
 * the algorithm specifies.
 *
 * Envelope wire shape (DSSE v1.0):
 * ```json
 * {
 *   "payload": "<base64(canonical statement bytes)>",
 *   "payloadType": "application/vnd.in-toto+json",
 *   "signatures": [{ "keyid": "<optional>", "sig": "<base64(signature)>" }]
 * }
 * ```
 *
 * Key custody (AWP spec §1 principle 2: customer-keyed, this OPEN package holds
 * nothing): signing goes through a caller-supplied {@link Signer} so the
 * producer (core) injects its own Ed25519 key. Verification takes a raw 32-byte
 * Ed25519 public key (or a Node `KeyObject`). A {@link createTestSigner} is
 * provided for vectors/tests ONLY.
 *
 * Dependencies: Node `crypto` (stdlib — Ed25519 native since Node 12+; no
 * third-party signing dependency, keeping the verify path dependency-light per
 * the AW-3 offline requirement). `./canonical-json`, `./statement`, `../schema`.
 *
 * @example
 * import { signEnvelope, verifyEnvelope, createTestSigner } from './dsse.js';
 * const { signer, publicKey } = createTestSigner();
 * const env = signEnvelope(record, signer);
 * const result = verifyEnvelope(env, publicKey);
 * if (result.ok) console.log(result.record.profile);
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from 'node:crypto';
import { PAYLOAD_TYPE, type WitnessRecord } from '../schema/index.js';
import { canonicalJSONBytes } from './canonical-json.js';
import {
  buildStatement,
  buildValidatedStatement,
  checkStatementShape,
  statementAsJson,
  type WitnessStatement,
} from './statement.js';

const SP = 0x20; // ASCII space
const DSSE_PREFIX = 'DSSEv1';

/**
 * One signature on a DSSE envelope. `keyid` is an optional, opaque hint a
 * verifier MAY use to select a key; it is NOT trusted and never substitutes for
 * checking the signature against a known public key.
 */
export interface DsseSignature {
  /** Optional opaque key hint (e.g. a fingerprint). Not security-relevant. */
  keyid?: string;
  /** Base64-encoded raw Ed25519 signature (64 bytes). */
  sig: string;
}

/** A DSSE v1.0 envelope (wire shape). `payload` is base64 of the Statement bytes. */
export interface DsseEnvelope {
  /** Base64 of the canonical in-toto Statement UTF-8 bytes. */
  payload: string;
  /** The payload type; AWP fixes this to {@link PAYLOAD_TYPE}. */
  payloadType: string;
  /** One or more signatures over `PAE(payloadType, decode(payload))`. */
  signatures: DsseSignature[];
}

/**
 * A signing function injected by the key holder. Given the exact PAE bytes,
 * return the raw Ed25519 signature bytes (64). The OPEN package never sees the
 * private key — only this closure does.
 */
export type SignFn = (paeBytes: Uint8Array) => Uint8Array;

/** A signer: how to sign, and an optional keyid to stamp on the signature. */
export interface Signer {
  /** Produce a raw Ed25519 signature over the PAE bytes. */
  sign: SignFn;
  /** Optional keyid hint to record in the envelope signature. */
  keyid?: string;
}

/**
 * Compute the DSSE v1.0 Pre-Authentication Encoding for a payload type + payload.
 *
 * This is the byte string the signature is computed over. It is intentionally
 * trivial and fully specified by this function body (see the module docstring
 * for the spec). Lengths are byte lengths of the UTF-8 / raw encodings.
 *
 * @param payloadType - The DSSE payload type (e.g. {@link PAYLOAD_TYPE}).
 * @param payload - The raw payload bytes (the canonical Statement UTF-8).
 * @returns The PAE byte string.
 *
 * @example
 * pae('application/vnd.in-toto+json', new TextEncoder().encode('{}'));
 */
export function pae(payloadType: string, payload: Uint8Array): Uint8Array {
  const typeBytes = new TextEncoder().encode(payloadType);
  const prefixBytes = new TextEncoder().encode(DSSE_PREFIX);
  const typeLenBytes = new TextEncoder().encode(String(typeBytes.length));
  const payloadLenBytes = new TextEncoder().encode(String(payload.length));

  // "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
  const total =
    prefixBytes.length +
    1 +
    typeLenBytes.length +
    1 +
    typeBytes.length +
    1 +
    payloadLenBytes.length +
    1 +
    payload.length;

  const out = new Uint8Array(total);
  let off = 0;
  const put = (bytes: Uint8Array): void => {
    out.set(bytes, off);
    off += bytes.length;
  };
  put(prefixBytes);
  out[off++] = SP;
  put(typeLenBytes);
  out[off++] = SP;
  put(typeBytes);
  out[off++] = SP;
  put(payloadLenBytes);
  out[off++] = SP;
  put(payload);
  return out;
}

/**
 * Build the unsigned in-toto Statement payload bytes for a record: the canonical
 * (key-sorted) JSON UTF-8 of the Statement. Exposed for the signature path and
 * for test vectors.
 *
 * @param statement - The in-toto Statement to serialize.
 * @returns The canonical UTF-8 payload bytes.
 */
export function statementPayloadBytes(statement: WitnessStatement): Uint8Array {
  return canonicalJSONBytes(statementAsJson(statement));
}

/**
 * Encode a WitnessRecord into an UNSIGNED structure: the in-toto Statement and
 * its canonical payload bytes. Most callers want {@link signEnvelope}; this is
 * the seam for an external key-custody flow that signs the bytes itself.
 *
 * Fail-closed: an invalid record returns `{ ok: false, errors }`.
 *
 * @param input - The candidate WitnessRecord (validated here).
 * @returns The statement + payload bytes, or schema errors.
 */
export function encodePayload(
  input: unknown,
): { ok: true; statement: WitnessStatement; payload: Uint8Array } | { ok: false; errors: string[] } {
  const built = buildValidatedStatement(input);
  if (!built.ok) {
    return { ok: false, errors: built.errors };
  }
  return { ok: true, statement: built.statement, payload: statementPayloadBytes(built.statement) };
}

/**
 * Wrap a validated WitnessRecord in a signed DSSE v1.0 envelope carrying an
 * in-toto Statement v1 (AWP spec §4). The record is validated first; an invalid
 * record throws (callers with untrusted input should pre-validate or use
 * {@link encodePayload}).
 *
 * @param record - A WitnessRecord to wrap and sign.
 * @param signer - The key holder's signing closure (+ optional keyid).
 * @returns The signed DSSE envelope.
 * @throws {Error} If `record` is not a structurally-valid WitnessRecord.
 *
 * @example
 * const env = signEnvelope(record, signer);
 * // env.signatures[0].sig is base64; env.payload is base64 of the statement
 */
export function signEnvelope(record: WitnessRecord, signer: Signer): DsseEnvelope {
  const built = buildValidatedStatement(record);
  if (!built.ok) {
    throw new Error(`cannot sign an invalid WitnessRecord: ${built.errors.join('; ')}`);
  }
  const payload = statementPayloadBytes(built.statement);
  const paeBytes = pae(PAYLOAD_TYPE, payload);
  const sig = signer.sign(paeBytes);
  const signature: DsseSignature = {
    sig: Buffer.from(sig).toString('base64'),
    ...(signer.keyid !== undefined ? { keyid: signer.keyid } : {}),
  };
  return {
    payload: Buffer.from(payload).toString('base64'),
    payloadType: PAYLOAD_TYPE,
    signatures: [signature],
  };
}

/** Result of {@link decodeEnvelope}. */
export type DecodeResult =
  | { ok: true; statement: WitnessStatement; record: WitnessRecord }
  | { ok: false; reason: string };

/**
 * Decode a DSSE envelope's payload back to a Statement + WitnessRecord WITHOUT
 * checking the signature. Validates the envelope wire shape, the `payloadType`,
 * and the Statement/record shape (via {@link checkStatementShape}) — so a
 * malformed or non-AWP envelope is rejected with a named reason rather than
 * yielding a half-trusted object.
 *
 * NOTE: decoding is not verification. Use {@link verifyEnvelope} when you need
 * the signature checked; this is the round-trip / inspection path.
 *
 * @param envelope - The DSSE envelope (already JSON-parsed).
 * @returns `{ ok: true, statement, record }` or `{ ok: false, reason }`.
 */
export function decodeEnvelope(envelope: unknown): DecodeResult {
  const shape = checkEnvelopeShape(envelope);
  if (!shape.ok) {
    return { ok: false, reason: shape.reason };
  }
  const env = shape.envelope;
  if (env.payloadType !== PAYLOAD_TYPE) {
    return {
      ok: false,
      reason: `payloadType must be "${PAYLOAD_TYPE}", got ${JSON.stringify(env.payloadType)}`,
    };
  }
  let payloadJson: unknown;
  try {
    const bytes = Buffer.from(env.payload, 'base64');
    payloadJson = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    return { ok: false, reason: `payload is not valid base64 JSON: ${(err as Error).message}` };
  }
  const stmt = checkStatementShape(payloadJson);
  if (!stmt.ok) {
    return { ok: false, reason: stmt.reason };
  }
  return { ok: true, statement: stmt.statement, record: stmt.statement.predicate };
}

/** A single named check result, mirroring the AW-3 per-check report contract. */
export interface EnvelopeCheck {
  /** Check name, e.g. `"signature"`, `"payloadType"`, `"statement"`. */
  name: string;
  /** Whether the check passed. */
  ok: boolean;
  /** One-line human reason (always present — never a bare boolean). */
  reason: string;
}

/** Result of {@link verifyEnvelope}: the per-check list plus the parsed record on success. */
export type VerifyEnvelopeResult =
  | { ok: true; checks: EnvelopeCheck[]; statement: WitnessStatement; record: WitnessRecord }
  | { ok: false; checks: EnvelopeCheck[] };

/**
 * A public key accepted by {@link verifyEnvelope}: a Node `KeyObject`, a raw
 * 32-byte Ed25519 public key (`Uint8Array`/`Buffer`), or a PEM/DER string.
 */
export type PublicKeyInput = KeyObject | Uint8Array | string;

/**
 * Verify a DSSE v1.0 envelope FAIL-CLOSED against an Ed25519 public key.
 *
 * Runs, and reports by name, every applicable check (threat model: "every
 * applicable check must run and report"):
 *  1. `envelope-shape` — the wire shape is a DSSE envelope with ≥1 signature;
 *  2. `payloadType` — equals {@link PAYLOAD_TYPE} (algorithm/format confusion);
 *  3. `signature` — at least one signature verifies over `PAE(payloadType,
 *     payload)` with the supplied key (Ed25519);
 *  4. `statement` — the decoded payload is a valid AWP in-toto Statement whose
 *     subject binds the predicate's intent (AC5).
 *
 * The overall result is `ok` only when ALL checks pass. A tampered payload
 * fails `signature`; a wrong key fails `signature`; a mismatched payloadType or
 * statement fails its own named check.
 *
 * @param envelope - The DSSE envelope (already JSON-parsed).
 * @param publicKey - The Ed25519 public key that should have signed it.
 * @returns The per-check list, plus the record/statement when fully valid.
 *
 * @example
 * const r = verifyEnvelope(env, publicKey);
 * if (!r.ok) for (const c of r.checks) if (!c.ok) console.error(c.name, c.reason);
 */
export function verifyEnvelope(envelope: unknown, publicKey: PublicKeyInput): VerifyEnvelopeResult {
  const checks: EnvelopeCheck[] = [];

  // 1. envelope shape
  const shape = checkEnvelopeShape(envelope);
  if (!shape.ok) {
    checks.push({ name: 'envelope-shape', ok: false, reason: shape.reason });
    return { ok: false, checks };
  }
  checks.push({ name: 'envelope-shape', ok: true, reason: 'well-formed DSSE envelope with ≥1 signature' });
  const env = shape.envelope;

  // 2. payloadType
  if (env.payloadType !== PAYLOAD_TYPE) {
    checks.push({
      name: 'payloadType',
      ok: false,
      reason: `payloadType must be "${PAYLOAD_TYPE}", got ${JSON.stringify(env.payloadType)}`,
    });
    return { ok: false, checks };
  }
  checks.push({ name: 'payloadType', ok: true, reason: `payloadType is "${PAYLOAD_TYPE}"` });

  // 3. signature — over PAE(payloadType, raw payload bytes)
  let payloadBytes: Buffer;
  try {
    payloadBytes = Buffer.from(env.payload, 'base64');
  } catch (err) {
    checks.push({ name: 'signature', ok: false, reason: `payload not base64: ${(err as Error).message}` });
    return { ok: false, checks };
  }
  const paeBytes = pae(env.payloadType, payloadBytes);

  let keyObject: KeyObject;
  try {
    keyObject = toPublicKeyObject(publicKey);
  } catch (err) {
    checks.push({ name: 'signature', ok: false, reason: `invalid public key: ${(err as Error).message}` });
    return { ok: false, checks };
  }

  const sigOk = env.signatures.some((s) => {
    let sigBytes: Buffer;
    try {
      sigBytes = Buffer.from(s.sig, 'base64');
    } catch {
      return false;
    }
    try {
      return nodeVerify(null, paeBytes, keyObject, sigBytes);
    } catch {
      return false;
    }
  });
  if (!sigOk) {
    checks.push({
      name: 'signature',
      ok: false,
      reason: 'no signature verified against the supplied Ed25519 public key (tampered payload or wrong key)',
    });
    return { ok: false, checks };
  }
  checks.push({ name: 'signature', ok: true, reason: 'Ed25519 signature verified over DSSE PAE' });

  // 4. statement shape + subject binding
  let payloadJson: unknown;
  try {
    payloadJson = JSON.parse(payloadBytes.toString('utf8'));
  } catch (err) {
    checks.push({ name: 'statement', ok: false, reason: `payload not JSON: ${(err as Error).message}` });
    return { ok: false, checks };
  }
  const stmt = checkStatementShape(payloadJson);
  if (!stmt.ok) {
    checks.push({ name: 'statement', ok: false, reason: stmt.reason });
    return { ok: false, checks };
  }
  checks.push({ name: 'statement', ok: true, reason: 'valid in-toto Statement; subject binds intent (AC5)' });

  return { ok: true, checks, statement: stmt.statement, record: stmt.statement.predicate };
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

/** Validated DSSE wire shape (payload string, payloadType string, ≥1 sig). */
type EnvelopeShapeResult =
  | { ok: true; envelope: DsseEnvelope }
  | { ok: false; reason: string };

/**
 * Validate the DSSE envelope wire shape: an object with a string `payload`, a
 * string `payloadType`, and a non-empty `signatures` array whose entries each
 * have a string `sig` (and optional string `keyid`).
 *
 * @param value - The candidate envelope.
 * @returns The typed envelope or a named reason.
 */
function checkEnvelopeShape(value: unknown): EnvelopeShapeResult {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'envelope is not a JSON object' };
  }
  const obj = value as Record<string, unknown>;
  if (typeof obj['payload'] !== 'string') {
    return { ok: false, reason: 'envelope.payload must be a base64 string' };
  }
  if (typeof obj['payloadType'] !== 'string') {
    return { ok: false, reason: 'envelope.payloadType must be a string' };
  }
  const sigs = obj['signatures'];
  if (!Array.isArray(sigs) || sigs.length === 0) {
    return { ok: false, reason: 'envelope.signatures must be a non-empty array' };
  }
  const signatures: DsseSignature[] = [];
  for (const s of sigs) {
    if (s === null || typeof s !== 'object') {
      return { ok: false, reason: 'each signature must be an object' };
    }
    const so = s as Record<string, unknown>;
    if (typeof so['sig'] !== 'string') {
      return { ok: false, reason: 'each signature must have a base64 string "sig"' };
    }
    if (so['keyid'] !== undefined && typeof so['keyid'] !== 'string') {
      return { ok: false, reason: 'signature keyid, when present, must be a string' };
    }
    signatures.push({
      sig: so['sig'],
      ...(typeof so['keyid'] === 'string' ? { keyid: so['keyid'] } : {}),
    });
  }
  return {
    ok: true,
    envelope: { payload: obj['payload'], payloadType: obj['payloadType'], signatures },
  };
}

/**
 * Coerce a {@link PublicKeyInput} to a Node `KeyObject`. A raw 32-byte
 * Uint8Array is wrapped as a DER SPKI Ed25519 key; PEM/DER strings and existing
 * KeyObjects pass through `createPublicKey`.
 *
 * @param key - The public key in any accepted form.
 * @returns A Node `KeyObject` usable with `crypto.verify`.
 */
function toPublicKeyObject(key: PublicKeyInput): KeyObject {
  if (typeof key === 'object' && key !== null && 'asymmetricKeyType' in key) {
    return key as KeyObject;
  }
  if (key instanceof Uint8Array) {
    if (key.length === 32) {
      return createPublicKey({ key: rawEd25519ToSpki(key), format: 'der', type: 'spki' });
    }
    // Assume DER already.
    return createPublicKey({ key: Buffer.from(key), format: 'der', type: 'spki' });
  }
  // string: PEM (createPublicKey auto-detects PEM)
  return createPublicKey(key);
}

/** The fixed 12-byte DER prefix for an Ed25519 SubjectPublicKeyInfo. */
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Wrap a raw 32-byte Ed25519 public key in a DER SPKI structure so
 * `createPublicKey` accepts it. The prefix is the standard Ed25519 SPKI header.
 *
 * @param raw - The raw 32-byte Ed25519 public key.
 * @returns DER-encoded SPKI bytes.
 */
function rawEd25519ToSpki(raw: Uint8Array): Buffer {
  return Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
}

/**
 * Create an in-process Ed25519 {@link Signer} plus its public key, for tests and
 * committed vectors ONLY. Real deployments inject their own signer; the OPEN
 * package never generates or holds production keys.
 *
 * @param keyid - Optional keyid to stamp on produced signatures.
 * @returns `{ signer, publicKey, privateKey }` — `publicKey` is a Node KeyObject.
 *
 * @example
 * const { signer, publicKey } = createTestSigner('test-key-1');
 * const env = signEnvelope(record, signer);
 * verifyEnvelope(env, publicKey).ok; // true
 */
export function createTestSigner(keyid?: string): {
  signer: Signer;
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const signer: Signer = {
    sign: (paeBytes: Uint8Array): Uint8Array => nodeSign(null, paeBytes, privateKey),
    ...(keyid !== undefined ? { keyid } : {}),
  };
  return { signer, publicKey, privateKey };
}

/**
 * Build a {@link Signer} from an externally-held Ed25519 private key (PEM, DER,
 * or a Node `KeyObject`) — the customer-key-custody path. The private key is
 * captured only inside the returned closure.
 *
 * @param privateKey - The Ed25519 private key (KeyObject or PEM/DER string).
 * @param keyid - Optional keyid hint.
 * @returns A {@link Signer}.
 */
export function signerFromPrivateKey(
  privateKey: KeyObject | string,
  keyid?: string,
): Signer {
  const key = typeof privateKey === 'string' ? privateKey : privateKey;
  return {
    sign: (paeBytes: Uint8Array): Uint8Array => nodeSign(null, paeBytes, key),
    ...(keyid !== undefined ? { keyid } : {}),
  };
}

export { buildStatement };
