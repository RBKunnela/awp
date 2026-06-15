/**
 * @module verify/checks
 *
 * The individual, named checks `awp verify` runs. Each returns a
 * {@link CheckResult} — `{ name, ok, reason }`, never a bare boolean (AW-3 AC4:
 * "the report lists every check with PASS/FAIL and a one-line reason"). The
 * checks compose AW-1 (schema + profile validators) and AW-2 (DSSE/in-toto
 * verify) with no duplication, plus AWP-specific honesty and chain-link checks
 * and the optional AW-5 OTS anchor read.
 *
 * Offline guarantee (AC3): every check here uses only Node stdlib `crypto` and
 * in-memory data. None opens a socket, reads the filesystem, or calls a
 * calendar. The CLI reads the input file once; the checks never do I/O.
 *
 * Checks, in the order the verifier runs them:
 *  1. `schema`        — the predicate is a structurally-valid WitnessRecord (AW-1).
 *  2. `profile`       — the record meets its profile's minimums (AW-1 profiles).
 *  3. `signature`     — the DSSE Ed25519 signature verifies over PAE (AW-2);
 *                       implies the in-toto Statement shape + subject binding,
 *                       which AW-2's `verifyEnvelope` checks before returning.
 *  4. `claim-class`   — every verification carries a valid honesty-boundary
 *                       claim_class, and the record does not overclaim.
 *  5. `chain-link`    — `chain.prev_record_hash` matches the supplied
 *                       predecessor (when one is supplied), else is well-formed.
 *  6. `checkpoint`    — when a signed C2SP checkpoint is present, its note
 *                       signature verifies and the root it commits is returned as
 *                       authoritative (AW-4). "Not present" is reported, not skipped.
 *  7. `inclusion`     — when an RFC 9162 inclusion proof is present, the record's
 *                       leaf hash matches and folds to the signed checkpoint root
 *                       (AW-4). "Not present" is reported, not skipped.
 *  8. `anchor`        — when an external anchor is present (OTS and/or RFC 3161),
 *                       it commits the verified checkpoint root; reported as an
 *                       honest time BOUND with the anchor's evidentiary weight.
 *                       "Not present" is reported, not silently skipped.
 *
 * Dependencies: `../schema` (AW-1), `../envelope` (AW-2), `../log` (AW-4 Merkle +
 *               checkpoint), `../anchor` (AW-5 OTS + RFC 3161), Node `crypto`.
 * Used by: `./verify`.
 */

import { createHash } from 'node:crypto';
import {
  CLAIM_CLASSES,
  validateRecordAndProfile,
  type ClaimClass,
  type WitnessRecord,
} from '../schema/index.js';
import {
  statementPayloadBytes,
  verifyEnvelope,
  buildStatement,
  type PublicKeyInput,
  type WitnessStatement,
} from '../envelope/index.js';
import { verifyOtsAnchor, verifyRfc3161Anchor } from '../anchor/index.js';
import type {
  AnchorProof,
  Rfc3161AnchorProof,
  Rfc3161TrustAnchor,
} from '../anchor/index.js';
import {
  fromHex,
  hashLeaf,
  toHex,
  verifyInclusion,
  verifyNote,
  parseCheckpoint,
  type InclusionProof,
} from '../log/index.js';
import type { FullReceipt, WireInclusionProof } from '../ops/index.js';

/** Lowercase 64-char hex SHA-256 — the only digest form AWP uses. */
const SHA256_HEX = /^[a-f0-9]{64}$/;

/**
 * One named check outcome. `ok` is the pass/fail; `reason` is always a
 * one-line human explanation (never omitted, never a bare boolean) so the
 * report is legible and a FAIL names exactly what failed.
 */
export interface CheckResult {
  /** Stable check name, e.g. `"signature"`, `"chain-link"`, `"anchor"`. */
  name: string;
  /** Whether the check passed. */
  ok: boolean;
  /** One-line human-readable reason (always present). */
  reason: string;
}

/**
 * Inputs the checks may need beyond the receipt itself: the public key the
 * envelope should verify against, and (optionally) the predecessor record's
 * hash to confirm the per-record chain link.
 */
export interface CheckContext {
  /** The Ed25519 public key the DSSE envelope must verify against. */
  publicKey: PublicKeyInput;
  /**
   * Optional expected predecessor hash. When supplied, the chain-link check
   * asserts `record.chain.prev_record_hash === expectedPrevRecordHash`. When
   * omitted, the check only asserts the field is a well-formed digest (no
   * predecessor to compare against — e.g. a genesis or standalone record).
   */
  expectedPrevRecordHash?: string;
  /**
   * Optional pinned RFC 3161 trust anchor (the TSA signing key the operator
   * trusts, plus its `qualified` flag). REQUIRED to verify an RFC 3161 anchor; a
   * receipt carrying an `rfc3161` anchor without a trust anchor here (or embedded
   * in the receipt) FAILS that anchor — the verifier trusts no TSA implicitly.
   */
  rfc3161TrustAnchor?: Rfc3161TrustAnchor;
}

/** SHA-256 of bytes, hex. */
function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Check 1+2 — schema and profile. Returns the parsed record on success so later
 * checks need not re-parse. Composes AW-1's `validateRecordAndProfile`.
 *
 * @param predicate - The decoded WitnessRecord predicate (or unknown JSON).
 * @returns Two check results (schema, profile) and the record when both pass.
 */
export function checkSchemaAndProfile(predicate: unknown): {
  checks: CheckResult[];
  record?: WitnessRecord;
} {
  const result = validateRecordAndProfile(predicate);
  if (result.ok) {
    return {
      checks: [
        { name: 'schema', ok: true, reason: 'predicate is a structurally-valid WitnessRecord v0.1' },
        {
          name: 'profile',
          ok: true,
          reason: `profile "${result.profile}" constraints satisfied`,
        },
      ],
      record: result.record,
    };
  }
  if (result.stage === 'schema') {
    return {
      checks: [
        { name: 'schema', ok: false, reason: `invalid WitnessRecord: ${result.errors.join('; ')}` },
        { name: 'profile', ok: false, reason: 'skipped — record failed structural validation' },
      ],
    };
  }
  // stage === 'profile': schema passed, profile minimums unmet.
  return {
    checks: [
      { name: 'schema', ok: true, reason: 'predicate is a structurally-valid WitnessRecord v0.1' },
      {
        name: 'profile',
        ok: false,
        reason: `profile "${result.profile}" unmet: ${result.failures
          .map((f) => f.constraint)
          .join(', ')}`,
      },
    ],
  };
}

/**
 * Check 3 — DSSE signature + in-toto Statement shape + subject binding. Thin
 * wrapper over AW-2's {@link verifyEnvelope}: a tampered payload or wrong key
 * fails `signature`; a non-AWP statement fails `statement`. The decoded record
 * is returned on success.
 *
 * @param envelope - The DSSE envelope (already JSON-parsed).
 * @param publicKey - The Ed25519 public key the envelope must verify against.
 * @returns The named checks plus `{ record, statement }` when fully valid.
 */
export function checkSignature(
  envelope: unknown,
  publicKey: PublicKeyInput,
): { checks: CheckResult[]; record?: WitnessRecord; statement?: WitnessStatement } {
  const result = verifyEnvelope(envelope, publicKey);
  // verifyEnvelope already returns named { name, ok, reason } checks — reuse them.
  if (result.ok) {
    return { checks: result.checks, record: result.record, statement: result.statement };
  }
  return { checks: result.checks };
}

/**
 * Check 4 — claim-class honesty boundary. Asserts every `verifications[]` entry
 * carries a `claim_class` from the closed set {@link CLAIM_CLASSES}
 * (`integrity-since-witness` / `verified-against` / `asserted-by`), so a record
 * cannot grammatically overclaim authenticity-at-origin or identity-proofing.
 *
 * The schema enum already rejects unknown values structurally; this check is the
 * EXPLICIT, named restatement of the honesty boundary in the verifier's report
 * (auditor-enablement §3 Part C: volunteer the limit before the auditor finds
 * it). It also flags the dishonest combination of a `verified-against` claim
 * whose own `result` is not `pass` — claiming verification you did not achieve.
 *
 * @param record - A structurally-valid WitnessRecord.
 * @returns A single `claim-class` check result.
 */
export function checkClaimClassHonesty(record: WitnessRecord): CheckResult {
  const verifications = record.verifications ?? [];
  const allowed = new Set<string>(CLAIM_CLASSES);

  for (const v of verifications) {
    if (!allowed.has(v.claim_class)) {
      return {
        name: 'claim-class',
        ok: false,
        reason: `verification "${v.check}" has claim_class "${v.claim_class}" outside the honesty boundary {${CLAIM_CLASSES.join(
          ', ',
        )}}`,
      };
    }
    // A "verified-against" claim must actually have passed its verification —
    // claiming you verified something whose result was fail/unverifiable is the
    // exact overclaim the boundary exists to prevent.
    if (v.claim_class === ('verified-against' satisfies ClaimClass) && v.result !== 'pass') {
      return {
        name: 'claim-class',
        ok: false,
        reason: `verification "${v.check}" claims "verified-against" but its result is "${v.result}" (overclaim: not actually verified)`,
      };
    }
  }

  const summary =
    verifications.length === 0
      ? 'no verification entries (record claims only integrity-since-witness)'
      : `${verifications.length} verification(s); every claim_class within the honesty boundary`;
  return { name: 'claim-class', ok: true, reason: summary };
}

/**
 * Check 5 — per-record hash-chain link. When `expectedPrevRecordHash` is
 * supplied, asserts `record.chain.prev_record_hash` equals it (a mismatch means
 * the record does not link to the claimed predecessor — AC5). When no
 * predecessor is supplied, asserts the field is a well-formed digest (a genesis
 * or standalone record links to nothing to compare here).
 *
 * Re-implemented in-package against the record's own `chain` block — the kernel
 * hash-chain semantics conceptually, but NO core import (AW-3 context & reuse).
 *
 * @param record - A structurally-valid WitnessRecord.
 * @param expectedPrevRecordHash - Optional predecessor hash to match.
 * @returns A single `chain-link` check result.
 */
export function checkChainLink(
  record: WitnessRecord,
  expectedPrevRecordHash?: string,
): CheckResult {
  const prev = record.chain.prev_record_hash;
  if (!SHA256_HEX.test(prev)) {
    return {
      name: 'chain-link',
      ok: false,
      reason: `chain.prev_record_hash is not a lowercase 64-char hex SHA-256`,
    };
  }
  if (expectedPrevRecordHash === undefined) {
    return {
      name: 'chain-link',
      ok: true,
      reason: `chain.prev_record_hash well-formed (no predecessor supplied to compare)`,
    };
  }
  if (prev !== expectedPrevRecordHash.toLowerCase()) {
    return {
      name: 'chain-link',
      ok: false,
      reason: `chain.prev_record_hash does not match the supplied predecessor (expected ${expectedPrevRecordHash.slice(
        0,
        12,
      )}…, got ${prev.slice(0, 12)}…)`,
    };
  }
  return {
    name: 'chain-link',
    ok: true,
    reason: `chain.prev_record_hash matches the supplied predecessor`,
  };
}

/**
 * The legacy Phase-1 record commitment: `sha256(canonical statement bytes)`. The
 * full RFC 9162 inclusion proof (AW-6, {@link checkInclusion}) is the primary
 * binding now; this remains for AW-3 receipts that carry only `record_commitment`
 * and for the optional `record_commitment` cross-check.
 *
 * @param record - The decoded WitnessRecord.
 * @returns The hex commitment.
 */
export function recordCommitment(record: WitnessRecord): string {
  return sha256Hex(statementPayloadBytes(buildStatement(record)));
}

/**
 * The canonical leaf bytes a record contributes to the transparency log: the
 * EXACT in-toto Statement bytes the DSSE envelope signs
 * (`statementPayloadBytes(buildStatement(record))`). The log's leaf hash is then
 * `hashLeaf(theseBytes)` (RFC 9162 `SHA-256(0x00 || bytes)`). Exposed so the
 * inclusion check (and an auditor) can recompute the committed leaf from the
 * decoded record with no hidden canonicalization.
 *
 * @param record - The decoded WitnessRecord.
 * @returns The canonical Statement leaf bytes.
 */
export function recordLeafBytes(record: WitnessRecord): Uint8Array {
  return statementPayloadBytes(buildStatement(record));
}

/**
 * Rebuild an in-memory RFC 9162 {@link InclusionProof} from a receipt's
 * JSON-portable {@link WireInclusionProof} (hex hashes → bytes). Returns an error
 * string if any hash is not a well-formed 32-byte hex value.
 *
 * @param wire - The wire inclusion proof from the receipt.
 * @returns `{ ok, proof }` or `{ ok: false, reason }`.
 */
function parseWireInclusion(
  wire: WireInclusionProof,
): { ok: true; proof: InclusionProof } | { ok: false; reason: string } {
  if (!Number.isInteger(wire.leafIndex) || wire.leafIndex < 0) {
    return { ok: false, reason: 'inclusion.leafIndex must be a non-negative integer' };
  }
  if (!Number.isInteger(wire.treeSize) || wire.treeSize < 1 || wire.leafIndex >= wire.treeSize) {
    return { ok: false, reason: 'inclusion.treeSize must be a positive integer greater than leafIndex' };
  }
  if (!SHA256_HEX.test(wire.leafHash)) {
    return { ok: false, reason: 'inclusion.leafHash is not a lowercase 64-char hex SHA-256' };
  }
  if (!Array.isArray(wire.siblings)) {
    return { ok: false, reason: 'inclusion.siblings must be an array' };
  }
  const siblings = [];
  for (const s of wire.siblings) {
    if (s === null || typeof s !== 'object' || !SHA256_HEX.test(s.hash)) {
      return { ok: false, reason: 'each inclusion.siblings[].hash must be a lowercase 64-char hex SHA-256' };
    }
    if (s.position !== 'left' && s.position !== 'right') {
      return { ok: false, reason: "each inclusion.siblings[].position must be 'left' or 'right'" };
    }
    siblings.push({ hash: fromHex(s.hash), position: s.position });
  }
  return {
    ok: true,
    proof: {
      leafIndex: wire.leafIndex,
      treeSize: wire.treeSize,
      leafHash: fromHex(wire.leafHash),
      siblings,
    },
  };
}

/**
 * Check — the signed C2SP checkpoint. When the receipt carries a `checkpoint`
 * block (AW-6), verifies the signed note against the log key the receipt embeds
 * (or that the operator pins), parses the `tlog-checkpoint` body, and confirms the
 * committed root equals `receipt.checkpoint_root`. A tampered checkpoint body
 * (changed size or root) fails the note signature; a wrong/forged key fails it
 * too. Returns the AUTHORITATIVE root (the one inside the signed note) so the
 * inclusion check folds against signed data, not a convenience field.
 *
 * "Not present" is reported as a passing, explicit line (a bare signed envelope or
 * an AW-3 receipt has no checkpoint to verify) — never a silent skip.
 *
 * @param receipt - The full receipt (may carry a `checkpoint` block).
 * @returns The `checkpoint` check plus the verified root bytes when present+valid.
 */
export function checkCheckpoint(
  receipt: FullReceipt,
): { check: CheckResult; rootHex?: string } {
  const cp = receipt.checkpoint;
  if (cp === undefined) {
    return {
      check: {
        name: 'checkpoint',
        ok: true,
        reason: 'no checkpoint block present (record bound directly via record_commitment, if anchored)',
      },
    };
  }
  if (typeof cp.note !== 'string' || typeof cp.keyName !== 'string' || typeof cp.publicKeyB64 !== 'string') {
    return { check: { name: 'checkpoint', ok: false, reason: 'checkpoint block is malformed (need note, keyName, publicKeyB64)' } };
  }

  let pub: Uint8Array;
  try {
    pub = new Uint8Array(Buffer.from(cp.publicKeyB64, 'base64'));
  } catch (err) {
    return { check: { name: 'checkpoint', ok: false, reason: `checkpoint publicKeyB64 invalid: ${(err as Error).message}` } };
  }
  if (pub.length !== 32) {
    return { check: { name: 'checkpoint', ok: false, reason: `checkpoint public key must be 32 raw bytes (got ${pub.length})` } };
  }

  const noteResult = verifyNote(cp.note, { name: cp.keyName, publicKey: pub });
  if (!noteResult.ok) {
    const failed = noteResult.checks.find((c) => !c.ok);
    return {
      check: {
        name: 'checkpoint',
        ok: false,
        reason: `checkpoint note signature failed (${failed?.name}): ${failed?.reason}`,
      },
    };
  }

  const parsed = parseCheckpoint(noteResult.text);
  if (!parsed.ok) {
    return { check: { name: 'checkpoint', ok: false, reason: `checkpoint body invalid: ${parsed.reason}` } };
  }
  const signedRootHex = toHex(parsed.checkpoint.root);

  // The convenience field, when present, MUST agree with the signed root.
  if (receipt.checkpoint_root !== undefined && receipt.checkpoint_root.toLowerCase() !== signedRootHex) {
    return {
      check: {
        name: 'checkpoint',
        ok: false,
        reason: 'receipt.checkpoint_root does not match the root inside the signed checkpoint note',
      },
    };
  }

  return {
    check: {
      name: 'checkpoint',
      ok: true,
      reason: `signed checkpoint for "${parsed.checkpoint.origin}" verified: size ${parsed.checkpoint.size}, root ${signedRootHex.slice(0, 12)}…`,
    },
    rootHex: signedRootHex,
  };
}

/**
 * Check — the RFC 9162 inclusion proof. When the receipt carries an `inclusion`
 * block (AW-6), this confirms the record's leaf is in the tree the checkpoint
 * committed:
 *  1. the proof's `leafHash` equals `hashLeaf(recordLeafBytes(record))` — i.e. the
 *     proof is for THIS record's signed Statement bytes, not some other leaf;
 *  2. folding the leaf hash with the audit-path siblings reproduces the
 *     checkpoint root (the verified, signed root from {@link checkCheckpoint} when
 *     available, else the receipt's `checkpoint_root`).
 *
 * A flipped byte anywhere (leaf hash, a sibling, the root) makes the fold diverge
 * → FAIL. "Not present" is an explicit passing line, never a silent skip.
 *
 * @param receipt - The full receipt (may carry an `inclusion` block).
 * @param record - The decoded WitnessRecord (to recompute the committed leaf).
 * @param verifiedRootHex - The signed checkpoint root from {@link checkCheckpoint},
 *   if the checkpoint verified; otherwise inclusion folds against
 *   `receipt.checkpoint_root`.
 * @returns A single `inclusion` check result.
 */
export function checkInclusion(
  receipt: FullReceipt,
  record: WitnessRecord,
  verifiedRootHex?: string,
): CheckResult {
  const wire = receipt.inclusion;
  if (wire === undefined) {
    return {
      name: 'inclusion',
      ok: true,
      reason: 'no inclusion proof present (record not bound to a Merkle tree in this receipt)',
    };
  }

  const parsed = parseWireInclusion(wire);
  if (!parsed.ok) {
    return { name: 'inclusion', ok: false, reason: parsed.reason };
  }
  const proof = parsed.proof;

  // (1) The proof must be for THIS record's canonical Statement leaf.
  const expectedLeafHash = hashLeaf(recordLeafBytes(record));
  if (toHex(expectedLeafHash) !== toHex(proof.leafHash)) {
    return {
      name: 'inclusion',
      ok: false,
      reason: 'inclusion proof leafHash does not equal hashLeaf(record statement bytes) — proof is for a different leaf',
    };
  }

  // (2) Determine the root to fold against. Prefer the signed checkpoint root.
  const rootHex = verifiedRootHex ?? receipt.checkpoint_root;
  if (rootHex === undefined || !SHA256_HEX.test(rootHex.toLowerCase())) {
    return {
      name: 'inclusion',
      ok: false,
      reason: 'no checkpoint root to verify the inclusion proof against (missing/invalid checkpoint_root and no signed checkpoint)',
    };
  }

  const ok = verifyInclusion(proof.leafHash, proof, fromHex(rootHex.toLowerCase()));
  if (!ok) {
    return {
      name: 'inclusion',
      ok: false,
      reason: `inclusion proof does not reproduce the checkpoint root (leaf ${proof.leafIndex} of ${proof.treeSize}); tree/root mismatch`,
    };
  }
  return {
    name: 'inclusion',
    ok: true,
    reason: `RFC 9162 inclusion proof verified: leaf ${proof.leafIndex} of ${proof.treeSize} reproduces root ${rootHex.slice(0, 12)}…`,
  };
}

/**
 * The honest, never-overstated time-bounding line for an anchored record (AW-6
 * AC5; auditor play §2 item 7). A record's existence is BOUNDED by its
 * checkpoint's anchor — "this record existed no later than the checkpoint anchored
 * at T" — never a per-record qualified time. The weight word is the anchor's:
 * `trust-minimized` for OTS (Bitcoin), `qualified` only for an RFC 3161 token
 * verified against an operator-declared qualified anchor.
 *
 * @param weight - The honest evidentiary weight (`trust-minimized`/`qualified`/`timestamp`).
 * @param detail - The anchor-specific time detail (block/genTime).
 * @returns The bounding sentence.
 */
export function timeBoundingLine(weight: string, detail: string): string {
  return `time bound: this record existed no later than the checkpoint anchored by this proof (${weight}); ${detail}`;
}

/**
 * Check — external time anchor (optional). When the receipt carries no anchors,
 * reports `not-present` (an explicit, passing line; never a silent skip). When
 * anchors are present, for each one it:
 *  - confirms the anchor commits the receipt's checkpoint root (the SIGNED root
 *    from {@link checkCheckpoint} when available, else `receipt.checkpoint_root`);
 *  - for OTS, reads the proof offline (trust-minimized weight, confirmed/pending);
 *  - for RFC 3161, verifies the token against the pinned trust anchor (from the
 *    verify options or embedded in the receipt) and reports `qualified` weight
 *    ONLY when that anchor is declared qualified — else a plain timestamp.
 * The result phrases the record's time as BOUNDED by the checkpoint anchor (AC5).
 *
 * When `record_commitment` is present it is still cross-checked against the
 * recomputed commitment (back-compat with AW-3 receipts).
 *
 * @param receipt - The full receipt (envelope + optional anchors).
 * @param record - The decoded WitnessRecord (for the commitment recompute).
 * @param verifiedRootHex - The signed checkpoint root, if the checkpoint verified.
 * @param trustAnchor - The pinned RFC 3161 trust anchor from the verify options.
 * @returns A single `anchor` check result summarizing all anchors.
 */
export function checkAnchor(
  receipt: FullReceipt,
  record: WitnessRecord,
  verifiedRootHex?: string,
  trustAnchor?: Rfc3161TrustAnchor,
): CheckResult {
  const anchors = receipt.anchors ?? [];
  if (anchors.length === 0) {
    return {
      name: 'anchor',
      ok: true,
      reason: 'no external anchor present (signature + chain still prove integrity-since-witness)',
    };
  }

  // An anchored receipt MUST bind the record to a checkpoint root. Prefer the
  // signed root (already proven by checkCheckpoint) over the convenience field.
  const checkpointRoot = (verifiedRootHex ?? receipt.checkpoint_root)?.toLowerCase();
  if (checkpointRoot === undefined || !SHA256_HEX.test(checkpointRoot)) {
    return {
      name: 'anchor',
      ok: false,
      reason: 'anchors present but no valid checkpoint root to bind them to (missing/invalid checkpoint_root and no signed checkpoint)',
    };
  }
  const expectedCommitment = recordCommitment(record);
  if (receipt.record_commitment !== undefined && receipt.record_commitment !== expectedCommitment) {
    return {
      name: 'anchor',
      ok: false,
      reason: 'receipt.record_commitment does not match the recomputed record commitment (record not bound to this anchor)',
    };
  }

  // The trust anchor for RFC 3161 may come from the verify options or be embedded
  // in the receipt (so the auditor's single file is self-contained).
  const resolvedTrustAnchor = trustAnchor ?? embeddedTrustAnchor(receipt);

  const summaries: string[] = [];
  for (const anchor of anchors) {
    const r = verifyOneAnchor(anchor, checkpointRoot, resolvedTrustAnchor);
    if (!r.ok) {
      return { name: 'anchor', ok: false, reason: r.reason };
    }
    summaries.push(r.summary);
  }
  return { name: 'anchor', ok: true, reason: summaries.join(' | ') };
}

/**
 * Read an RFC 3161 trust anchor embedded in a receipt (`rfc3161_trust_anchor`:
 * `{ public_key_pem | public_key_b64, qualified?, name? }`), so a self-contained
 * receipt can carry the operator-pinned TSA key the verifier checks an RFC 3161
 * token against. `qualified` is the operator's assertion (default false); it is
 * the SOLE thing that lets the verifier report qualified weight.
 *
 * @param receipt - The receipt (may carry an embedded trust anchor).
 * @returns The trust anchor, or undefined if none is embedded/parseable.
 */
function embeddedTrustAnchor(receipt: FullReceipt): Rfc3161TrustAnchor | undefined {
  const raw = (receipt as unknown as Record<string, unknown>)['rfc3161_trust_anchor'];
  if (raw === null || typeof raw !== 'object') return undefined;
  const obj = raw as Record<string, unknown>;
  let publicKey: string | Uint8Array | undefined;
  if (typeof obj['public_key_pem'] === 'string') {
    publicKey = obj['public_key_pem'];
  } else if (typeof obj['public_key_b64'] === 'string') {
    publicKey = new Uint8Array(Buffer.from(obj['public_key_b64'], 'base64'));
  }
  if (publicKey === undefined) return undefined;
  return {
    publicKey,
    qualified: obj['qualified'] === true,
    ...(typeof obj['name'] === 'string' ? { name: obj['name'] } : {}),
  };
}

/** Verify one anchor proof against the checkpoint root, reporting honest weight. */
function verifyOneAnchor(
  anchor: AnchorProof,
  checkpointRoot: string,
  trustAnchor?: Rfc3161TrustAnchor,
): { ok: true; summary: string } | { ok: false; reason: string } {
  if (anchor.type === 'ots') {
    if (anchor.checkpoint_root.toLowerCase() !== checkpointRoot) {
      return {
        ok: false,
        reason: 'OTS anchor checkpoint_root does not match the verified checkpoint root',
      };
    }
    const res = verifyOtsAnchor(anchor);
    if (!res.ok) {
      return { ok: false, reason: `OTS anchor failed: ${res.reason}` };
    }
    const detail = res.confirmed
      ? `OpenTimestamps confirmed (Bitcoin block ${res.block_heights.join(', ')})`
      : `OpenTimestamps calendar-pending (${res.calendars.join(', ')}), not yet block-confirmed`;
    return { ok: true, summary: timeBoundingLine('trust-minimized', detail) };
  }

  if (anchor.type === 'rfc3161') {
    if (anchor.checkpoint_root.toLowerCase() !== checkpointRoot) {
      return {
        ok: false,
        reason: 'RFC 3161 anchor checkpoint_root does not match the verified checkpoint root',
      };
    }
    if (trustAnchor === undefined) {
      return {
        ok: false,
        reason:
          'RFC 3161 anchor present but no trust anchor supplied (pass --tsa-pubkey / rfc3161TrustAnchor or embed rfc3161_trust_anchor); the verifier trusts no TSA implicitly',
      };
    }
    const res = verifyRfc3161Anchor(anchor as Rfc3161AnchorProof, { trustAnchor });
    if (!res.ok) {
      const failed = res.checks.find((c) => !c.ok);
      return { ok: false, reason: `RFC 3161 anchor failed (${failed?.name ?? 'verify'}): ${failed?.reason ?? res.reason}` };
    }
    const weight = res.weight === 'qualified' ? 'qualified (eIDAS Art. 41 presumption)' : 'timestamp (non-qualified TSA)';
    return { ok: true, summary: timeBoundingLine(weight, `RFC 3161 TSA genTime ${res.info.genTime}`) };
  }

  // Unknown anchor type — never reported as passed.
  return {
    ok: false,
    reason: `unrecognized anchor type ${JSON.stringify((anchor as { type?: unknown }).type)}; refusing to report it as passed`,
  };
}

/**
 * The honesty-boundary line the report always prints (AW-3 threat model: the
 * report must state, in its own output, what it verifies and what it does NOT —
 * integrity-since-witness only). Verbatim, this is the line a test asserts.
 */
export const HONESTY_BOUNDARY_LINE =
  'AWP verify proves integrity-since-witness only: that this record is internally consistent, ' +
  'correctly signed, and unaltered since it was witnessed. It does NOT prove completeness ' +
  '(that every action was recorded), authenticity-at-origin, or the identity of any person.';
