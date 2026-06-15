/**
 * @module anchor/types
 *
 * The external-anchor proof types AWP verifies, and the `Receipt` shape that
 * carries a signed envelope together with its anchor proof(s).
 *
 * An anchor is an INDEPENDENT, external attestation that a checkpoint root
 * existed at a point in time — produced outside the audited entity's control
 * (AWP spec §3 "Anchors"; auditor-enablement §2 item 1: source independence is
 * ISA 500 A31(a)'s highest evidence tier). AWP anchors PER CHECKPOINT, never
 * per record (spec §2; cost scales with checkpoint cadence) — so an anchor
 * proof carries the checkpoint root it commits to, and the verifier confirms
 * the record's envelope is bound to that root.
 *
 * Honest evidentiary weight (auditor-enablement §3 Part C, the claim-class
 * boundary applied to TIME): the verifier reports WHICH anchor backs the time
 * and its weight. It must NEVER claim qualified/eIDAS legal weight from an
 * OpenTimestamps-only proof:
 *  - `ots` (OpenTimestamps) → "trust-minimized (Bitcoin calendars)". Free, no
 *    contract, no trusted party. The buildable-NOW anchor.
 *  - `rfc3161` (qualified eIDAS TSA) → "qualified (eIDAS Art. 41 presumption)".
 *    A LATER, operator + vendor decision. Reserved here so a qualified token
 *    drops into the same verifier with no rework; not produced by this package.
 *
 * Scope note: this story (AW-3) ships the OTS read/verify PATH so the auditor
 * walkthrough can confirm an externally-anchored time when an `.ots` proof is
 * present. The Merkle log and checkpoint signing themselves are later stories;
 * here the anchor commits directly to a checkpoint root the receipt supplies,
 * and the binding the verifier enforces is "this root commits to this record".
 *
 * Dependencies: none (pure types).
 * Used by: `./opentimestamps`, `../verify/checks`, `../verify/verify`.
 */

/** The evidentiary weight a verifier may HONESTLY attribute to an anchor. */
export const ANCHOR_WEIGHTS = ['trust-minimized', 'qualified'] as const;
/** One of {@link ANCHOR_WEIGHTS}. */
export type AnchorWeight = (typeof ANCHOR_WEIGHTS)[number];

/** The anchor proof kinds AWP recognizes. `chain` is reserved, not built here. */
export const ANCHOR_TYPES = ['ots', 'rfc3161', 'chain'] as const;
/** One of {@link ANCHOR_TYPES}. */
export type AnchorType = (typeof ANCHOR_TYPES)[number];

/**
 * An OpenTimestamps anchor proof (the buildable-NOW, free, trust-minimized
 * variant). Carries the committed checkpoint root and a base64 of the `.ots`
 * proof bytes. The `pending` flag is reported honestly: a fresh OTS proof is
 * aggregated by calendar servers but not yet committed to a Bitcoin block, so
 * its time is "submitted, awaiting block confirmation" rather than confirmed.
 */
export interface OtsAnchorProof {
  /** Discriminant. */
  type: 'ots';
  /**
   * The checkpoint root this proof commits to, lowercase 64-char hex SHA-256.
   * This is the digest the OTS calendar timestamped.
   */
  checkpoint_root: string;
  /** Base64 of the raw `.ots` proof bytes. */
  ots_proof_b64: string;
  /**
   * Whether the proof is still pending Bitcoin confirmation (calendar-attested
   * but not yet block-committed). Reported honestly by the verifier.
   */
  pending?: boolean;
}

/**
 * An RFC 3161 timestamp anchor proof. Carries the checkpoint root the TSA
 * token's message imprint must match and the base64 DER `TimeStampToken`. The
 * SAME shape carries a free, non-qualified TSA token (freetsa.org, DigiCert) and
 * a qualified eIDAS TSA token — the difference is the trust anchor it is verified
 * against (config, not code: see AW-5 `rfc3161.ts`). The verifier reports
 * `qualified` weight ONLY when the supplied trust anchor is declared qualified;
 * a token verified against a non-qualified anchor is reported as a plain
 * timestamp, never as carrying the eIDAS Art. 41 presumption.
 */
export interface Rfc3161AnchorProof {
  /** Discriminant. */
  type: 'rfc3161';
  /** The checkpoint root the TSA token's message imprint should match. */
  checkpoint_root: string;
  /** Base64 of the DER RFC 3161 TimeStampToken. */
  tst_der_b64: string;
}

/**
 * The open anchor-proof union. Left open for the reserved `chain` (on-chain)
 * variant (auditor research; optional, operator-gated) without committing to it
 * here.
 */
export type AnchorProof = OtsAnchorProof | Rfc3161AnchorProof;

/**
 * A receipt: a signed DSSE envelope plus zero or more external anchor proofs,
 * and the checkpoint root the record is bound into.
 *
 * In a full pipeline (AW-4/AW-6) the binding is "record → Merkle inclusion →
 * checkpoint root → anchor". At Phase 1 the receipt supplies `checkpoint_root`
 * and a `record_commitment` digest the verifier recomputes from the envelope,
 * so the chain "this record is the one committed by this anchored root" is
 * checkable offline today. `anchors` is optional: a bare signed envelope (no
 * anchors) verifies for signature + record + honesty, and the anchor check is
 * reported as "not present" rather than silently skipped.
 */
export interface Receipt {
  /** The DSSE v1.0 envelope (AW-2 wire shape). Typed loosely; the verifier validates it. */
  envelope: unknown;
  /**
   * Optional checkpoint root (lowercase 64-char hex SHA-256) the record is
   * committed into and the anchors attest. Required iff `anchors` is non-empty.
   */
  checkpoint_root?: string;
  /**
   * Optional commitment proving THIS envelope is the one under
   * `checkpoint_root`. At Phase 1 this is `sha256(canonical statement bytes)`;
   * the full Merkle inclusion proof replaces it in AW-6.
   */
  record_commitment?: string;
  /** Optional external anchor proofs over `checkpoint_root`. */
  anchors?: AnchorProof[];
}
