/**
 * @module ops/proof
 *
 * The producer-side `proof(id)` operation (AW-6): assemble a SELF-CONTAINED
 * Receipt bundle for one witnessed record — everything an auditor needs to verify
 * the full chain offline, in one JSON file:
 *
 *   signed DSSE envelope (AW-2)               "this is the witnessed record, signed"
 *     → RFC 9162 inclusion proof (AW-4)       "the record's leaf is in the tree…"
 *       → C2SP signed checkpoint (AW-4)       "…whose root this log signed at size N"
 *         → external anchor proof(s) (AW-5)   "…and that root existed at time T"
 *
 * The binding that makes the bundle airtight, and that `verify` re-checks:
 *  - the inclusion proof's leaf hash is `hashLeaf(canonical Statement bytes)` —
 *    the SAME Statement bytes the DSSE envelope signs (one object, two domain
 *    separations). No hidden canonicalization: an auditor recomputes the leaf
 *    from the decoded record via `statementPayloadBytes(buildStatement(record))`.
 *  - the inclusion proof recomputes to the checkpoint's root;
 *  - each anchor commits that same checkpoint root.
 *
 * `proof(id)` here takes an explicit `(store, signer, key material)` because the
 * OPEN package owns no key and no global log — it operates on the reference
 * {@link LogStore} a caller (test/sample) supplies. paybot-core's AW-7 store wires
 * its own persistence behind the same interface; `id` is the leaf index in the
 * supplied store. The op does NO network and NO external filesystem I/O.
 *
 * Wire shapes ({@link WireInclusionProof}, {@link WireCheckpoint}) serialize the
 * AW-4 in-memory proof/checkpoint as JSON-friendly hex/base64 + text so the whole
 * receipt is one portable file; `verify` parses them back with the same
 * primitives. They are ADDITIVE to the AW-3 {@link Receipt} (envelope + anchors);
 * an AW-3 receipt without them still verifies (the inclusion/checkpoint checks
 * report "not present" rather than failing).
 *
 * Dependencies: `../log/store`, `../log/proofs`, `../log/checkpoint`,
 *   `../envelope` (statement bytes), `../anchor` (anchor proof types),
 *   `./checkpoint`.
 * Used by: tests, the sample generator, and downstream producers.
 *
 * @example
 * const cp = checkpoint(log, signer);          // seal the tree
 * const receipt = proof(leafIndex, {
 *   store: log, record, envelope, signerPublicKey, checkpoint: cp, anchors,
 * });
 * verify(receipt, { publicKey }).ok;           // true, full chain
 */

import { createHash } from 'node:crypto';
import { encodePayload } from '../envelope/index.js';
import { hashNode, toHex } from '../log/merkle-rfc9162.js';
import type { InclusionProof, ProofStep } from '../log/proofs.js';
import type { ReferenceLog } from '../log/store.js';
import type { AnchorProof, Receipt } from '../anchor/index.js';
import type { WitnessRecord } from '../schema/index.js';
import type { CheckpointResult } from './checkpoint.js';

/** One inclusion-proof step in JSON form: a hex sibling hash + its side. */
export interface WireProofStep {
  /** The sibling node hash, lowercase 64-char hex (32 bytes). */
  hash: string;
  /** Which operand the sibling is when folded with the running hash. */
  position: 'left' | 'right';
}

/**
 * An RFC 9162 inclusion proof in JSON-portable form: hashes as lowercase hex so
 * the whole receipt is one text file. `verify` rebuilds the in-memory
 * {@link InclusionProof} from this and folds it to a root.
 */
export interface WireInclusionProof {
  /** 0-based index of the leaf within the tree. */
  leafIndex: number;
  /** Total number of leaves in the tree the proof targets. */
  treeSize: number;
  /** The proven leaf's hash (`hashLeaf(statement bytes)`), lowercase hex. */
  leafHash: string;
  /** Sibling hashes from the leaf level up to (excluding) the root. */
  siblings: WireProofStep[];
}

/**
 * A checkpoint in JSON-portable form: the signed-note text plus the log public
 * key the verifier checks the note's signature against, and the origin/key name.
 * The public key is carried so the receipt is self-contained (the auditor needs
 * no out-of-band key); a deployment that distributes its log key separately may
 * omit it and supply it to `verify` another way.
 */
export interface WireCheckpoint {
  /** The C2SP signed-note text (body + blank line + signature line(s)). */
  note: string;
  /** The log's signed-note key name (equals the checkpoint origin for AWP). */
  keyName: string;
  /** The log's 32-byte Ed25519 public key, base64, for note-signature verify. */
  publicKeyB64: string;
}

/**
 * A FULL receipt bundle: the AW-3 {@link Receipt} (signed envelope + anchors)
 * EXTENDED with the AW-4 inclusion proof and signed checkpoint that tie the
 * record's leaf to the anchored root. Additive — every AW-3 receipt is a valid
 * (anchor-only) {@link FullReceipt} with `inclusion`/`checkpoint` absent.
 */
export interface FullReceipt extends Receipt {
  /** The RFC 9162 inclusion proof binding the record's leaf to the tree root. */
  inclusion?: WireInclusionProof;
  /** The signed C2SP checkpoint the inclusion proof's root must match. */
  checkpoint?: WireCheckpoint;
}

/** Inputs to {@link proof}: the store, the record + its signed envelope, and the
 * sealed checkpoint and anchors that cover the record's leaf. */
export interface ProofInputs {
  /** The append-only log the record's leaf lives in. */
  store: ReferenceLog;
  /** The witnessed record (its Statement bytes are the committed leaf). */
  record: WitnessRecord;
  /** The signed DSSE envelope over `record` (AW-2 `signEnvelope` output). */
  envelope: unknown;
  /** The log's 32-byte Ed25519 public key (for the receipt's checkpoint block). */
  signerPublicKey: Uint8Array;
  /** The sealed checkpoint (`checkpoint(store, signer)`) covering the leaf. */
  checkpoint: CheckpointResult;
  /** Optional external anchor proof(s) over the checkpoint root (AW-5). */
  anchors?: AnchorProof[];
  /**
   * Optionally also include the legacy AW-3 `record_commitment`
   * (`sha256(statement bytes)`) for backward compatibility with the AW-3 anchor
   * check. Off by default — the inclusion proof supersedes it.
   */
  includeLegacyCommitment?: boolean;
}

/** Serialize an in-memory {@link ProofStep} to its hex wire form. */
function wireStep(step: ProofStep): WireProofStep {
  return { hash: toHex(step.hash), position: step.position };
}

/**
 * Serialize an in-memory {@link InclusionProof} to its JSON-portable form.
 *
 * @param proof - The AW-4 inclusion proof.
 * @returns The hex-encoded {@link WireInclusionProof}.
 */
export function toWireInclusion(proof: InclusionProof): WireInclusionProof {
  return {
    leafIndex: proof.leafIndex,
    treeSize: proof.treeSize,
    leafHash: toHex(proof.leafHash),
    siblings: proof.siblings.map(wireStep),
  };
}

/**
 * Assemble a full, self-contained {@link FullReceipt} for the leaf at `id` in the
 * supplied store. Builds the RFC 9162 inclusion proof for that leaf, attaches the
 * sealed checkpoint and any anchors, and binds the leaf to the record's Statement
 * bytes (the same bytes the envelope signs). The result verifies end-to-end with
 * `verify` offline.
 *
 * Consistency the op guarantees (so the receipt is internally coherent before it
 * ever reaches a verifier):
 *  - the leaf at `id` equals `statementPayloadBytes(buildStatement(record))`;
 *  - the inclusion proof's tree size and the checkpoint size agree;
 *  - the inclusion proof's recomputed root equals the checkpoint root.
 *
 * @param id - The 0-based leaf index in `inputs.store`.
 * @param inputs - The record, its envelope, the sealed checkpoint, and anchors.
 * @returns A {@link FullReceipt} ready for `verify`.
 * @throws {Error} If the leaf at `id` does not match the record's Statement bytes,
 *   or the inclusion proof's root does not match the checkpoint root (a bundle
 *   that could never verify — fail at production time, not at the auditor's desk).
 * @throws {RangeError} If `id` is out of range for the store.
 *
 * @example
 * const receipt = proof(0, { store, record, envelope, signerPublicKey, checkpoint });
 */
export function proof(id: number, inputs: ProofInputs): FullReceipt {
  const { store, record, envelope, signerPublicKey, checkpoint: cp, anchors } = inputs;

  // The leaf this proof targets MUST be the record's canonical Statement bytes,
  // i.e. the EXACT payload the DSSE envelope signs. We derive those bytes via
  // encodePayload (which VALIDATES the record first, applying schema defaults like
  // artifact.pii_bearing) so the committed leaf matches the signed payload — the
  // verifier recomputes the same bytes from the record it decodes out of the
  // envelope. Building from the raw, unvalidated record would omit those defaults
  // and yield a leaf that fails the inclusion check at the auditor's desk.
  const encoded = encodePayload(record);
  if (!encoded.ok) {
    throw new Error(`record does not validate, cannot build a leaf: ${encoded.errors.join('; ')}`);
  }
  const statementBytes = encoded.payload;
  const storedLeaf = store.leaf(id);
  if (!bytesEqual(storedLeaf, statementBytes)) {
    throw new Error(
      `leaf ${id} does not equal the record's canonical (validated) Statement bytes; ` +
        'the committed leaf and the signed payload must be the same object — append ' +
        'encodePayload(record).payload (or the envelope payload bytes) as the leaf',
    );
  }

  const inclusion = store.inclusionProof(id);

  // Cross-layer coherence: the proof's root must equal the checkpoint root, and
  // the sizes must agree. (verify re-checks these; we also refuse to emit an
  // incoherent bundle.)
  const proofRootHex = foldRootHex(inclusion);
  if (proofRootHex !== cp.rootHex) {
    throw new Error(
      `inclusion proof root (${proofRootHex.slice(0, 12)}…) does not match checkpoint root ` +
        `(${cp.rootHex.slice(0, 12)}…); proof and checkpoint disagree`,
    );
  }
  if (inclusion.treeSize !== cp.size) {
    throw new Error(
      `inclusion proof tree size ${inclusion.treeSize} does not match checkpoint size ${cp.size}`,
    );
  }

  const receipt: FullReceipt = {
    envelope,
    checkpoint_root: cp.rootHex,
    inclusion: toWireInclusion(inclusion),
    checkpoint: {
      note: cp.note,
      keyName: cp.origin,
      publicKeyB64: Buffer.from(signerPublicKey).toString('base64'),
    },
  };
  if (anchors !== undefined && anchors.length > 0) {
    receipt.anchors = anchors;
  }
  if (inputs.includeLegacyCommitment === true) {
    receipt.record_commitment = sha256Hex(statementBytes);
  }
  return receipt;
}

/**
 * Recompute the Merkle root a wire inclusion proof folds to, as lowercase hex —
 * the same fold `verify` performs, exposed so the producer can self-check that
 * the bundle is coherent before emitting it.
 *
 * @param inclusion - The in-memory inclusion proof.
 * @returns The recomputed root, lowercase hex.
 */
function foldRootHex(inclusion: InclusionProof): string {
  let running = inclusion.leafHash;
  for (const step of inclusion.siblings) {
    running =
      step.position === 'left' ? hashNode(step.hash, running) : hashNode(running, step.hash);
  }
  return toHex(running);
}

/** Length-checked byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** SHA-256 of bytes, hex (for the optional legacy commitment). */
function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}
