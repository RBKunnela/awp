/**
 * @module log
 *
 * Barrel for the AWP transparency-log layer (AW-4): a standard RFC 9162
 * (`RFC9162_SHA256`) append-only Merkle log over RAW BYTES, with inclusion and
 * consistency proof verification, and C2SP `tlog-checkpoint` + `signed-note`
 * encode / parse / verify.
 *
 * ⚠️ The Merkle hashing here is the STANDARD raw-byte rule (children decoded to
 * 32 bytes before hashing) so independent RFC 9162 verifiers interoperate. A
 * separate, pinned utf8-hex-text variant used elsewhere in the wider system for
 * batch corroboration is intentionally NOT on any path here; the two rules
 * produce different roots for the same leaves, which is documented in
 * `docs/merkle-rules.md` and pinned by `test/log/merkle-rule-divergence.test.ts`.
 * `hashNodeUtf8Hex` is exported ONLY to drive that divergence test — never call
 * it on a verification path.
 *
 * Dependencies: `./merkle-rfc9162`, `./proofs`, `./checkpoint`.
 * Used by: the package root `src/index.ts`; AW-6 wires these into `awp verify`.
 *
 * @example
 * import {
 *   merkleTreeHash, buildInclusionProof, verifyInclusion,
 *   buildConsistencyProof, verifyConsistency,
 *   encodeCheckpoint, signNote, verifyNote, parseCheckpoint,
 *   createTestNoteSigner,
 * } from 'agent-witness-protocol/log';
 */

export {
  LEAF_PREFIX,
  NODE_PREFIX,
  HASH_SIZE,
  emptyTreeHash,
  hashLeaf,
  hashNode,
  hashNodeUtf8Hex,
  largestPowerOfTwoBelow,
  merkleTreeHash,
  toHex,
  fromHex,
  hashesEqual,
} from './merkle-rfc9162.js';

export {
  buildInclusionProof,
  verifyInclusion,
  buildConsistencyProof,
  verifyConsistency,
} from './proofs.js';

export type {
  ProofStep,
  InclusionProof,
  ConsistencyProof,
} from './proofs.js';

export {
  encodeCheckpoint,
  parseCheckpoint,
  keyId,
  signNote,
  addSignature,
  splitNote,
  verifyNote,
  createTestNoteSigner,
} from './checkpoint.js';

export type {
  Checkpoint,
  ParseCheckpointResult,
  NoteSignFn,
  NoteSigner,
  NoteSignature,
  SplitNoteResult,
  NoteVerifier,
  NoteCheck,
  VerifyNoteResult,
} from './checkpoint.js';

export {
  ReferenceLog,
  DEFAULT_CHECKPOINT_EVERY,
} from './store.js';

export type {
  LogStore,
  ReferenceLogOptions,
} from './store.js';
