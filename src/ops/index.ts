/**
 * @module ops
 *
 * Barrel for the AWP producer-side operations (AW-6): `checkpoint()` (seal an
 * append-only log into a signed C2SP checkpoint) and `proof(id)` (assemble a
 * self-contained Receipt bundle = signed envelope + RFC 9162 inclusion proof +
 * checkpoint + anchor proofs). These compose the AW-2 envelope, AW-4 log, and
 * AW-5 anchor layers; they add no new crypto or wire format of their own.
 *
 * The ops operate on the reference {@link ReferenceLog} (a {@link LogStore}); a
 * production store (paybot-core AW-7) implements the same interface. They perform
 * NO network and NO external filesystem I/O.
 *
 * Dependencies: `./checkpoint`, `./proof`.
 * Used by: the package root `src/index.ts`, tests, and the sample generator.
 *
 * @example
 * import { checkpoint, proof } from 'agent-witness-protocol';
 */

export { checkpoint } from './checkpoint.js';
export type { CheckpointResult } from './checkpoint.js';

export { proof, toWireInclusion } from './proof.js';
export type {
  FullReceipt,
  ProofInputs,
  WireInclusionProof,
  WireCheckpoint,
  WireProofStep,
} from './proof.js';
