/**
 * @module ops/checkpoint
 *
 * The producer-side `checkpoint()` operation (AW-6): seal the current state of an
 * append-only log into a C2SP `signed-note` over a `tlog-checkpoint` body. The
 * checkpoint is the log's signed commitment "at tree size N, the Merkle root is
 * R" — the artifact external monitors cosign and AW-5 anchors (OTS / RFC 3161),
 * and the artifact an inclusion proof is verified against in a full receipt.
 *
 * This op is a thin, auditable composition over imported primitives — it adds NO
 * new crypto and NO new wire format:
 *  - the Merkle root comes from the {@link LogStore} (AW-4 RFC 9162);
 *  - the body is built by AW-4 {@link encodeCheckpoint} (C2SP `tlog-checkpoint`);
 *  - the signature is produced by AW-4 {@link signNote} via a caller-supplied
 *    {@link NoteSigner} closure (the log holds its own Ed25519 key; this OPEN
 *    package never generates or holds a production key).
 *
 * Key custody: the signer is injected. For tests and the committed sample,
 * `createTestNoteSigner` (AW-4) mints an in-process key; a real deployment passes
 * a closure backed by its KMS/HSM.
 *
 * Time semantics (AW-6 AC5): issuing a checkpoint is what BOUNDS the time of every
 * record it covers — once this checkpoint's root is anchored, those records
 * "existed no later than the checkpoint's anchor time." `checkpoint()` therefore
 * also marks the store's cadence so the bound is explicit, never a per-record
 * qualified time.
 *
 * Dependencies: `../log/store` (the log), `../log/checkpoint` (C2SP encode/sign).
 * Used by: `./proof` (a receipt references the checkpoint that covers its leaf),
 * the package root, tests, and the sample generator.
 *
 * @example
 * import { ReferenceLog } from 'agent-witness-protocol/log';
 * import { checkpoint } from 'agent-witness-protocol';
 * const { signer } = createTestNoteSigner('awp.example/log');
 * const cp = checkpoint(log, signer); // { note, rootHex, size, origin }
 */

import {
  encodeCheckpoint,
  signNote,
  type NoteSigner,
} from '../log/checkpoint.js';
import { toHex } from '../log/merkle-rfc9162.js';
import type { ReferenceLog } from '../log/store.js';

/**
 * A sealed checkpoint: the signed-note wire text plus the facts it commits, so a
 * caller (and `proof()`) can reference it without re-parsing.
 */
export interface CheckpointResult {
  /** The C2SP signed-note text (checkpoint body + blank line + signature line). */
  note: string;
  /** The committed Merkle root, lowercase 64-char hex. */
  rootHex: string;
  /** The tree size (leaf count) the checkpoint commits. */
  size: number;
  /** The log origin (C2SP checkpoint line 1). */
  origin: string;
}

/**
 * Seal the current state of `log` into a signed checkpoint note. Reads the log's
 * current size and Merkle root, encodes the C2SP `tlog-checkpoint` body, signs it
 * with `signer`, marks the store's checkpoint cadence, and returns the note plus
 * the committed facts.
 *
 * @param log - The append-only {@link ReferenceLog} to checkpoint.
 * @param signer - The log's note signer (injected key custody).
 * @param extensions - Optional opaque C2SP extension lines (e.g. a timestamp
 *   hint). Each must be non-empty and newline-free (enforced by `encodeCheckpoint`).
 * @returns The {@link CheckpointResult}.
 * @throws {RangeError} If the store/checkpoint encoding rejects an input.
 *
 * @example
 * const cp = checkpoint(log, signer);
 * // cp.note verifies with verifyNote(cp.note, { name: log.origin, publicKey });
 */
export function checkpoint(
  log: ReferenceLog,
  signer: NoteSigner,
  extensions?: string[],
): CheckpointResult {
  const size = log.size();
  const root = log.root();
  const body = encodeCheckpoint({
    origin: log.origin,
    size,
    root,
    ...(extensions !== undefined ? { extensions } : {}),
  });
  const note = signNote(body, signer);
  // Issuing the checkpoint is what bounds the covered records' time — record it.
  log.markCheckpoint();
  return { note, rootHex: toHex(root), size, origin: log.origin };
}
