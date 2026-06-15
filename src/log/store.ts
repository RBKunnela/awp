/**
 * @module log/store
 *
 * A REFERENCE, in-package append-only log (AW-6) so the OPEN package can produce
 * its own receipts for tests and the committed sample — and so the auditor
 * walkthrough is self-demonstrating without a private store. paybot-core supplies
 * the REAL store in AW-7; the open ops (`ops/proof`, `ops/checkpoint`) depend on
 * the {@link LogStore} INTERFACE, never on this concrete class, so a production
 * store drops in by implementing the same methods.
 *
 * What it is, precisely:
 *  - An ordered list of leaves. Each leaf is the canonical in-toto Statement
 *    bytes of a witnessed record (the EXACT bytes DSSE signs — see `ops/proof`),
 *    so the leaf the log commits and the payload the envelope signs are the same
 *    object under two domain separations (`hashLeaf` 0x00 vs DSSE PAE). No hidden
 *    canonicalization: an auditor recomputes a leaf from the decoded record by
 *    `statementPayloadBytes(buildStatement(record))`.
 *  - APPEND-ONLY: {@link ReferenceLog.append} only pushes; there is no update or
 *    delete. The Merkle root and every inclusion proof are derived from the leaf
 *    list via the AW-4 RFC 9162 primitives (imported, never re-implemented).
 *  - CHECKPOINT CADENCE: {@link ReferenceLog.shouldCheckpoint} encodes a simple,
 *    inspectable cadence (every N appends, or when forced) so a record's time is
 *    BOUNDED by the next checkpoint's anchor — never a per-record qualified time
 *    (AW-6 AC5; auditor play §2 item 7). The cadence is a property of the store,
 *    not of any record.
 *
 * This module performs NO network and NO external filesystem I/O — it is a pure
 * in-memory structure. Persisting it (POSIX files, a DB) is the production
 * store's concern; the interface is deliberately tiny so either backs it.
 *
 * Dependencies: `./merkle-rfc9162` (root + leaf hashing), `./proofs` (inclusion).
 * Used by: `../ops/checkpoint`, `../ops/proof`, the package root, tests.
 *
 * @example
 * import { ReferenceLog } from 'agent-witness-protocol/log';
 * const log = new ReferenceLog('awp.example/log');
 * const i = log.append(statementBytes);   // 0-based leaf index
 * const proof = log.inclusionProof(i);     // RFC 9162 audit path
 * const root = log.root();                 // 32-byte Merkle root
 */

import {
  emptyTreeHash,
  hashLeaf,
  merkleTreeHash,
  toHex,
} from './merkle-rfc9162.js';
import { buildInclusionProof, type InclusionProof } from './proofs.js';

/**
 * The minimal append-only-log contract the OPEN producer ops depend on. A real
 * store (AW-7) implements this; the in-package {@link ReferenceLog} implements it
 * for tests and the sample. Indices are 0-based and stable (append-only).
 */
export interface LogStore {
  /** The log's unique origin identity string (C2SP checkpoint line 1). */
  readonly origin: string;
  /** The number of leaves currently in the log (its tree size). */
  size(): number;
  /**
   * Append one leaf (the canonical Statement bytes of a record) and return its
   * 0-based index. Append-only: never updates or removes an existing leaf.
   */
  append(leaf: Uint8Array): number;
  /** The leaf bytes at `index` (the bytes that were appended). */
  leaf(index: number): Uint8Array;
  /** The current Merkle root (32 raw bytes), per RFC 9162 over all leaves. */
  root(): Uint8Array;
  /** The current Merkle root as lowercase 64-char hex. */
  rootHex(): string;
  /** An RFC 9162 inclusion (audit-path) proof for the leaf at `index`. */
  inclusionProof(index: number): InclusionProof;
}

/**
 * Options controlling the reference log's checkpoint cadence. The cadence bounds
 * a record's time (a record is anchored only once a checkpoint covering it is
 * issued and anchored), so it is the store's policy, never a per-record claim.
 */
export interface ReferenceLogOptions {
  /**
   * Issue a checkpoint at least every `checkpointEvery` appends. Default 8. A
   * larger value batches more records under one anchor (cheaper, coarser time);
   * a smaller value tightens the time bound (more anchors). Must be a positive
   * integer.
   */
  checkpointEvery?: number;
}

/** The default checkpoint cadence (appends per checkpoint). */
export const DEFAULT_CHECKPOINT_EVERY = 8;

/**
 * An in-memory, append-only RFC 9162 log — the reference {@link LogStore}. Holds
 * the ordered leaf bytes; derives roots and inclusion proofs from them with the
 * AW-4 primitives. Self-contained and deterministic: the same appends in the same
 * order always yield the same roots and proofs, so a committed sample is
 * reproducible.
 *
 * @example
 * const log = new ReferenceLog('awp.example/log', { checkpointEvery: 4 });
 * log.append(a); log.append(b);
 * if (log.shouldCheckpoint()) issueCheckpoint(log);
 */
export class ReferenceLog implements LogStore {
  /** The ordered leaf inputs (raw Statement bytes). Append-only. */
  private readonly leaves: Uint8Array[] = [];
  /** Tree size at the last issued checkpoint, to drive the cadence. */
  private lastCheckpointSize = 0;
  /** Appends per checkpoint (cadence). */
  private readonly checkpointEvery: number;

  /**
   * @param origin - The log's unique identity string (C2SP checkpoint line 1).
   * @param options - Optional checkpoint cadence.
   * @throws {RangeError} If `origin` is empty/multiline or the cadence is invalid.
   */
  constructor(
    public readonly origin: string,
    options: ReferenceLogOptions = {},
  ) {
    if (origin.length === 0 || origin.includes('\n')) {
      throw new RangeError('log origin must be a non-empty single line');
    }
    const every = options.checkpointEvery ?? DEFAULT_CHECKPOINT_EVERY;
    if (!Number.isInteger(every) || every < 1) {
      throw new RangeError(`checkpointEvery must be a positive integer (got ${every})`);
    }
    this.checkpointEvery = every;
  }

  /** {@inheritDoc LogStore.size} */
  size(): number {
    return this.leaves.length;
  }

  /**
   * {@inheritDoc LogStore.append}
   *
   * @param leaf - The canonical Statement bytes to append as a leaf.
   * @returns The new leaf's 0-based index.
   * @throws {TypeError} If `leaf` is empty (a zero-byte leaf is almost always a bug).
   */
  append(leaf: Uint8Array): number {
    if (leaf.length === 0) {
      throw new TypeError('refusing to append a zero-length leaf');
    }
    // Defensive copy so a later mutation of the caller's buffer cannot rewrite
    // an already-committed leaf (append-only must hold against aliasing too).
    this.leaves.push(Uint8Array.from(leaf));
    return this.leaves.length - 1;
  }

  /**
   * {@inheritDoc LogStore.leaf}
   *
   * @param index - The 0-based leaf index.
   * @returns A copy of the leaf bytes.
   * @throws {RangeError} If `index` is out of range.
   */
  leaf(index: number): Uint8Array {
    const l = this.leaves[index];
    if (l === undefined) {
      throw new RangeError(`leaf index ${index} out of range for log of size ${this.leaves.length}`);
    }
    return Uint8Array.from(l);
  }

  /**
   * {@inheritDoc LogStore.root}
   *
   * @returns The 32-byte Merkle root (the empty-tree hash when no leaves).
   */
  root(): Uint8Array {
    return this.leaves.length === 0 ? emptyTreeHash() : merkleTreeHash(this.leaves);
  }

  /** {@inheritDoc LogStore.rootHex} */
  rootHex(): string {
    return toHex(this.root());
  }

  /**
   * {@inheritDoc LogStore.inclusionProof}
   *
   * @param index - The 0-based leaf index to prove.
   * @returns The RFC 9162 inclusion proof (its `leafHash` is `hashLeaf(leaf)`).
   * @throws {RangeError} If `index` is out of range.
   */
  inclusionProof(index: number): InclusionProof {
    if (index < 0 || index >= this.leaves.length) {
      throw new RangeError(`leaf index ${index} out of range for log of size ${this.leaves.length}`);
    }
    return buildInclusionProof(this.leaves, index);
  }

  /**
   * The leaf hash for the leaf at `index` (`hashLeaf(leaf)`), exposed for callers
   * that want to bind a receipt to the exact committed leaf without rebuilding it.
   *
   * @param index - The 0-based leaf index.
   * @returns The 32-byte leaf hash.
   */
  leafHash(index: number): Uint8Array {
    return hashLeaf(this.leaf(index));
  }

  /**
   * Whether the cadence says a new checkpoint is due: at least `checkpointEvery`
   * appends have landed since the last checkpoint (and there is at least one new
   * leaf). A producer calls this after appends to decide whether to checkpoint;
   * the open `checkpoint()` op also forces one regardless.
   *
   * @returns True iff a checkpoint is due by the cadence.
   */
  shouldCheckpoint(): boolean {
    const pending = this.leaves.length - this.lastCheckpointSize;
    return pending > 0 && pending >= this.checkpointEvery;
  }

  /**
   * Record that a checkpoint was issued at the current size (resets the cadence
   * counter). Called by `checkpoint()` after it signs a note over {@link root}.
   *
   * @returns The tree size at which the checkpoint was marked.
   */
  markCheckpoint(): number {
    this.lastCheckpointSize = this.leaves.length;
    return this.lastCheckpointSize;
  }

  /** The tree size at the most recently marked checkpoint. */
  checkpointSize(): number {
    return this.lastCheckpointSize;
  }
}

/**
 * Re-export the hash size so downstream code can import it from the store module
 * without reaching into `merkle-rfc9162`. A raw hash is always this many bytes.
 */
export { HASH_SIZE } from './merkle-rfc9162.js';
