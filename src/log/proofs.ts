/**
 * @module log/proofs
 *
 * RFC 9162 §2.1 Merkle audit-path (inclusion) and consistency proof VERIFICATION,
 * plus the matching proof GENERATION used to build test vectors and to let a log
 * serve receipts. All hashing is the standard RAW-BYTE RFC9162_SHA256 rule from
 * `./merkle-rfc9162` — never the separate utf8-hex variant (see docs/merkle-rules.md).
 *
 * Two independent guarantees a verifier can re-perform offline:
 *
 *  1. INCLUSION (RFC 9162 §2.1.3.1 / §2.1.3.2): given a leaf at index `i` in a
 *     tree of size `n`, an inclusion proof is the list of sibling hashes along
 *     the path from that leaf to the root. The verifier recomputes the root from
 *     `leafHash` + the path and checks it equals the published root.
 *
 *  2. CONSISTENCY (RFC 9162 §2.1.4.2): given two tree sizes `m < n`, a
 *     consistency proof lets a verifier check that the size-`n` tree is an
 *     APPEND-ONLY extension of the size-`m` tree — i.e. the first `m` leaves were
 *     never altered or removed. It recomputes BOTH the old root (size `m`) and
 *     the new root (size `n`) from the proof and checks each against the
 *     respective published root. A rewrite of any of the first `m` leaves makes
 *     the recomputed old root diverge → the proof FAILS.
 *
 * The verification math here is the raw-byte RFC 9162 algorithm. The proof JSON
 * shape borrows the familiar `{ leafIndex, leafHash, siblings[] }` layout for
 * inclusion convenience, but the hashing is RFC 9162's, not any other variant's.
 *
 * Dependencies: `./merkle-rfc9162`.
 * Used by: `./checkpoint` (a checkpoint binds the root these proofs target),
 * `./index`, downstream `awp verify` (AW-6 wires these into the receipt verifier).
 *
 * @example
 * import { verifyInclusion, buildInclusionProof, merkleTreeHash, hashLeaf } from './log/index.js';
 * const root = merkleTreeHash(leaves);
 * const proof = buildInclusionProof(leaves, 2);
 * verifyInclusion(hashLeaf(leaves[2]), proof, root); // true
 */

import {
  hashLeaf,
  hashNode,
  hashesEqual,
  largestPowerOfTwoBelow,
  merkleTreeHash,
} from './merkle-rfc9162.js';

/**
 * One step on a Merkle audit path: a sibling hash and which side it sits on
 * relative to the running hash. `position: 'left'` means the sibling is the
 * LEFT operand (`hashNode(sibling, running)`); `'right'` means it is the RIGHT
 * operand (`hashNode(running, sibling)`).
 */
export interface ProofStep {
  /** The sibling node hash at this level (32 raw bytes). */
  hash: Uint8Array;
  /** Which operand the sibling is when combined with the running hash. */
  position: 'left' | 'right';
}

/**
 * An RFC 9162 inclusion (audit-path) proof for a single leaf, in a tree of a
 * known size. The shape mirrors the common `{ leafIndex, leafHash, siblings[] }`
 * layout for ergonomics; `treeSize` is carried so the verifier needs nothing but
 * the proof and the published root.
 */
export interface InclusionProof {
  /** 0-based index of the leaf within the tree. */
  leafIndex: number;
  /** Total number of leaves in the tree the proof targets. */
  treeSize: number;
  /** The proven leaf's hash (`hashLeaf(entry)`, 32 raw bytes). */
  leafHash: Uint8Array;
  /** Sibling hashes from the leaf level up to (excluding) the root. */
  siblings: ProofStep[];
}

/**
 * Build the RFC 9162 audit path (sibling hashes) for the leaf at `index` in the
 * tree whose `entries` are the raw leaf inputs. Used to mint receipts and to
 * generate committed test vectors.
 *
 * The path is produced by the recursive subtree split (the same split MTH uses):
 * at each level the running leaf is on one side; the OTHER side's subtree hash is
 * the sibling recorded for that level.
 *
 * @param entries - The ordered raw leaf inputs (the full tree).
 * @param index - 0-based index of the leaf to prove.
 * @returns The inclusion proof for that leaf.
 * @throws {RangeError} If `index` is out of range for `entries`.
 *
 * @example
 * const proof = buildInclusionProof([enc('a'), enc('b'), enc('c')], 0);
 */
export function buildInclusionProof(entries: Uint8Array[], index: number): InclusionProof {
  const n = entries.length;
  if (!Number.isInteger(index) || index < 0 || index >= n) {
    throw new RangeError(`leaf index ${index} out of range for tree of size ${n}`);
  }
  const siblings = subtreeInclusionPath(entries, index);
  return {
    leafIndex: index,
    treeSize: n,
    leafHash: hashLeaf(entries[index]!),
    siblings,
  };
}

/**
 * Recursive helper: the audit path for leaf `index` within `entries` (a subtree
 * of size `entries.length`). The path is ordered LEAF-FIRST (closest sibling
 * first), matching {@link verifyInclusion}'s fold order.
 *
 * @param entries - The subtree's raw leaf inputs.
 * @param index - 0-based index within this subtree.
 * @returns The list of sibling steps from this subtree's leaf up to its root.
 */
function subtreeInclusionPath(entries: Uint8Array[], index: number): ProofStep[] {
  const n = entries.length;
  if (n <= 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (index < k) {
    // Leaf is in the LEFT subtree; sibling is the RIGHT subtree root.
    const inner = subtreeInclusionPath(entries.slice(0, k), index);
    const rightSibling = merkleTreeHash(entries.slice(k));
    return [...inner, { hash: rightSibling, position: 'right' }];
  }
  // Leaf is in the RIGHT subtree; sibling is the LEFT subtree root.
  const inner = subtreeInclusionPath(entries.slice(k), index - k);
  const leftSibling = merkleTreeHash(entries.slice(0, k));
  return [...inner, { hash: leftSibling, position: 'left' }];
}

/**
 * Verify an RFC 9162 inclusion proof: recompute the root by folding the leaf hash
 * with each sibling (LEAF-FIRST order) and compare against `expectedRoot`.
 *
 * @param leafHash - The proven leaf's hash (`hashLeaf(entry)`).
 * @param proof - The inclusion proof (its `siblings` drive the fold).
 * @param expectedRoot - The published Merkle root to check against.
 * @returns True iff the recomputed root equals `expectedRoot`.
 *
 * @example
 * verifyInclusion(hashLeaf(entry), proof, publishedRoot); // true / false
 */
export function verifyInclusion(
  leafHash: Uint8Array,
  proof: InclusionProof,
  expectedRoot: Uint8Array,
): boolean {
  if (!hashesEqual(leafHash, proof.leafHash)) {
    // The proof was minted for a different leaf hash than the one supplied.
    return false;
  }
  let running = leafHash;
  for (const step of proof.siblings) {
    running =
      step.position === 'left'
        ? hashNode(step.hash, running)
        : hashNode(running, step.hash);
  }
  return hashesEqual(running, expectedRoot);
}

/**
 * An RFC 9162 consistency proof between an earlier tree of size `m` and a later
 * tree of size `n` (`0 < m <= n`). `path` is the ordered list of node hashes the
 * §2.1.4.2 algorithm consumes.
 */
export interface ConsistencyProof {
  /** The earlier (smaller) tree size. */
  first: number;
  /** The later (larger) tree size (`>= first`). */
  second: number;
  /** The ordered consistency-proof node hashes (RFC 9162 §2.1.4.1). */
  path: Uint8Array[];
}

/**
 * Build the RFC 9162 §2.1.4.1 consistency proof PROOF(m, D[n]) between tree size
 * `m` and the full tree `entries` (size `n`, `0 < m <= n`). Used to mint
 * checkpoint-to-checkpoint consistency evidence and committed vectors.
 *
 * Algorithm (RFC 9162 §2.1.4.1), with `b = true` meaning "the size-m subtree is
 * a complete left edge of the current subtree" (so its root is already known to
 * the verifier and is omitted unless `m` equals the whole subtree):
 *
 *   PROOF(m, D[n]) = SUBPROOF(m, D[n], true)
 *   SUBPROOF(m, D[m], true)  = {}
 *   SUBPROOF(m, D[m], false) = { MTH(D[m]) }
 *   SUBPROOF(m, D[n], b) with m < n, k = largest 2^x < n:
 *     if m <= k: SUBPROOF(m, D[0:k], b)            ++ { MTH(D[k:n]) }
 *     if m  > k: SUBPROOF(m-k, D[k:n], false)      ++ { MTH(D[0:k]) }
 *
 * @param entries - The full (size-`n`) ordered raw leaf inputs.
 * @param m - The earlier tree size to prove consistency from (`0 < m <= n`).
 * @returns The consistency proof.
 * @throws {RangeError} If `m` is out of range.
 *
 * @example
 * const proof = buildConsistencyProof(allLeaves, 3); // from size 3 to size n
 */
export function buildConsistencyProof(entries: Uint8Array[], m: number): ConsistencyProof {
  const n = entries.length;
  if (!Number.isInteger(m) || m <= 0 || m > n) {
    throw new RangeError(`consistency 'first' size ${m} out of range for tree of size ${n}`);
  }
  return { first: m, second: n, path: subProof(m, entries, true) };
}

/**
 * RFC 9162 §2.1.4.1 SUBPROOF recursion over raw leaf inputs.
 *
 * @param m - The earlier tree size within this subtree.
 * @param entries - The current subtree's raw leaf inputs (size `n`).
 * @param b - The "complete left edge" flag (see {@link buildConsistencyProof}).
 * @returns The ordered list of node hashes for this subtree.
 */
function subProof(m: number, entries: Uint8Array[], b: boolean): Uint8Array[] {
  const n = entries.length;
  if (m === n) {
    // SUBPROOF(m, D[m], true) = {}; SUBPROOF(m, D[m], false) = { MTH(D[m]) }
    return b ? [] : [merkleTreeHash(entries)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    // Left edge fully contains the size-m subtree; append right subtree root.
    return [...subProof(m, entries.slice(0, k), b), merkleTreeHash(entries.slice(k))];
  }
  // m > k: recurse into the right subtree (now NOT a complete left edge),
  // append the (known, complete) left subtree root.
  return [...subProof(m - k, entries.slice(k), false), merkleTreeHash(entries.slice(0, k))];
}

/**
 * Verify an RFC 9162 §2.1.4.2 consistency proof: from the proof and the two
 * published roots, recompute BOTH the size-`first` root and the size-`second`
 * root and require each to match. This proves the larger tree is an APPEND-ONLY
 * extension of the smaller one — any rewrite of the first `m` leaves makes the
 * recomputed `oldRoot` diverge and the proof FAILS.
 *
 * The algorithm walks the proof maintaining two running hashes — `hash1` toward
 * the size-`m` root, `hash2` toward the size-`n` root — combining them
 * identically while the path is shared and diverging only where the new tree
 * grew on the right. It is the reference RFC 9162 §2.1.4.2 / transparency-dev
 * `VerifyConsistency` structure, restated with step comments so it is
 * auditable:
 *
 *  1. Trivial sizes: `m == n` ⇒ empty proof and equal roots; `m == 0` ⇒ empty
 *     proof (the empty tree is consistent with any tree, no nodes to check).
 *  2. Walk `node = m-1` and `last = n-1` (rightmost-leaf indices) up the tree,
 *     halving both, until `node` is even — that aligns to the highest border
 *     node fully contained in the old tree. Seed both running hashes with the
 *     first proof node there (or with `oldRoot` when `node` reached 0, i.e. `m`
 *     is a perfect power-of-two subtree whose root is already `oldRoot`).
 *  3. Climb: when `node` is a right child, prepend the next proof node to BOTH
 *     hashes; when it is a left child WITH a right sibling in the new tree
 *     (`node < last`), append the next proof node to the NEW hash only.
 *  4. Drain remaining proof nodes into the NEW hash (the new tree's right edge).
 *  5. Accept iff `hash1 == oldRoot`, `hash2 == newRoot`, and every proof node
 *     was consumed (no trailing junk).
 *
 * @param proof - The consistency proof (`first`, `second`, `path`).
 * @param oldRoot - The published root at size `proof.first`.
 * @param newRoot - The published root at size `proof.second`.
 * @returns True iff both roots are reproduced from the proof (append-only holds).
 *
 * @example
 * verifyConsistency(proof, rootAtM, rootAtN); // true if append-only
 */
export function verifyConsistency(
  proof: ConsistencyProof,
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
): boolean {
  const { first: size1, second: size2, path } = proof;
  if (size1 < 0 || size2 < size1) return false;

  // (1) Trivial sizes.
  if (size1 === size2) return path.length === 0 && hashesEqual(oldRoot, newRoot);
  if (size1 === 0) return path.length === 0; // empty old tree: nothing to prove
  if (path.length === 0) return false; // size1 < size2 needs at least one node

  // (2) Align to the highest fully-contained border node of the old tree.
  let node = size1 - 1;
  let last = size2 - 1;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    last = Math.floor(last / 2);
  }

  let p = 0;
  let hash1: Uint8Array;
  let hash2: Uint8Array;
  if (node > 0) {
    hash1 = path[0]!;
    hash2 = path[0]!;
    p = 1;
  } else {
    // m is a perfect power-of-two subtree: its root IS oldRoot.
    hash1 = oldRoot;
    hash2 = oldRoot;
  }

  // (3) Climb the shared path.
  while (node > 0) {
    if (p >= path.length) return false;
    if (node % 2 === 1) {
      // Right child: prepend the sibling to BOTH running hashes.
      hash1 = hashNode(path[p]!, hash1);
      hash2 = hashNode(path[p]!, hash2);
      p += 1;
    } else if (node < last) {
      // Left child with a right sibling in the NEW tree only.
      hash2 = hashNode(hash2, path[p]!);
      p += 1;
    }
    node = Math.floor(node / 2);
    last = Math.floor(last / 2);
  }

  // (4) Drain the new tree's remaining right edge into the NEW hash.
  while (last > 0) {
    if (p >= path.length) return false;
    hash2 = hashNode(hash2, path[p]!);
    p += 1;
    last = Math.floor(last / 2);
  }

  // (5) Both roots reproduced and every proof node consumed.
  return hashesEqual(hash1, oldRoot) && hashesEqual(hash2, newRoot) && p === path.length;
}
