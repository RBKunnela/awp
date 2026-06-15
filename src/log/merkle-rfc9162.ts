/**
 * @module log/merkle-rfc9162
 *
 * RFC 9162 (Certificate Transparency v2) §2 Merkle tree — the `RFC9162_SHA256`
 * profile — implemented over **RAW BYTES**. This is the hashing core of the OPEN
 * Agent Witness Protocol (AWP) transparency log (AW-4): the leaf/node domain-
 * separated hash rule and the Merkle Tree Hash (MTH) over a sequence of entries.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE RULE, stated so an auditor can re-implement it from this docstring alone
 * (RFC 9162 §2.1, "Merkle Hash Trees"):
 *
 *   - Hash function: SHA-256.
 *   - Leaf hash:   HASH( 0x00 || entry_bytes )        (RFC 9162 / RFC 6962 §2.1)
 *   - Node hash:   HASH( 0x01 || left || right )
 *                  where `left` and `right` are the **32 RAW BYTES** of the two
 *                  child hashes — NOT their hex text. This is the whole point of
 *                  the RFC9162_SHA256 profile: children are the raw digest bytes.
 *   - Empty tree:  MTH({}) = HASH() of the empty string (SHA-256 of zero bytes).
 *
 * The Merkle Tree Hash over a list D[n] = d[0..n-1] is defined recursively
 * (RFC 9162 §2.1.1):
 *
 *   MTH({})        = SHA-256()                              // empty input
 *   MTH({d0})      = HASH(0x00 || d0)                       // single leaf
 *   MTH(D[n])      = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
 *                    where k is the largest power of two strictly less than n
 *                    (k < n <= 2k). The tree is therefore left-full: the left
 *                    subtree is always a complete (power-of-two) subtree.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ⚠️  INTEROP LANDMINE — READ docs/merkle-rules.md.
 *
 * A DIFFERENT, pinned, NON-STANDARD Merkle variant exists elsewhere in the wider
 * system: it concatenates the two child hashes as **lowercase utf8-hex TEXT**
 * (128 hex characters) under the same 0x01 prefix, and never decodes them to raw
 * bytes. That variant is held SEPARATE for its own batch-corroboration purpose
 * and is intentionally NOT reachable from this module. The two rules produce
 * DIFFERENT roots for the same leaves — see {@link hashNodeUtf8Hex} (provided
 * ONLY for the documented divergence test, never on the verification path) and
 * the boundary test in `test/log/merkle-rule-divergence.test.ts`.
 *
 * The OPEN log MUST use the standard RAW-BYTE rule here so that any independent
 * RFC 9162 verifier (Go sumdb, Sigsum, Rekor v2, a hand-rolled auditor script)
 * interoperates with no hidden canonicalization.
 *
 * Dependencies: Node `crypto` (stdlib SHA-256; no third-party hashing dependency,
 * keeping the verify path dependency-light per the AW-3 offline requirement).
 * Used by: `./proofs` (inclusion + consistency verification), `./checkpoint`
 * (root computation for a checkpoint), the package root.
 *
 * @example
 * import { merkleTreeHash, hashLeaf } from './merkle-rfc9162.js';
 * const leaves = [new TextEncoder().encode('a'), new TextEncoder().encode('b')];
 * const root = merkleTreeHash(leaves); // 32-byte Uint8Array root hash
 */

import { createHash } from 'node:crypto';

/** Domain-separation prefix for a leaf hash (RFC 9162 / RFC 6962 §2.1). */
export const LEAF_PREFIX = 0x00;
/** Domain-separation prefix for an interior node hash (RFC 9162 / RFC 6962 §2.1). */
export const NODE_PREFIX = 0x01;
/** SHA-256 digest length in bytes — the size of every node hash in this profile. */
export const HASH_SIZE = 32;

/**
 * Raw SHA-256 over the concatenation of the given byte chunks.
 *
 * @param chunks - Byte chunks to feed to the digest, in order.
 * @returns The 32-byte SHA-256 digest as a `Uint8Array`.
 */
function sha256(...chunks: Uint8Array[]): Uint8Array {
  const h = createHash('sha256');
  for (const c of chunks) h.update(c);
  return new Uint8Array(h.digest());
}

/**
 * The hash of an empty Merkle tree: `MTH({}) = SHA-256("")` (RFC 9162 §2.1.1).
 * This is `SHA-256` of zero input bytes — NOT a domain-separated value.
 *
 * @returns The 32-byte hash of the empty input.
 *
 * @example
 * Buffer.from(emptyTreeHash()).toString('hex');
 * // => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
 */
export function emptyTreeHash(): Uint8Array {
  return sha256();
}

/**
 * Compute a leaf hash with leaf domain separation (RFC 9162 §2.1):
 * `HASH(0x00 || entry)`.
 *
 * `entry` is the RAW serialized record bytes (e.g. the canonical in-toto
 * Statement UTF-8 of an AWP receipt, or any caller-chosen leaf encoding). The
 * 0x00 prefix guarantees a leaf can never be reinterpreted as an interior node.
 *
 * @param entry - The raw leaf input bytes.
 * @returns The 32-byte leaf hash.
 *
 * @example
 * hashLeaf(new TextEncoder().encode('hello'));
 */
export function hashLeaf(entry: Uint8Array): Uint8Array {
  return sha256(Uint8Array.of(LEAF_PREFIX), entry);
}

/**
 * Compute an interior node hash with node domain separation (RFC 9162 §2.1):
 * `HASH(0x01 || left || right)`, where `left` and `right` are the **32 RAW
 * BYTES** of the two child hashes.
 *
 * THIS IS THE STANDARD RFC9162_SHA256 RAW-BYTE RULE. The children are the raw
 * digest bytes, concatenated, never their hex text. Any deviation (e.g. hex-text
 * concatenation) yields a non-interoperable root — see the module docstring and
 * `docs/merkle-rules.md`.
 *
 * @param left - The left child's 32-byte hash.
 * @param right - The right child's 32-byte hash.
 * @returns The 32-byte parent node hash.
 * @throws {RangeError} If either child is not exactly 32 bytes (would silently
 *   break interop with a wrong-length input).
 *
 * @example
 * hashNode(hashLeaf(a), hashLeaf(b));
 */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== HASH_SIZE || right.length !== HASH_SIZE) {
    throw new RangeError(
      `hashNode children must be ${HASH_SIZE} raw bytes each (got ${left.length} and ${right.length}); ` +
        'the RFC9162_SHA256 rule hashes raw digest bytes, not hex text',
    );
  }
  return sha256(Uint8Array.of(NODE_PREFIX), left, right);
}

/**
 * NON-STANDARD, NON-INTEROP node rule — provided ONLY so the divergence from the
 * standard raw-byte rule can be demonstrated and pinned by a test. **Never call
 * this on a verification path.**
 *
 * This mirrors the pinned utf8-hex-text variant used elsewhere in the wider
 * system for a separate batch-corroboration purpose: the two child hashes are
 * lowercase hex strings, concatenated and hashed AS UTF-8 TEXT (128 hex chars)
 * under the 0x01 prefix, never decoded to raw bytes. For identical leaves this
 * produces a DIFFERENT root than {@link hashNode}. See `docs/merkle-rules.md`.
 *
 * @param left - The left child's 32-byte hash (rendered to lowercase hex here).
 * @param right - The right child's 32-byte hash (rendered to lowercase hex here).
 * @returns The 32-byte parent under the utf8-hex-text rule (NOT RFC 9162).
 */
export function hashNodeUtf8Hex(left: Uint8Array, right: Uint8Array): Uint8Array {
  const leftHex = Buffer.from(left).toString('hex');
  const rightHex = Buffer.from(right).toString('hex');
  return sha256(
    Uint8Array.of(NODE_PREFIX),
    new TextEncoder().encode(leftHex),
    new TextEncoder().encode(rightHex),
  );
}

/**
 * The largest power of two strictly less than `n` (RFC 9162 §2.1.1's split point
 * `k`, with `k < n <= 2k`). Defined for `n >= 2`.
 *
 * @param n - A count of leaves, `n >= 2`.
 * @returns The split index `k`, a power of two with `k < n <= 2k`.
 *
 * @example
 * largestPowerOfTwoBelow(5); // => 4
 * largestPowerOfTwoBelow(4); // => 2
 */
export function largestPowerOfTwoBelow(n: number): number {
  if (!Number.isInteger(n) || n < 2) {
    throw new RangeError(`largestPowerOfTwoBelow requires an integer n >= 2 (got ${n})`);
  }
  let k = 1;
  // Double until k would reach or exceed n; the last k < n is the answer.
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Compute the Merkle Tree Hash (MTH) of a list of leaf inputs, per RFC 9162
 * §2.1.1, using the standard RAW-BYTE node rule ({@link hashNode}).
 *
 * Each element of `entries` is the RAW leaf input (the same bytes you would pass
 * to {@link hashLeaf}); this function applies the leaf domain separation itself.
 * The result is the 32-byte tree root for a tree of `entries.length` leaves.
 *
 *   MTH({})   = {@link emptyTreeHash}()
 *   MTH({d0}) = hashLeaf(d0)
 *   MTH(D[n]) = hashNode(MTH(D[0:k]), MTH(D[k:n])),  k = largest 2^x < n
 *
 * @param entries - The ordered list of raw leaf inputs.
 * @returns The 32-byte Merkle tree root.
 *
 * @example
 * const root = merkleTreeHash([enc('a'), enc('b'), enc('c')]);
 */
export function merkleTreeHash(entries: Uint8Array[]): Uint8Array {
  const n = entries.length;
  if (n === 0) return emptyTreeHash();
  if (n === 1) return hashLeaf(entries[0]!);
  const k = largestPowerOfTwoBelow(n);
  const left = merkleTreeHash(entries.slice(0, k));
  const right = merkleTreeHash(entries.slice(k));
  return hashNode(left, right);
}

/**
 * Convenience: render a node/leaf/root hash as lowercase hex. Used by vectors,
 * checkpoints (where the wire form is base64), and human-readable diagnostics.
 *
 * @param hash - A raw hash (typically 32 bytes).
 * @returns The lowercase hex string.
 */
export function toHex(hash: Uint8Array): string {
  return Buffer.from(hash).toString('hex');
}

/**
 * Convenience: parse a lowercase/uppercase hex string back to raw bytes.
 *
 * @param hex - A hex string of even length.
 * @returns The decoded bytes.
 * @throws {Error} If the input is not valid hex.
 */
export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`invalid hex string of length ${hex.length}`);
  }
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

/**
 * Constant-time-ish equality for two hashes. Returns false immediately on a
 * length mismatch; otherwise compares all bytes without early-out so a verifier
 * does not leak position information via timing. (The inputs here are public
 * hashes, so this is defense-in-depth, not a strict requirement.)
 *
 * @param a - First hash.
 * @param b - Second hash.
 * @returns True iff the two byte arrays are equal.
 */
export function hashesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
