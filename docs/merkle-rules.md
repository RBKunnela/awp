# Merkle hashing rules — the two variants, and why this open log uses only one

The Agent Witness Protocol (AWP) transparency log (AW-4) is a **standard
RFC 9162 (`RFC9162_SHA256`) append-only Merkle log**. Its leaf and node hashing
is defined over **raw bytes**. This document states that rule precisely, states
the *separate* non-standard variant that exists elsewhere in the wider system,
and shows — with worked numbers — that the two produce **different roots** for
the same leaves. The boundary is captured as committed test vectors
(`test/log/vectors/merkle-rule-divergence.json`) and asserted by
`test/log/merkle-rule-divergence.test.ts`, so the divergence can never go silent.

> **Tamper-evidence, not tamper-proofing.** A Merkle log makes deletion or
> rewrite of past entries *evident* to anyone who checks a consistency proof. It
> does not make the underlying store physically immutable.

---

## Rule A — the standard RFC9162_SHA256 RAW-BYTE rule (THIS open log)

Hash function: **SHA-256**. Domain separation per RFC 9162 §2.1 / RFC 6962 §2.1.

```
leaf hash:  H(0x00 || entry_bytes)
node hash:  H(0x01 || left || right)
```

- `entry_bytes` is the **raw serialized leaf input** (for an AWP receipt, the
  canonical in-toto Statement UTF-8 bytes).
- `left` and `right` are the **32 RAW BYTES** of the two child hashes. They are
  **decoded to bytes before hashing** — never their hex text. This is the entire
  point of the `RFC9162_SHA256` profile, and it is what lets any independent
  RFC 9162 verifier (Go sumdb, Sigsum, Sigstore Rekor v2, or a hand-rolled
  auditor script) interoperate with this log.
- The empty tree hashes to `SHA-256("")` (RFC 9162 §2.1.1):
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The Merkle Tree Hash (MTH) over `D[n] = d[0..n-1]` (RFC 9162 §2.1.1):

```
MTH({})   = SHA-256("")
MTH({d0}) = H(0x00 || d0)
MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest 2^x with k < n
```

This is implemented in `src/log/merkle-rfc9162.ts` (`hashLeaf`, `hashNode`,
`merkleTreeHash`) and is the ONLY rule on any verification path in this package.

---

## Rule B — the separate utf8-hex-TEXT variant (NOT used here)

A **different, pinned, non-standard** Merkle variant exists elsewhere in the
wider system, kept SEPARATE for its own batch-corroboration purpose against an
external verifier. It uses the same `0x00`/`0x01` domain-separation prefixes but
hashes interior nodes over the children's **lowercase hex strings as UTF-8
text** — 128 hex characters — and **never decodes them to raw bytes**:

```
leaf hash:  H(0x00 || canonical_json_text)        -> lowercase hex string
node hash:  H(0x01 || leftHex || rightHex)        -- leftHex,rightHex are utf8 TEXT
```

Because the node inputs are 128 ASCII hex characters rather than 64 raw bytes,
**Rule B produces a different parent hash than Rule A for the same children.**

This package provides `hashNodeUtf8Hex` (in `src/log/merkle-rfc9162.ts`) **only**
to demonstrate and pin that divergence in a test. It is never called on a
verification path, and it is documented here so that no auditor or external
verifier ever silently mixes the two.

---

## Worked example — same two leaves, two roots

Leaves: the ASCII bytes of `leaf-0` and `leaf-1`.

| Quantity | Value (hex) |
| --- | --- |
| `H(0x00 \|\| "leaf-0")` (left leaf) | `305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7` |
| `H(0x00 \|\| "leaf-1")` (right leaf) | `3145c409f259b7c53e32036090ff76751025a2498ba9823ef718cac50b4e616f` |
| **Rule A** root `H(0x01 \|\| left \|\| right)` (32+32 raw bytes) | `60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc` |
| **Rule B** root `H(0x01 \|\| leftHex \|\| rightHex)` (128 utf8 hex chars) | `6cb610a55ea72fdd87e264eef8cf391d3bdb8f6c1af68d1b4698133e32d7146f` |

The two roots are different. An AWP open-log verifier MUST accept only the
Rule A root and MUST reject a Rule B root presented as if it were an open-log
root (and vice-versa). The test
`test/log/merkle-rule-divergence.test.ts` asserts exactly this, across whole
trees of 2..16 leaves, and checks these committed numbers against the live
implementation.

To regenerate the numbers from the shipped code:

```
npm run build
node test/log/vectors/generate-vectors.mjs
```

---

## Why this matters (threat model)

- **Hex/byte rule confusion → unverifiable receipts.** This is the single most
  likely interoperability bug in the transparency layer. It is killed by this
  document, the committed vectors, and the boundary test — a verifier built from
  the RFC against Rule A will never silently agree with a Rule B root.
- **Second-preimage / tree-extension.** The `0x00`/`0x01` prefixes mean a leaf
  hash can never be reinterpreted as an interior node, preventing the classic
  Merkle tree-extension second-preimage attack. Both rules share this property;
  only the node-input encoding differs.

---

## Proof verification (Rule A only)

- **Inclusion** (`src/log/proofs.ts`, `verifyInclusion`): recompute the root from
  the leaf hash and the audit path; RFC 9162 §2.1.3.
- **Consistency** (`src/log/proofs.ts`, `verifyConsistency`): recompute BOTH the
  old (size `m`) and new (size `n`) roots from the proof; RFC 9162 §2.1.4.2. Any
  rewrite of one of the first `m` leaves makes the recomputed old root diverge,
  so the proof fails — the rewrite is evident.
- **Checkpoint** (`src/log/checkpoint.ts`): the root at a given size is committed
  in a C2SP `tlog-checkpoint` (`origin` / decimal `size` / base64 `root`) wrapped
  in a `signed-note`; `verifyNote` checks the Ed25519 signature over the note
  text, so a tampered size or root fails.
