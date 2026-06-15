# The AWP receipt bundle — structure, the leaf rule, and how to verify it by hand

A **receipt** is one self-contained JSON file that lets anyone re-check a witnessed
agent event **offline**, with no network and no relationship with whoever produced
it. This document specifies the bundle the `proof()` operation assembles and the
`awp verify` CLI checks, states the exact **leaf rule** so an auditor can
re-implement the binding from scratch, and walks the verification end to end.

> **Tamper-evidence, not tamper-proofing.** Each layer makes alteration *evident*
> to a checker. The bundle does not make any underlying store physically immutable;
> it makes a change detectable.

---

## The four layers

```
signed DSSE envelope          (AW-2)   "this is the witnessed record, signed"
  └─ RFC 9162 inclusion proof (AW-4)   "the record's leaf is in the tree…"
       └─ signed C2SP checkpoint (AW-4)"…whose Merkle root the log signed at size N"
            └─ external anchor   (AW-5) "…and that root existed at time T"
```

`awp verify` runs each as a named, fail-closed check and prints `PASS`/`FAIL` with
a one-line reason. A full receipt is airtight only when the inclusion proof, the
checkpoint, and the anchor all agree on **one root**.

---

## Wire shape

```jsonc
{
  // — convenience for a one-argument `awp verify` (the CLI also accepts --pubkey):
  "public_key_pem":        "-----BEGIN PUBLIC KEY----- …",     // the ENVELOPE key
  "public_key_raw_base64": "…",                                 // same key, 32 raw bytes

  // — layer 1: the signed record (AW-2 DSSE v1.0 + in-toto Statement v1):
  "envelope": {
    "payload":     "<base64(canonical in-toto Statement bytes)>",
    "payloadType": "application/vnd.in-toto+json",
    "signatures":  [{ "sig": "<base64(Ed25519 signature)>" }]
  },

  // — the Merkle root the inclusion proof folds to and the checkpoint commits:
  "checkpoint_root": "<lowercase 64-char hex SHA-256>",

  // — layer 2: the RFC 9162 inclusion (audit-path) proof for the record's leaf:
  "inclusion": {
    "leafIndex": 1,
    "treeSize":  4,
    "leafHash":  "<hex>",                       // = hashLeaf(canonical Statement bytes)
    "siblings":  [ { "hash": "<hex>", "position": "left" | "right" }, … ]
  },

  // — layer 3: the signed C2SP checkpoint (a tlog-checkpoint in a signed-note):
  "checkpoint": {
    "note":        "<origin>\n<size>\n<base64(root)>\n\n— <keyName> <base64(keyID||sig)>\n",
    "keyName":     "<the log's signed-note key name = its origin>",
    "publicKeyB64":"<the LOG's 32-byte Ed25519 public key, base64>"   // ≠ the envelope key
  },

  // — layer 4: external time anchor(s) over checkpoint_root (zero or more):
  "anchors": [
    { "type": "ots",     "checkpoint_root": "<hex>", "ots_proof_b64": "<base64(.ots)>" },
    { "type": "rfc3161", "checkpoint_root": "<hex>", "tst_der_b64":   "<base64(DER token)>" }
  ],

  // — optional: a pinned RFC 3161 trust anchor, so the file is self-contained for
  //   the qualified-time path (qualified weight is reported ONLY if declared here):
  "rfc3161_trust_anchor": { "public_key_pem": "…", "qualified": true, "name": "…" }
}
```

The `inclusion` and `checkpoint` blocks are **additive**: a bare signed envelope or
an AW-3 single-layer receipt (no `inclusion`/`checkpoint`) still verifies — those
checks report **"not present"** (a passing, explicit line), never a silent skip.

> **Two different keys.** The **envelope** is signed by the producer's record key
> (`public_key_pem`). The **checkpoint** note is signed by the **log's** key
> (`checkpoint.publicKeyB64`). They are independent; the receipt carries both so an
> auditor needs nothing out of band.

---

## The leaf rule (re-implementable, no hidden canonicalization)

The log leaf for a record is the **exact bytes the DSSE envelope signs** — the
canonical in-toto Statement — and the Merkle leaf hash is the standard RFC 9162
rule over those bytes:

```
leaf_bytes = canonical_JSON_utf8( inToToStatement(record) )      // == base64decode(envelope.payload)
leaf_hash  = SHA-256( 0x00 || leaf_bytes )                       // RFC 9162 §2.1 hashLeaf
```

where:

- `inToToStatement(record)` is `{ _type, subject:[{name, digest.sha256}], predicateType, predicate: record }`
  with `subject[0]` bound to `record.intent.target_ref` / `record.intent.params_hash`
  (see [`docs/anchoring.md`](anchoring.md) and the envelope module);
- `record` is the **validated** record — schema defaults (e.g. `artifact.pii_bearing`)
  are applied **before** canonicalization, because the envelope signs the validated
  form. Building a leaf from the raw, unvalidated record would omit those defaults
  and the leaf would not match;
- `canonical_JSON` is recursive **lexicographic key-sort** + compact separators
  (the AW-2 canonical-JSON rule); the only canonicalization, fully specified and
  re-implementable;
- node hashing for the audit path is the standard RFC 9162 **raw-byte** rule
  `H(0x01 || left || right)` (see [`docs/merkle-rules.md`](merkle-rules.md) — the
  raw-byte rule, *not* the separate utf8-hex variant).

Equivalently, the simplest way to obtain `leaf_bytes` is `base64decode(envelope.payload)`
— they are identical to the signed payload by construction.

---

## Verifying by hand (what `awp verify` does, step by step)

1. **signature** — recompute DSSE PAE over `payloadType` + `base64decode(payload)`
   and check the Ed25519 signature against the envelope key; then check the in-toto
   Statement shape and that `subject[0]` binds `intent`. This yields the trusted
   decoded **record**.
2. **schema / profile / claim-class / chain-link** — the record is a valid
   `WitnessRecord`, meets its profile minimums, every `claim_class` is within the
   honesty boundary, and the hash-chain link is well-formed (or matches a supplied
   predecessor).
3. **checkpoint** — verify the signed-note signature in `checkpoint.note` against
   `checkpoint.publicKeyB64` + `keyName`, then parse the `tlog-checkpoint` body. The
   root inside the **signed** note is authoritative; it must equal `checkpoint_root`.
4. **inclusion** — recompute `leaf_hash` from the decoded record (the leaf rule
   above) and confirm it equals `inclusion.leafHash`; then fold `leaf_hash` with the
   `siblings` (leaf-first; `left` ⇒ `H(0x01 || sibling || running)`, `right` ⇒
   `H(0x01 || running || sibling)`) and confirm the result equals the **signed**
   checkpoint root.
5. **anchor** — for each anchor, confirm it commits the verified checkpoint root,
   then verify the proof (OTS `.ots` walk, offline; or the RFC 3161 token against
   the pinned trust anchor). The report states the record's time as a **bound** —
   *"existed no later than the checkpoint anchored by this proof"* — with the
   honest weight (trust-minimized for OTS; qualified for RFC 3161 only when the
   trust anchor is declared qualified).

A single flipped byte anywhere makes exactly one layer's recomputation diverge, so
the report **names** the broken layer and exits non-zero. The committed
`samples/receipt.json` (PASS) and `test/verify/fixtures/full-receipt-tampered.json`
(a flipped hex char in `inclusion.siblings[0].hash` → `inclusion` FAIL, every other
layer still PASS) are the worked example.

---

## Producing a receipt — `checkpoint()` and `proof()`

```ts
import { ReferenceLog, checkpoint, proof, signEnvelope, encodePayload } from 'agent-witness-protocol';

const log = new ReferenceLog('awp.example/witness-log');
const envelope = signEnvelope(record, envelopeSigner);          // AW-2
log.append(encodePayload(record).payload);                       // leaf = signed bytes
const cp = checkpoint(log, logNoteSigner);                       // seal a signed checkpoint
const receipt = proof(leafIndex, {                               // assemble the bundle
  store: log, record, envelope,
  signerPublicKey: logNoteSigner.publicKey,
  checkpoint: cp, anchors,                                       // AW-5 anchor proof(s)
});
```

`proof()` refuses to emit an incoherent bundle: it checks that the stored leaf equals
the record's **validated** Statement bytes and that the inclusion proof folds to the
checkpoint root, so a mis-wired producer fails at production time, not at the
auditor's desk. The reference `ReferenceLog` is an in-memory append-only log for the
sample and tests; a production deployment supplies its own store behind the same
`LogStore` interface (and its own key custody for the note signer).

> **Time precision.** A record's time is *bounded by its checkpoint's anchor* — "no
> later than the checkpoint anchored at T" — never a per-record qualified time. The
> checkpoint **cadence** (how many records share one anchor) is a property of the
> log, set when the store is constructed.
