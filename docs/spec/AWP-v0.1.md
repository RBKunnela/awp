# AWP — Agent Witness Protocol, v0.1

| | |
|---|---|
| **Version** | 0.1 |
| **Date** | {DATE} |
| **Author** | Renata Baldissara-Kunnela |
| **License** | [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/) (this specification document) |
| **Status** | Draft / Experimental |
| **Canonical name** | Agent Witness Protocol (AWP™) |

> **How to cite:** *Agent Witness Protocol (AWP), v0.1 — Author: Renata Baldissara-Kunnela.*
> The reference verifier and SDK are published separately under Apache-2.0; the production
> engine that produces governed receipts at scale is a separate, proprietary work.

---

## Abstract

An AI agent took an action — it moved money, generated a document, acted on a person's
authorization. Later, someone asks: *what exactly did it do, who permitted it, and is the
record of it unaltered?* Today that question has no portable answer. Logs live inside the
system that produced them; to check them you must trust — and usually ask — the operator.
The **Agent Witness Protocol (AWP)** defines one structured, signed record of a governed
agent event — its intent, the authorization behind it, the artifacts it touched (by hash,
never by content), and the witness's own typed testimony about each thing it checked — and a
way to **re-verify that record offline, with no network and no relationship with whoever
produced it.** AWP is a *binding grammar over existing standards* (DSSE/in-toto, RFC 9162
Merkle transparency, RFC 3161 / OpenTimestamps time anchoring), not new cryptography. Its
contribution is the composition — and an honesty boundary, typed into the schema, that makes
overclaiming grammatically impossible.

---

## 1. Scope & non-goals

### In scope

- A canonical record format — the **`WitnessRecord`** — for one governed agent event.
- A **signed, portable envelope** (DSSE + in-toto Statement) so the record travels intact.
- A **transparency-log layer** (RFC 9162 Merkle inclusion proofs + C2SP signed checkpoints)
  so a record's presence in an append-only log is provable.
- **External time anchoring** of checkpoints (OpenTimestamps now; an RFC 3161 / eIDAS slot
  reserved) so a record's existence can be bounded in time by a source outside the producer.
- An **offline verification procedure** (`awp verify`) that re-checks all of the above with
  zero network access.

### Non-goals — what AWP does *not* do

AWP records are **tamper-evident**: a verifier can detect whether a record was altered after
it was witnessed. They are **not** any of the following, and the schema does not let a record
claim to be:

- **Not tamper-proof / not uncorruptible.** AWP makes alteration *detectable*; it does not
  make any underlying store physically immutable.
- **Not authenticity-at-origin.** Proving an artifact is unaltered *since witnessing* says
  nothing about whether it was legitimate when first seen.
- **Not identity-proofing.** AWP can record that a credential from an issuer was verified
  against that issuer's keys. It never asserts that a person is real, or who they "really"
  are. Assurance levels are *echoed* from the issuer, never asserted by AWP.
- **Not completeness.** A record proves what *was* recorded. It can never prove that
  everything was recorded.
- **Not a court-admissibility or legal-authenticity determination.** AWP produces evidence;
  whether that evidence is admissible or sufficient in any jurisdiction is for that forum.

The verbs AWP uses are *witness, verify, anchor, prove*. The verbs it never uses are
*issue, certify, identify, authenticate-a-person*.

---

## 2. The `WitnessRecord`

A `WitnessRecord` is the predicate of one governed event. Three blocks are always required —
`deployment`, `intent`, `chain` — and the rest are optional at the schema level and made
required per *profile* (§6).

### 2.1 Intent — what the agent set out to do

```yaml
intent:
  agent:        { agent_id, agent_key_fpr, runtime_ref }
  action:       <verb, e.g. payment.refund | doc.generate | order.place>
  target_ref:   <opaque, customer-resolvable reference>
  params_hash:  <sha256 of the action parameters>
  started_at:   <RFC 3339 timestamp>
  ended_at:     <RFC 3339 timestamp>
  policy:       { policy_id, policy_hash, decision: allow | deny | escalate }
```

The intent block names *who acted* (opaque agent references only — never raw PII), *what verb*,
*against what target*, *with what parameters* (by hash), *when*, and *the governance decision*
recorded with it.

### 2.2 Authorization — the credential that permitted it

```yaml
authorization:
  principal_ref: <pseudonymous, customer-resolvable only>
  credential:
    type:           oidc | saml | webauthn | openid4vp | sd-jwt-vc | mdoc | ap2-mandate
    issuer:         <iss / DID / IdP entity id>
    assertion_hash: <sha256 of the raw assertion — the assertion stays in the customer's systems>
    challenge_binding:      { … }   # WebAuthn path — binds the credential to THIS intent
    presentation_binding:   { … }   # OpenID4VP path — binds the credential to THIS intent
    status_check:           { method, result, checked_at }
    trust_anchor:           <trust-list / jwks_uri / x5c reference + retrieval time>
    verified:               true | false
    assurance_echo:         <e.g. "eIDAS-high" — ECHOED from the issuer, never asserted by AWP>
    verifier_policy_version: <id>
```

The authorization block is a **verification receipt for an externally-issued credential** — no
prior standard defines this shape, so AWP defines it. The two *binding* sub-blocks are the
mechanism by which a credential is tied to *this specific intent* rather than to a session.

### 2.3 Artifacts — what it read or produced (by hash)

```yaml
artifacts:
  - role:       input | output
    digest:     { alg: sha256 | hmac-sha256, value: <hex>, key_ref: <required when hmac> }
    media_type: <mime>
    size:       <bytes>
    pii_bearing: <bool, default false>
    provenance:  { c2pa_manifest_hash, c2pa_validation: pass|fail|absent, origin_claims: [...] }
```

Content is addressed by hash, never by value. **PII rule (enforced in the schema, not just the
prose):** when an artifact is PII-bearing, a plain `sha256` digest is forbidden — a hash of
low-entropy personal data is reversible — and an `hmac-sha256` digest with a customer-held
`key_ref` is required. Destroying that key is an erasure (see §2.5). Provenance claims (e.g.
C2PA manifests) are **passed through and attributed, never warranted** by AWP.

### 2.4 Verifications — the witness's own typed testimony (the honesty boundary)

```yaml
verifications:
  - check:        <e.g. ap2.checkout_mandate.sd_jwt_signature>
    subject_hash: <sha256 of the verified material>
    issuer:       <whose material>
    method:       <how the keys were obtained>
    result:       pass | fail | unverifiable
    claim_class:  integrity-since-witness | verified-against | asserted-by
```

Every verification entry carries exactly one **`claim_class`**, and this is where AWP's honesty
is structural rather than promised — see §5.

### 2.5 Chain & erasure

```yaml
chain:           { prev_record_hash: <sha256> }   # per-record hash-chain link
erasure_events:                                    # key destruction is itself witnessed
  - { artifact_ref, key_ref, destroyed_at, requested_by_ref }
```

A per-record hash chain gives cheap sequential audit; the Merkle layer (§4) sits above it.
When a customer destroys an HMAC key to erase PII-bearing content, **the erasure itself is
witnessed** — and the chain's integrity survives the erasure.

### 2.6 Receipt — the self-contained, offline-verifiable bundle

A **receipt** chains four layers into one file so anyone can re-check the event offline:

```
signed DSSE envelope          "this is the witnessed record, signed"
  └─ RFC 9162 inclusion proof  "the record's leaf is in the tree…"
       └─ signed C2SP checkpoint "…whose Merkle root the log signed at size N"
            └─ external anchor   "…and that root existed at time T"
```

The receipt is airtight only when the inclusion proof, the checkpoint, and the anchor all agree
on **one root**. A single flipped byte anywhere makes exactly one layer's recomputation diverge,
so the verifier *names* the broken layer.

---

## 3. Verification — the three proofs

`awp verify <receipt.json>` runs, and prints by name, every applicable check, with **zero
network access and no relationship with the producer**:

1. **The signed envelope** (`signature`, `statement`) — recompute the DSSE pre-authentication
   encoding and check the Ed25519 signature against the producer's record key; confirm the
   in-toto Statement shape and that its subject binds the intent. *(Implemented.)*
2. **The transparency log** (`inclusion`, `checkpoint`) — recompute the record's Merkle leaf
   (the exact bytes the envelope signed; RFC 9162 §2.1 `hashLeaf` rule), fold it with the
   audit-path siblings, and confirm the result equals the root inside a **signed** C2SP
   checkpoint. *(Implemented.)*
3. **The time anchor** (`anchor`) — confirm the external anchor commits the verified checkpoint
   root, and report the record's time as an **honest bound** — *"existed no later than the
   checkpoint anchored at T"* — with that anchor's evidentiary weight (see §7). *(OpenTimestamps
   implemented; RFC 3161 verification implemented, qualified weight gated on config.)*

The result is `PASS` (exit 0) or `FAIL` (exit 1, naming the failing check). The schema,
profile, claim-class, and chain-link checks run alongside these. Every report carries a verbatim
honesty line: AWP verify proves **integrity-since-witness only** — not completeness, not
authenticity-at-origin, not the identity of any person.

> **Re-implementability.** There is exactly one canonicalization rule (recursive lexicographic
> key-sort + compact separators), fully specified. An auditor can re-derive every byte the
> verifier checks from this document plus the public DSSE/in-toto, RFC 9162, RFC 3161, RFC 5652,
> and OpenTimestamps specifications. AWP introduces no hidden canonicalization.

---

## 4. The transparency log (RFC 9162 + C2SP)

AWP adopts the **RFC 9162 `RFC9162_SHA256` Merkle subset** for inclusion proofs and the
**C2SP `tlog-checkpoint` in a signed note** for checkpoints. Two properties matter:

- **The leaf is the signed bytes.** The Merkle leaf for a record is *exactly* the canonical
  in-toto Statement the DSSE envelope signs (`leaf_hash = SHA-256(0x00 ‖ leaf_bytes)`), so the
  log entry and the signed record cannot disagree.
- **Two independent keys.** The envelope is signed by the **producer's** record key; the
  checkpoint note is signed by the **log's** key. A full receipt carries both, so an auditor
  needs nothing out of band.

Node hashing for the audit path uses the standard RFC 9162 **raw-byte** rule
`H(0x01 ‖ left ‖ right)`. AWP deliberately uses the standard raw-byte rule (not any utf8-hex
variant) so that off-the-shelf RFC 9162 verifiers interoperate.

---

## 5. The honesty boundary

This is AWP's defining design decision: **overclaim is made unrepresentable in the types, not
merely discouraged in prose.**

### 5.1 The `claim_class` taxonomy

Every verification is exactly one of:

| `claim_class` | Means | Attributes truth to |
|---|---|---|
| `integrity-since-witness` | The referenced material is unaltered since it was witnessed. The weakest, always-true-of-AWP claim. | nobody — it is a statement about the record itself |
| `verified-against` | The witness checked the material against a named issuer's keys/trust anchor, and it verified. | the **issuer**, never AWP |
| `asserted-by` | The witness is recording a claim some issuer made, without itself verifying it. The honest "we were told." | the **issuer** |

There is deliberately **no value** for "authenticity-at-origin" or "identity-proofing." Those
claims cannot be expressed in a `WitnessRecord` at all.

### 5.2 The explicit never-claim list

A conformant producer and a conformant verifier MUST NOT present an AWP record as proving any
of the following, and no field exists to encode them:

- that a record is **tamper-proof, immutable, or uncorruptible** (always *tamper-evident*);
- that a **person is real**, or that an identity has been **proofed** (AWP echoes issuer
  assurance via `assurance_echo`; it never asserts it);
- that a document is **legally authentic** or **issued by a legitimate authority**;
- that a record is **complete** — that *everything* was recorded;
- that a timestamp carries an **eIDAS-qualified legal presumption** unless an RFC 3161 token
  from a qualified trust anchor, pinned as qualified by the operator, is actually present (§7);
- that the record is **admissible** or **sufficient** as evidence in any court or proceeding.

### 5.3 "Customer-keyed" is precise, not absolute

AWP's trust model is that each deployment signs under the customer's own keys for the **log,
witness, and record** — the verifier needs no key held by the protocol's operator. This does
not assert that *no* operator key exists anywhere in a given product built on AWP; it asserts
that *verification* requires none.

---

## 6. Profiles

A profile is a **constraint set over the one schema**, not a separate schema. The record carries
a `profile` that selects which optional blocks become required:

| Profile | Requires | The scene it fits |
|---|---|---|
| `pay` | an `authorization` with a mandate-class credential **and** ≥1 verification on it | an agent action that moved money under a payment mandate |
| `doc` | ≥1 `artifact`; authorization optional (unattended generation is witnessable — it just proves less, and the record says so) | a document an agent produced or read |
| `principal` | an `authorization` whose credential is bound to *this* intent (`challenge_binding` or `presentation_binding`) — a session is not enough | a verified human standing behind a specific action |
| `composite` | intent + ≥1 artifact + mandate-class authorization + ≥1 verification (the union of `pay` and `doc`) | the e-commerce case: a refund + a credit-note document + the approving human, in one record |

---

## 7. Anchoring

AWP anchors a **checkpoint root** (never an individual record) to an external time source, so
cost and proof volume scale with the checkpoint cadence, not with traffic. There are two anchor
paths, and they carry **different** evidentiary weight; the verifier never blurs them.

| Path | Status | Trust model | Honest weight the verifier reports |
|---|---|---|---|
| **OpenTimestamps (OTS)** | **Implemented** — free, no contract | Bitcoin calendars, no trusted party | `trust-minimized` (Bitcoin); confirmed vs pending stated explicitly |
| **RFC 3161 (qualified eIDAS TSA)** | **Planned / Experimental** — verification implemented, qualified vendor is an operator decision (contract + cost) | a QTSP on an EU trusted list (eIDAS Art. 41) | `qualified` **only** when the operator pins the trust anchor as qualified; otherwise a plain `timestamp` — never inferred from the token |

OpenTimestamps confirmation is genuinely asynchronous (Bitcoin block time). A submitted anchor
is reported as *"calendar-attested, awaiting Bitcoin confirmation"* and is **never** presented as
confirmed time until a real block attestation is re-derived offline.

A third, optional, on-chain witness path is **reserved** in the anchor union but not built in
v0.1; leaving the union open lets it land later without reshaping the verifier.

---

## 8. Relationship to the EU AI Act

The EU AI Act's **Article 12** requires high-risk AI systems to automatically and
tamper-evidently log events over their lifetime, with a minimum 6-month retention (Art. 26(6)
for deployers). The Act's application date for high-risk systems is **2 August 2026** as
currently enacted; a November 2025 *Digital Omnibus* proposal would defer standalone
Annex III high-risk obligations to **2 December 2027**, but that proposal is **not yet law**.

A `WitnessRecord` natively expresses Article 12's minimums — start/end timestamps, system
identity and version (`deployment.software`), input references by hash, the governance decision,
and the reference of the human verifier. AWP positions as a logging *architecture* that maps
cleanly onto these requirements. It is **not** a compliance certification, and conformance to
AWP is not conformance to the AI Act — see §9.

---

## 9. Conformance — "ALIGN ≠ conform"

AWP **adopts** mature standards verbatim (DSSE/in-toto, RFC 9162, C2SP checkpoints, RFC 3161,
OpenTimestamps) and **aligns with** standards still in flight (notably IETF SCITT and COSE
Receipts). AWP makes a deliberate distinction:

- **ADOPT** — AWP uses the standard as specified; an external implementation of that standard
  interoperates.
- **ALIGN** — AWP is *emit-compatible* with the standard's direction but **does not claim
  conformance** to a specification that has not reached RFC/final status.

A producer is *AWP-conformant* when it emits records that pass `awp verify` against this
document's rules. AWP conformance is a statement about the record, never about any external
standards body's certification, and never about legal compliance.

### 9.1 Why DSSE/in-toto, and not a COSE_Sign1 / SCITT profile (today)

AWP's differentiation lives in the **payload** — the `WitnessRecord` carried as an in-toto
Statement predicate (human authorization with intent binding, the `claim_class` honesty
boundary, eIDAS-qualified time, the customer-keyed trust model). It does **not** live in the
outer signing envelope. AWP therefore signs with the **DSSE + in-toto** envelope, whose
ecosystem (CNCF-graduated in-toto, the Sigstore family, RFC 9162 + C2SP) is fielded and
offline-verifiable with off-the-shelf tooling **today**, rather than COSE_Sign1, whose
SCITT/COSE-Receipts profile is still an IETF draft.

The recurring question — *"why isn't AWP just a SCITT profile?"* — has a precise answer:

> SCITT's deployment model assumes an always-online, append-only Transparency Service as the
> universal trust anchor. AWP's topology is **customer-keyed**: the neutral witness is operated
> by or for the customer, and verification requires no key held by the protocol's operator and
> no third-party registry. AWP **composes with** SCITT's transparency and non-repudiation
> principles (this §9) while deliberately not binding a record's validity to a third party's
> availability.

The RFC 9162 Merkle layer and C2SP checkpoints (§4) are already the SCITT-compatible bridge: a
future migration changes only the outer envelope; the Merkle anchoring, timestamping, and the
entire `WitnessRecord` payload remain byte-identical.

### 9.2 SCITT migration gate (deferred — do not build until triggered)

A COSE Receipt **export** path (the record re-serialized in COSE_Sign1 for SCITT-ecosystem
consumers, with DSSE remaining the canonical verification path) is **specified-as-deferred**.
It is not built, and a dual-envelope canonical format is explicitly **rejected** (it doubles the
verification surface and signals indecision). Re-open this decision only when **any** of the
following triggers fires:

1. A named design partner, enterprise, or government audit makes COSE/SCITT conformance a hard
   procurement requirement; **or**
2. `draft-ietf-scitt-architecture` reaches final RFC status **and** a SCITT conformance test
   suite exists; **or**
3. The next scheduled architecture review (no earlier than Q4 2026).

Until a trigger fires, AWP remains DSSE/in-toto + "SCITT-aligned" per §9. *(Decision basis:
roundtable 2026-06-29, unanimous — `docs/paybot/competitive/awp-scitt-envelope-roundtable-2026-06-29.md` in the AIOX-Enterprise repo.)*

---

## 10. Versioning & change policy

- This specification is versioned with **SemVer**. v0.x is **experimental**: blocks may change,
  and a v0.x record is not guaranteed to validate against a later v0.y schema.
- The record rides inside an in-toto Statement under a versioned `predicateType`; the namespace
  domain in v0.1 is a placeholder pending the canonical domain decision and MUST NOT be treated
  as a committed URL.
- Breaking changes to the `WitnessRecord` schema, the leaf rule, the canonicalization rule, or
  the `claim_class` taxonomy require a **major** version bump. New optional blocks or new profile
  types are **minor**. Editorial changes are **patch**.
- The honesty boundary (§5) is **invariant**: no version of AWP will add a `claim_class` that
  asserts authenticity-at-origin or identity-proofing.

---

## 11. Attribution & trademark

- **Author of the standard:** **Renata Baldissara-Kunnela.** This authorship is durable: under
  CC-BY-4.0 every derivative of this document must credit the author by name, with the title,
  version, source, and license.
- **License of this document:** CC-BY-4.0. **The reference verifier and SDK** are published
  separately under **Apache-2.0** (free to implement, embed, and redistribute). **The production
  engine** that produces governed receipts at scale is a separate, proprietary work and is not
  covered by these licenses.
- **Name:** *Agent Witness Protocol* and *AWP* are intended as trademarks. The intent is to
  grant a free right to state factual compatibility — *"AWP-compatible"*, *"Witnessed by … ·
  Agent Witness Protocol"* — to any implementation that conforms to this specification, under a
  published usage policy. (Trademark registration is a follow-up action and is not yet filed.)
- Per the universal open-standard pattern (and as the Community Specification License makes
  explicit): **attribution is required for derivatives of this *document*; implementations of
  the specification are free of any attribution obligation.** Credit lives in the spec and the
  name — never as friction on adoption.

---

## Appendix A — Composition, not invention

AWP claims **no new cryptography**. Each layer is an adopted, independently-specified standard:

| Layer | Standard | AWP's role |
|---|---|---|
| Record envelope | DSSE v1.0 + in-toto Statement v1 | adopt as the signed wrapper |
| Transparency log | RFC 9162 (`RFC9162_SHA256`) Merkle subset | adopt for inclusion proofs |
| Checkpoint | C2SP `tlog-checkpoint` + signed note | adopt for signed roots |
| Time anchor (now) | OpenTimestamps (Bitcoin) | adopt as the free, trust-minimized anchor |
| Time anchor (planned) | RFC 3161 / eIDAS qualified TSA | verification adopted; qualified vendor is operator config |
| Signatures / hashing | Ed25519, SHA-256, HMAC-SHA256 | adopt |

AWP's contribution is the **binding** of intent + authorization + artifacts + typed testimony
into one provable, offline-verifiable unit — and the honesty boundary that keeps it from
claiming more than it can prove.

---

*Agent Witness Protocol (AWP), v0.1 — Author: Renata Baldissara-Kunnela. Licensed CC-BY-4.0.*
*Tamper-evident, not tamper-proof. Integrity-since-witness only.*
