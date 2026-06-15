# Agent Witness Protocol (AWP) — open schema & verifier

> Status: v0.1 (early). This package ships the **open** data definition (the
> `WitnessRecord` schema, types, and profile validators), the **DSSE + in-toto
> signed envelope**, the RFC 9162 transparency-log layer (Merkle proofs + C2SP
> checkpoints) with a reference append-only **log store**, the external **time
> anchors** (OpenTimestamps verify + submit/upgrade, and an RFC 3161 qualified-TSA
> verify slot — see [`docs/anchoring.md`](docs/anchoring.md)), the **producer
> operations** `proof()` / `checkpoint()` that assemble a self-contained **receipt
> bundle**, and the offline **`awp verify`** CLI + library that checks that bundle
> end-to-end (see [`docs/receipts.md`](docs/receipts.md)). The package name and
> namespace below are **placeholders** pending an operator decision.

## What this is

A `WitnessRecord` is one structured record of a governed agent event: the
intent (what an agent set out to do), the authorization (the credential that
permitted it, and what was verified about that credential), the artifacts it
read or produced (by hash, never by content), and the witness's own typed
testimony about each external thing it checked.

This package is the **schema and the validators** — the contract every producer
emits and every verifier reads. It is deliberately permissive (Apache-2.0) so
that anyone can read the schema, validate a record, and — once the later
verifier stories land — re-check a receipt **without a relationship with, and
without asking, whoever produced it.**

## What it proves — and what it does not

AWP records are **tamper-evident**: a verifier can detect whether a record was
altered after it was witnessed. They are not, and this schema does not let a
record claim to be, any of the following:

- **Not authenticity-at-origin.** A record proving an artifact is unaltered
  since witnessing says nothing about whether the artifact was legitimate when
  it was first seen.
- **Not identity-proofing.** AWP can record that a credential from some issuer
  was verified against that issuer's keys. It never asserts that a person is
  real or who they "really" are. Issuer assurance levels are *echoed* from the
  issuer (`assurance_echo`), never asserted by AWP.
- **Not completeness.** A record proves what *was* recorded. It can never prove
  that everything was recorded.

The honesty boundary is enforced in the types, not just the prose. The
`claim_class` of every verification must be one of
`integrity-since-witness`, `verified-against`, or `asserted-by` — there is no
representable value that claims more than the witness can support.

## Profiles

A record carries a `profile` that selects which blocks are required:

| Profile | Requires |
|---|---|
| `pay` | an `authorization` with a mandate-class credential **and** at least one verification on it |
| `doc` | at least one `artifact`; authorization is optional (unattended generation is witnessable — it just proves less) |
| `principal` | an `authorization` whose credential is bound to *this* intent (`challenge_binding` or `presentation_binding`) |
| `composite` | intent + at least one artifact + mandate-class authorization + at least one verification (the union of the `pay` and `doc` minimums) |

## Usage

```ts
import { validateWitnessRecord, validateProfile } from 'agent-witness-protocol';

const result = validateWitnessRecord(input);
if (!result.ok) {
  console.error(result.errors);
} else {
  const profile = validateProfile(result.record);
  if (!profile.ok) console.error(profile.failures);
}
```

A JSON Schema (draft 2020-12) equivalent of the types ships at
`src/schema/witness-record.schema.json` for non-TypeScript consumers.

## Verify a receipt — offline, no relationship with the producer

`awp verify <receipt-or-envelope.json>` checks a receipt with **zero network
access and no relationship with whoever produced it**. It runs, and prints by
name, every applicable check:

- `signature` — the DSSE Ed25519 signature over the in-toto Statement;
- `statement` — the Statement shape and its subject binding to the intent;
- `schema` / `profile` — the `WitnessRecord` structure and its profile minimums;
- `claim-class` — the honesty boundary (no verification may overclaim);
- `chain-link` — the per-record hash-chain link;
- `checkpoint` — when a signed C2SP checkpoint is present, its note signature
  and the Merkle root it commits;
- `inclusion` — when an RFC 9162 inclusion proof is present, that the record's
  leaf folds to the signed checkpoint root;
- `anchor` — when an external anchor is present (OpenTimestamps and/or an RFC
  3161 token), that it commits the checkpoint root, reported as an **honest time
  bound** ("this record existed no later than the checkpoint anchored at T") with
  the anchor's **evidentiary weight**: trust-minimized Bitcoin time for OTS, and
  qualified eIDAS weight for RFC 3161 *only* when the pinned trust anchor is
  declared qualified — never inferred.

A **full receipt** chains all of these into one self-contained file:

```
signed DSSE envelope  →  RFC 9162 inclusion proof  →  signed C2SP checkpoint  →  external anchor
"the witnessed record"   "its leaf is in the tree"    "whose root the log signed"  "that root existed at T"
```

The result is `PASS` (exit 0) or `FAIL` (exit 1, naming the failing check), and
every report carries the verbatim honesty-boundary line: AWP verify proves
*integrity-since-witness only* — not completeness, not authenticity-at-origin,
not the identity of any person.

### The 10-minute walkthrough (byte-flip → FAIL)

A committed full-receipt sample makes the Phase-2 re-performance demo a copy-paste
— PASS over every layer, then a one-byte flip that FAILs with the named layer, all
offline:

```sh
npm run build

# 1. A full receipt verifies — every layer PASS (signature, schema, profile,
#    claim-class, chain, checkpoint, inclusion, anchor), exit 0:
node bin/awp.js verify samples/receipt.json

# 2. A copy with ONE flipped hex char in the inclusion proof's tree path —
#    re-run: FAIL, exit 1, naming the "inclusion" check (every OTHER layer still
#    PASSES, so the failure is provably isolated to the tampered layer):
node bin/awp.js verify test/verify/fixtures/full-receipt-tampered.json
```

The sample embeds its own public key, so a single argument is enough. The AW-3
single-layer fixtures (`test/verify/fixtures/valid-receipt.json` /
`tampered-receipt.json`, the byte-flip in an intent digest → `signature` FAIL)
still verify too. Pass `--pubkey <pem|base64|path>` to supply a key explicitly,
`--prev <hash>` to check a chain link against a known predecessor,
`--tsa-pubkey <pem|base64|path>` (+ `--tsa-qualified`) to verify an RFC 3161
anchor against a pinned TSA key, or `--json` for a machine report. Regenerate the
fixtures with `node test/verify/fixtures/generate-fixtures.mjs` (AW-3) and
`node test/verify/fixtures/generate-full-receipt.mjs` (AW-6 full receipt +
sample). See [`docs/receipts.md`](docs/receipts.md) for the bundle structure and
the exact, re-implementable leaf rule.

### As a library

```ts
import { verify } from 'agent-witness-protocol';

const report = verify(receiptJson, { publicKey });
if (!report.ok) {
  for (const c of report.checks) if (!c.ok) console.error(c.name, c.reason);
}
```

## License

Apache-2.0. See [LICENSE](./LICENSE).
