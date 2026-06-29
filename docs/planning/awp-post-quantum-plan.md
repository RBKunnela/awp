# AWP Post-Quantum (Hybrid) Signatures — Implementation Plan + ADR

**Author:** @architect (Aria), AIOX / PayBotFin
**Date:** 2026-06-17
**Status:** PLAN — not yet executed. Pending Challenger PASS before delegation.
**Scope:** Additive hybrid Ed25519 + ML-DSA (Dilithium2 / `ML-DSA-44`) signatures on the AWP DSSE envelope, EXPERIMENTAL, crypto-agile. **Not** a rewrite.
**Routing:** This doc is about the `awp` project, so it lives in `awp/docs/planning/` per `doc-routing-by-content-type.md` (project-specific, not framework).

> **Honesty boundary (binds this entire plan).** AWP never claims "quantum-proof,"
> "unbreakable," or "future-proof." PQ here is **EXPERIMENTAL**, **hybrid** (classical
> signature still required), and **not mandated** by any conformance tier. We mirror
> VeritasChain's honest "available, not a certification requirement" posture. No eIDAS /
> qualified / certified claims attach to the PQ path. ML-DSA is a NIST-standardized
> algorithm (FIPS-204); using it is not a guarantee of security against future attacks.

---

## 0. The approach in three lines

1. **Additive, not a rewrite.** The DSSE envelope already carries a `signatures[]` array; a hybrid record adds a *second* signature (ML-DSA-44) alongside the existing Ed25519 one over the **exact same PAE bytes**. Existing Ed25519-only receipts keep verifying byte-for-byte.
2. **Crypto-agile by a signature-suite registry.** A small typed registry (`alg` → {keyid convention, sign, verify, key sizes}) means adding SLH-DSA or ML-DSA-65 later is a registry entry + test vectors, not a verifier rewrite.
3. **Verifier policy = "verify-any-or-all, honestly reported."** The verifier checks every signature it has a key for, reports each by name, and applies an explicit, operator-pinned policy (`require: classical | any | all`); default is **classical-required + PQ-advisory** so legacy and hybrid both PASS while PQ status is always surfaced.

---

## 1. Technical design

### 1.1 What changes, what does not

| Layer | File | Change |
|---|---|---|
| Envelope | `src/envelope/dsse.ts` | Add a signature-suite registry; generalize `signEnvelope` to take 1..N signers; generalize `verifyEnvelope` to evaluate each `signatures[]` entry against a *set* of trust keys under a policy. **PAE byte string is unchanged.** |
| Envelope (new) | `src/envelope/suites.ts` | New: the `SignatureSuite` registry (`ed25519`, `ml-dsa-44`), keyid conventions, per-suite `sign`/`verify`. |
| Verify | `src/verify/checks.ts` | `checkSignature` becomes suite-aware: reports `signature:ed25519`, `signature:ml-dsa-44` (or a combined `signature` line listing each suite + verdict), plus a `pq-posture` advisory line. |
| Verify | `src/verify/verify.ts` | Thread a `pqPolicy` + optional PQ public key(s) through `VerifyOptions`. No reordering of the existing check pipeline. |
| Schema | `src/schema/witness-record.ts` | **No predicate change.** The signature suite lives in the DSSE envelope, not the witnessed predicate. (A record does not assert its own signature algorithm — the envelope does. This keeps the honesty boundary clean and avoids a schema-version bump.) |
| CLI | `src/cli/awp.ts` | Add `--pq-pubkey <ml-dsa pub>` and `--pq-require <off|advisory|required>` flags, mirroring the existing `--tsa-pubkey`/`--tsa-qualified` config-not-code pattern. |
| Docs | `README.md`, `docs/receipts.md`, new `docs/post-quantum.md` | PQ section, EXPERIMENTAL banner, never-say list extension. |
| Spec | `protocol/agentwitnessprotocolv0.1.md` | New §2.x PQ subsection + §11 open-item; version note. |
| Package | `package.json` | Add `@noble/post-quantum` as a dependency (see §1.4). |

### 1.2 Signature-suite enum + hybrid representation in `signatures[]`

DSSE `signatures[]` entries are `{ keyid?, sig }`. We do **not** invent a new wire field — we use the **`keyid` convention** to carry the suite, because:
- DSSE already says `keyid` is an opaque, untrusted hint a verifier MAY use to select a key (`dsse.ts` line 79-84). That is exactly "which key/alg is this signature."
- It keeps the envelope **100% DSSE-v1.0-conformant** — no custom envelope field (the spec's `AVOID: bespoke envelopes`, §2 line 71).

**Keyid convention (new, documented):**

```
keyid = "<suite>:<fingerprint>"
  suite ∈ { "ed25519", "ml-dsa-44" }    # the SignatureSuite registry id
  fingerprint = lowercase hex SHA-256 of the raw public key bytes (first 16 bytes / 32 hex chars)
```

Backward-compat rule: a `keyid` **with no `<suite>:` prefix, or absent,** is treated as `ed25519` (every existing receipt). This makes the change additive — old receipts parse unchanged.

A hybrid envelope therefore looks like:

```json
{
  "payload": "<base64 canonical statement>",
  "payloadType": "application/vnd.in-toto+json",
  "signatures": [
    { "keyid": "ed25519:9f2c…",   "sig": "<base64 64-byte Ed25519 sig>" },
    { "keyid": "ml-dsa-44:1a7b…", "sig": "<base64 2420-byte ML-DSA-44 sig>" }
  ]
}
```

Both signatures are over the **identical** `PAE(payloadType, payload)` bytes (`pae()` in `dsse.ts` — unchanged). No second canonicalization, no second payload. An auditor re-derives one byte string and checks it under two algorithms.

> **Naming decision — `ML-DSA-44`, not "Dilithium2."** The plan, the registry id, the
> keyid, the docs, and the spec all use the **NIST FIPS-204 name `ML-DSA-44`** (security
> level ~128-bit, Dilithium2's standardized successor). "Dilithium2" appears once, in
> parentheses, for reader recognition. Rationale in the ADR §3. (VCP's spec still says
> "DILITHIUM2"; using the standardized name is the more correct, more durable choice and a
> small honest edge.)

### 1.3 The `SignatureSuite` registry (crypto-agility core)

```ts
// src/envelope/suites.ts  (new)
export interface SignatureSuite {
  id: 'ed25519' | 'ml-dsa-44';          // closed enum today; extend by adding a member
  classical: boolean;                    // true = pre-quantum; false = PQ
  experimental: boolean;                 // ml-dsa-44 = true
  publicKeyLen: number;                  // 32 (ed25519) | 1312 (ml-dsa-44 pub)
  signatureLen: number;                  // 64 (ed25519) | 2420 (ml-dsa-44 sig)
  sign(paeBytes: Uint8Array, privateKey: SuitePrivateKey): Uint8Array;
  verify(paeBytes: Uint8Array, sig: Uint8Array, publicKey: SuitePublicKey): boolean;
  fingerprint(publicKey: SuitePublicKey): string;   // → keyid suffix
}
```

- `ed25519` suite wraps the *existing* Node `crypto` path (zero behavior change).
- `ml-dsa-44` suite wraps `@noble/post-quantum`'s `ml_dsa44` with **deterministic signing** (`{ extraEntropy: false }`) so committed test vectors are reproducible.
- Adding `slh-dsa-128f` or `ml-dsa-65` later = one registry entry + vectors. **That is the whole crypto-agility story** — no verifier edits, no schema bump.

Sizes (verified against `@noble/post-quantum` `ml_dsa44.lengths`): pub 1312 B, secret 2560 B, **sig 2420 B**. (A hybrid receipt grows by ~2.4 KB base64 ≈ 3.2 KB — note this in `docs/post-quantum.md`; it is the honest cost.)

### 1.4 Library choice for ML-DSA in TS/JS — evaluated

| Option | Verdict | Why |
|---|---|---|
| **`@noble/post-quantum`** (paulmillr) | **RECOMMENDED** | Pure-JS, **zero native bindings** (no `node-gyp`, no platform build — critical for AWP's cross-platform Win/Mac/Linux + offline + "auditor can re-run in 2036" stance). Audited lineage (noble family). FIPS-204 `ml_dsa44/65/87`, clean `keygen/sign/verify`, **deterministic mode** for vectors, tree-shakeable, MIT. Matches the existing dependency-light ethos (the only runtime dep today is `zod`). API mirrors the current `Signer` seam exactly. |
| `liboqs` / `oqs` Node bindings | Rejected (for now) | Native build (`node-gyp`/WASM toolchain) breaks the no-native-build, offline-auditable, cross-platform guarantee. The Mac→Windows toolchain fragility is a known operator pain (multi-machine setup). Re-evaluate only if a FIPS-140-3 *validated module* becomes a hard customer requirement — and document it as a separate suite, not a swap. |
| `mlkem`/`crystals-*` single-purpose pkgs | Rejected | Narrower, less-maintained, no unified DSA+SLH family for future agility. |
| WASM liboqs | Rejected | WASM red-status is a live pain in this ecosystem (night-shift WASM baseline issue); adds a build/runtime surface AWP deliberately avoids. |

**Decision: `@noble/post-quantum`.** It is the only option that preserves all four AWP invariants simultaneously: dependency-light, no native build, offline, auditable.

### 1.5 Verifier policy — "verify-any-or-all," honest reporting

The verifier evaluates **every** signature it has a trust key for and reports each. The **policy** decides whether the overall `ok` requires which suites to pass:

```ts
type PqPolicy = 'off' | 'advisory' | 'required';
// off       → ignore PQ signatures entirely (pure legacy mode)
// advisory  → DEFAULT. classical MUST verify; PQ is checked-and-reported but does NOT gate ok.
//             A hybrid receipt prints "signature:ml-dsa-44 PASS (advisory)"; a legacy receipt
//             prints "pq-posture: no PQ signature present (classical only)".
// required  → classical MUST verify AND at least one PQ signature MUST verify; absence = FAIL.
//             (Only an operator who has provisioned PQ keys end-to-end sets this.)
```

Rules (all reported by name, never silently skipped — the existing "silent partial verification is a FAIL" discipline, `verify.ts` line 34):
1. **Classical signature is always required** in `advisory`/`required` (an attacker must not strip the Ed25519 sig and pass on PQ alone while PQ libs are young/experimental). This is the hybrid guarantee: you need *both* halves' weaknesses to fail you.
2. A PQ signature present but **no PQ public key supplied** → reported as `signature:ml-dsa-44 UNVERIFIED (no key supplied)`; gates `ok` only under `required`.
3. A PQ signature that **fails** → always FAIL regardless of policy (a present-but-wrong PQ sig is tampering, not absence).
4. The verifier emits a dedicated **`pq-posture`** advisory line every run (mirrors the always-printed `HONESTY_BOUNDARY_LINE`), e.g. *"PQ posture: hybrid Ed25519 + ML-DSA-44 (EXPERIMENTAL); PQ is not mandated and carries no qualified/eIDAS weight."*

### 1.6 Test vectors (the Challenger will check these exist + pass)

Committed under `test/envelope/vectors/` and `test/verify/fixtures/`:
- **PASS — hybrid**: a receipt with valid Ed25519 + valid ML-DSA-44 over the same PAE; `advisory` and `required` both PASS.
- **PASS — classical-only legacy**: an existing Ed25519-only receipt; `advisory` PASSES with `pq-posture: classical only`; `required` FAILS with a named reason (proves the gate works).
- **FAIL — tampered payload**: one flipped byte → *both* `signature:ed25519` and `signature:ml-dsa-44` FAIL (proves both bind the same bytes).
- **FAIL — tampered PQ sig only**: flip one byte in the ML-DSA sig → `signature:ed25519` PASS, `signature:ml-dsa-44` FAIL → overall FAIL (rule 3).
- **FAIL — PQ stripped**: remove the ML-DSA entry → `advisory` PASS (legacy-shaped), `required` FAIL (rule 1/2 — absence detected).
- **Known-answer vector**: deterministic ML-DSA-44 sign over a fixed PAE + fixed seed → fixed signature bytes committed (reproducibility; an auditor regenerates and byte-compares). Uses `{ extraEntropy: false }`.
- **Cross-impl note (deferred, documented)**: optionally validate one vector against a second ML-DSA implementation to catch single-library bugs — flagged as a P3 follow-up, not blocking.

### 1.7 Backward-compat + migration

- **Existing receipts**: verify unchanged. `keyid` without a `suite:` prefix ⇒ `ed25519`. No re-signing, no re-issue.
- **Producers** opt in by configuring a second (ML-DSA) signer; the open package never holds keys (customer-keyed invariant preserved — both signers are injected closures, exactly like today's `signerFromPrivateKey`).
- **Migration path**: classical-only → hybrid (add PQ signer) → (far future, never in this work) PQ-required. Each step is config, never a forced flag-day.

### 1.8 Crypto-agility framing (what we are NOT doing)

We are not building a generic COSE/JOSE alg-negotiation engine (the spec explicitly `AVOID`s COSE-as-internal-format while Node libs are stale, §2 line 71). KISS: a 2-entry typed registry with documented extension points. Adding a third suite is a known, bounded, tested operation — that is sufficient agility for a v0.x protocol and avoids over-engineering (per `kiss-no-overengineering.md`).

---

## 2. Spec changes to AWP

Target file: `D:\1-PROJECTS\PAYBOT\protocol\agentwitnessprotocolv0.1.md` (project-owned).

1. **New §2.x "Post-quantum (experimental)"** under the Standards stack:
   - Status banner: **EXPERIMENTAL · hybrid · not mandated · no qualified weight.**
   - Suite: hybrid Ed25519 + ML-DSA-44 (FIPS-204) in the DSSE `signatures[]` array, both over the same PAE.
   - Keyid convention (`<suite>:<fp>`); legacy keyid ⇒ ed25519.
   - Verifier policy enum (`off`/`advisory`/`required`), default `advisory`, classical always required.
   - Explicit never-say: not "quantum-proof," not "future-proof," not certified.
2. **§4 envelope note**: one sentence — "the envelope MAY carry additional `signatures[]` entries under the suite-keyid convention; the witnessed predicate is unchanged and asserts no signature algorithm."
3. **§11 Open items**: "PQ suite expansion (ML-DSA-65 / SLH-DSA) and optional cross-implementation vector validation are deferred; FIPS-140-3-validated module (liboqs) is a separate future suite, not a swap."
4. **Versioning**: protocol stays **v0.1** (additive, no predicate change, no breaking wire change — old receipts still verify). Package bumps **0.1.0 → 0.2.0** (new feature, new optional dependency; minor per semver while pre-1.0). The `predicateType` placeholder is untouched.

---

## 3. ADR (short)

**ADR-AWP-PQ-001 — Hybrid additive ML-DSA-44 signatures on the DSSE envelope (EXPERIMENTAL)**

- **Status:** Proposed (pending Challenger PASS).
- **Context:** VeritasChain advertises EXPERIMENTAL Dilithium2+Falcon512 with a hybrid classical+PQC path (VCP v1.2 §1.4). AWP has zero PQ posture (`veritaschain-vs-awp-technical.md` §2.1, §6 item 3). DSSE already supports `signatures[]`; the change can be purely additive.
- **Decision:** Add a hybrid **Ed25519 + ML-DSA-44** signing/verifying path, carried in the existing DSSE `signatures[]` array via a `<suite>:<fp>` keyid convention, behind a verifier policy (`off`/`advisory`/`required`, default `advisory`, classical always required). Library: `@noble/post-quantum`. Crypto-agility via a small typed `SignatureSuite` registry. Marked EXPERIMENTAL, not mandated, no qualified weight.
- **Alternatives considered:**
  1. *New envelope field for PQ sig* — rejected (breaks DSSE conformance; spec `AVOID`s bespoke envelopes).
  2. *Replace Ed25519 with ML-DSA (PQ-only)* — rejected (young/experimental algorithm + library; loses the hybrid "need both to fail" guarantee; breaks every existing receipt).
  3. *Predicate-level signature-alg field* — rejected (a record asserting its own signature algorithm muddies the honesty boundary; the envelope is the right layer; forces a schema bump for no gain).
  4. *`liboqs`/WASM* — rejected for now (native build / WASM fragility breaks offline + cross-platform + auditable invariants). Documented as a future *separate suite*.
  5. *Falcon512 too (match VCP exactly)* — deferred (one PQ suite is enough to close the posture gap honestly; Falcon adds a second library surface for no near-term need — KISS).
- **Why hybrid-additive:** Existing Ed25519-only receipts verify unchanged (zero migration). An attacker must defeat *both* Ed25519 *and* ML-DSA to forge — the hybrid is strictly ≥ either alone. PQ can be exercised in production-shaped receipts today without betting the protocol on a young algorithm.
- **Why ML-DSA naming over "Dilithium":** `ML-DSA-44` is the NIST FIPS-204 standardized name; "Dilithium2" is the pre-standard research name. Using the standard name is more correct, more durable, and a small honest edge over VCP's still-"DILITHIUM2" spec. Documented once with the parenthetical for recognition.
- **Risks & mitigations:**
  - *PQ library immaturity* → hybrid (classical always required) contains the blast radius; EXPERIMENTAL labeling; deterministic vectors catch library regressions.
  - *Receipt size +~3 KB* → documented honestly in `docs/post-quantum.md`; advisory-default means most receipts stay classical-only until an operator opts in.
  - *Overclaim drift* → `pq-posture` line + extended never-say list in README/spec; Challenger gate enforces it.
  - *New runtime dependency* → `@noble/post-quantum` is pure-JS, audited-lineage, MIT, no native build; isolated behind the suite registry so it can be swapped.
  - *False sense of "quantum-safe"* → explicit honesty-boundary language; no certified/qualified claim attaches.

---

## 4. VeritasChain PQ delivery comparison + verdict

| Dimension | VeritasChain (VCP v1.2 §1.4) | AWP (this plan) | Read |
|---|---|---|---|
| PQ signature algorithm(s) | DILITHIUM2 **+** FALCON512 | ML-DSA-44 (one suite; agility for more) | VCP broader; AWP focused + standardized-naming |
| Status | EXPERIMENTAL, "not a certification requirement" | EXPERIMENTAL, "not mandated" | **Identical honest posture** (by design — we mirror it) |
| Hybrid classical+PQC | Defined hybrid path | Hybrid **enforced** (classical always required in advisory/required) | AWP's hybrid is a verifier *rule*, not just a defined option — slightly sharper |
| Classical default | Ed25519 default | Ed25519 default, PQ advisory-default | Same default; same "PQ doesn't gate unless you opt in" |
| Standardized naming | "DILITHIUM2" (pre-standard name) | "ML-DSA-44" (FIPS-204 name) | **AWP more correct/durable** |
| Carrier | (VCP's own envelope/tiers) | DSSE `signatures[]` (standard, additive) | AWP rides an existing standard array — cleaner additivity |
| Crypto-agility | Tier/spec-defined | Typed suite registry, add-by-entry+vectors | Comparable; AWP's is a concrete code seam |
| Cross-impl / FIPS-140-3 | Not stated | Deferred (documented as future separate suite) | Tie / both honest about the gap |

**Verdict (honest).** Ours is **compatible with what an informed user expects** and **at least as good on the axes that matter for a v0.x protocol**, while *narrower* on raw algorithm count:
- **Better**: standardized naming (`ML-DSA-44`), hybrid enforced as a verifier rule, additive carriage in a standard DSSE array (no bespoke envelope), a concrete crypto-agility seam.
- **Equal**: the honest EXPERIMENTAL/not-mandated posture, Ed25519 default, hybrid classical+PQC, "PQ doesn't gate unless opted in."
- **Behind / deliberately not chasing**: VCP ships *two* PQ algorithms (Dilithium2 **and** Falcon512); we ship one and defer the second (KISS — one suite closes the posture gap; a second is a registry entry when a real need appears). We also don't (yet) claim a FIPS-140-3-validated module.

Net: closing this gap moves AWP from "**nothing on PQ**" (the one real, quotable VCP lead per the comparison doc §2.1) to "**honest hybrid PQ, standardized-named, additive**" — neutralizing the lead without overclaiming. We are not worse off than a user coming from VCP would expect; on naming and additivity we are slightly ahead.

---

## 5. Night-shift execution structure (Full SDC, in order)

**Operating rules (NON-NEGOTIABLE):**
- Run order is the **full** AIOX Story Development Cycle, plan-first, **DEV LAST**: analyst → architect → pm → po → sm → (data-engineer N/A here) → qa/security → **dev** → devops. No code-first shortcuts (`feedback_loops_must_follow_full_sdc`).
- **Challenger gate (multi-lens), default verdict BLOCKED**, is mandatory and unskippable **twice**: (a) on **this plan** before any delegation, and (b) on **each story's output** before it is "done." Nothing ships without Challenger PASS (`feedback_nothing_done_without_challenger`). The Challenger convenes QA + security (incl. attacker lens — red-team the hybrid: sig-stripping, downgrade, algorithm-confusion, library-regression) + mental-model + Anthropic-practice lenses; output = visual diagram + plain language.
- **Quality Foundation** on every story: ≥80% coverage on changed files, ≥3 tests/function (happy/error/edge), zero skipped tests, doc comments on every export, 2-pass @qa under the 12-check matrix.
- **Automated PR merge authority**: only @devops merges, after the full chain signs off (`automated-pr-merge-authority.md`).
- Run with the **fable-profile at MAX effort**.

### Story list (each ends at a Challenger gate)

**Story PQ-0 — Spec + ADR + posture (docs-first, no code)**
- *Chain emphasis*: analyst (confirm VCP posture still current) → architect (this ADR) → pm (scope) → po (validate) → sm (draft) → qa (doc review) → devops (PR).
- *AC*: §2 spec PQ subsection + §4 note + §11 open item committed; ADR-AWP-PQ-001 committed; README never-say list extended; `docs/post-quantum.md` created (EXPERIMENTAL banner, size cost, keyid convention).
- *Tests*: doc-lint / link-check; honesty-boundary phrasing assertions can be added in PQ-2.
- *Why first*: SVG-1 intent anchoring — the spec is the anchor every later story is cross-checked against.

**Story PQ-1 — `SignatureSuite` registry + ML-DSA-44 suite (`src/envelope/suites.ts`)**
- *AC*: registry with `ed25519` (wrapping existing Node path, zero behavior change) + `ml-dsa-44` (`@noble/post-quantum`, deterministic); `fingerprint()`, keyid convention encode/decode; `@noble/post-quantum` added to `package.json`.
- *Tests*: keygen/sign/verify per suite; deterministic known-answer vector; keyid round-trip; legacy-keyid⇒ed25519; size assertions (pub/sig lengths). ≥3/function, ≥80%.

**Story PQ-2 — Generalize envelope sign/verify (`src/envelope/dsse.ts`)**
- *AC*: `signEnvelope(record, signers[])` (1..N) over one PAE; `verifyEnvelope` evaluates each `signatures[]` entry via the registry; **existing single-Ed25519 signature path unchanged + all current envelope tests still green** (regression shield).
- *Tests*: hybrid PASS; legacy PASS unchanged; tampered-payload → both suites FAIL; per-suite reporting; the committed PASS/FAIL vectors from §1.6. Regression: full existing `test/envelope/*` suite must pass.

**Story PQ-3 — Verifier policy + `pq-posture` reporting (`src/verify/checks.ts`, `verify.ts`)**
- *AC*: `PqPolicy` (`off`/`advisory`/`required`, default advisory); classical-always-required rule; PQ-fail-always-fails rule; per-suite named check lines; always-printed `pq-posture` advisory line; threads PQ key(s) through `VerifyOptions`.
- *Tests*: the full §1.6 fixture matrix (hybrid PASS, legacy PASS-advisory/FAIL-required, tampered-PQ-only FAIL, PQ-stripped advisory-PASS/required-FAIL); honesty-line presence assertion. Regression: full `test/verify/*`.

**Story PQ-4 — CLI flags + sample + walkthrough (`src/cli/awp.ts`, `samples/`, `README.md`)**
- *AC*: `--pq-pubkey`, `--pq-require <off|advisory|required>` (mirrors `--tsa-*`); a committed hybrid `samples/receipt-pq.json` embedding its keys; README 10-minute walkthrough extended with a hybrid PASS + a PQ-tamper FAIL line; `docs/post-quantum.md` finalized with the real sample.
- *Tests*: CLI exit-code + named-failure tests (mirror `test/verify/cli.test.ts`); the byte-flip demo asserted.

**Final gate — @qa 2-pass 12-check on the whole feature + multi-lens Challenger on the integrated output → @devops single PR per the merge-authority chain.**

---

## 6. Prerequisite / wiring note (the one thing Renata must do)

**The night-shift runner is currently project-scoped to the paybot repos only** (`reference_paybot_runners_host`: 6 paybot repos; `project_awp_phase3_plan` notes awp lives at `RBKunnela/awp`). For the loop to execute this plan, **`RBKunnela/awp` must be added to the night-shift runner's repo scope** (host wrappers at `~/night-shift-host/`). Without that, the loop cannot check out / build / PR against `awp`.

**Keys/secrets needed (all TEST-only — no production keys in the open repo):**
- No new *infrastructure* secret is required for PQ itself — ML-DSA test keys are **generated in-process** by the suite (like the existing `createTestSigner`), and committed vectors use a **fixed 32-byte seed** so they are reproducible and contain no secret material worth protecting.
- The runner already has whatever git/PR credentials it uses for the paybot repos; the same must cover `awp`.
- (Standing, unchanged) the eIDAS/qualified-TSA vendor decision is **out of scope** for PQ — do not conflate.

---

## 7. Effort + sequencing

| Story | Effort | Depends on | Parallelizable? |
|---|---|---|---|
| PQ-0 (spec/ADR/docs) | S (~2-3h) | — | Yes — runs in parallel with PQ-1 |
| PQ-1 (suite registry) | M (~4-6h) | — | Yes — parallel with PQ-0 |
| PQ-2 (envelope sign/verify) | M (~4-6h) | PQ-1 | No — needs the registry |
| PQ-3 (verifier policy) | M (~5-7h) | PQ-2 | No — needs envelope multi-sig |
| PQ-4 (CLI + sample + docs finalize) | S-M (~3-5h) | PQ-3, PQ-0 | No — integrates everything |

**Critical path:** PQ-1 → PQ-2 → PQ-3 → PQ-4 (≈ 16-24h of agent work + Challenger/QA gates).
**Safely parallel:** PQ-0 (docs/spec/ADR) runs alongside PQ-1 from the start; they converge at PQ-4.
**Total (incl. gates):** ~3-4 night-shift cycles at MAX effort, gated by Challenger PASS at the plan and at each story.

---

## 8. What stays honest (the never-say list, extended for PQ)

In addition to AWP's existing never-say list (not "tamper-proof," not "we verify identities," not "legally authentic," not crypto-shredding-as-differentiator, not eIDAS-qualified-until-pinned, not Merkle/Ed25519/OTS as inventions), PQ adds:
- Never "quantum-proof," "quantum-safe in production," "future-proof," or "unbreakable."
- Never imply ML-DSA is mandated, certified, or carries qualified/eIDAS weight.
- Never present hybrid as "stronger than classical" without the caveat that PQ is EXPERIMENTAL and the guarantee is "no weaker than Ed25519 alone + an experimental PQ backstop."
- Always surface the `pq-posture` line so the experimental status is impossible to miss.
