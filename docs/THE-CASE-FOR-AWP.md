# The Case for AWP (Agent Witness Protocol)

> **What this is:** the honest strategic case for AWP — why it exists, what it is and isn't, what's defensible, and why it's worth publishing. Grounded entirely in verified research; no claim here without a source.
>
> **Date:** 2026-06-29 · **Author:** Renata Baldissara-Kunnela · **Status:** case for decision
> **Sources:** `AIOX-Enterprise/docs/paybot/PAYBOTFIN-AWP-WITNESS-CLAIMS-MAP.md` (§1-9); novelty audit `competitive-landscape-2026-06-15.md`; teardown §5b `docs/paybot/competitive/vanta-scytale-teardown-2026-06-29.md`; envelope roundtable `docs/paybot/competitive/awp-scitt-envelope-roundtable-2026-06-29.md`; `awp/docs/spec/AWP-v0.1.md`; live verification (368/368 tests, `awp verify` PASS/tamper-FAIL).

---

## 1. Thesis (one paragraph)

AWP is **not novel cryptography — and it never claimed to be.** It is a careful *composition* of mature, off-the-shelf standards (DSSE/in-toto for the signed envelope, RFC 9162 for the transparency log, OpenTimestamps/RFC 3161 for time anchoring, Ed25519/SHA-256 for primitives). Roughly **80% of AWP is commodity.** Its worth is the **20% nobody else owns**: a typed *witness record* for governed agent actions — *who authorized it, what was verified, with a closed honesty boundary* — that anyone can re-verify **offline, with zero relationship to the producer.** That 20%, plus the **operating model of a neutral third-party witness**, is the defensible asset. The case for AWP is therefore not "we invented a protocol" — it's "we built the honest, interoperable receipt + we operate the neutral witness that issues it."

---

## 2. What AWP is (plainly)

A `WitnessRecord` is one structured, signed record of a governed agent event: the **intent** (what the agent set out to do), the **authorization** (the credential that permitted it + what was verified about that credential), the **artifacts** (by hash, never content), and the witness's **typed testimony** about each thing it checked. It ships as:
- an **open JSON Schema** (the contract any language can validate against),
- a **signed DSSE/in-toto envelope** so the record travels intact,
- an **RFC 9162 transparency-log** layer (Merkle inclusion proofs + signed checkpoints),
- external **time anchors** (OpenTimestamps now; RFC 3161/eIDAS qualified TSA planned),
- an offline **`awp verify` CLI + library** that checks a receipt end-to-end.

**Verified, live:** clean receipt → `RESULT: PASS` (11 checks, offline); flip one byte → `RESULT: FAIL`, fail-closed. 368/368 tests, 0 skips.

## 3. The honesty boundary (this is a feature, legally and commercially)

AWP proves **integrity-since-witness only** — that a record is internally consistent, correctly signed, and unaltered since it was witnessed. It explicitly does **NOT** prove authenticity-at-origin, completeness, or identity. This boundary is enforced in *types and verifier output*, not just prose (closed `claim_class` enum; an overclaim like `verified-against` with a non-`pass` result fails verification; every report prints the boundary). No competitor we surveyed has this typed honesty boundary. It is also the primary defense against reliance-liability.

---

## 4. The honest novelty position (credibility through candor)

Our own 2026-06-15 audit reached this before we did, independently. **The same protocol substrate already exists:**

| Layer | AWP uses | Already-existing standard | AWP's claim |
|-------|----------|---------------------------|-------------|
| Signed envelope | DSSE + in-toto Statement | in-toto (CNCF graduated) | **adopt** |
| Transparency log | RFC 9162 raw-byte Merkle | RFC 9162 / Cert Transparency | **adopt** |
| Checkpoints | C2SP `tlog-checkpoint` | C2SP | **adopt** |
| Time anchor | OpenTimestamps / RFC 3161 | OTS / eIDAS | **adopt** |
| Primitives | Ed25519, SHA-256 | — | **adopt (no new crypto)** |
| Adjacent full-stack standard | — | **IETF SCITT** (Signed Statements + Receipts + Transparency Service, offline-verifiable) | **align, not conform** |

Adjacent products already ship pieces of AWP's value *today*: in-toto (predicates), Google AP2 + Coinbase x402 ("a human authorized this agent payment"), AgentSystems "Notary" (commercial), agentstamp (OSS), and **VeritasChain/VCP** — a more-mature SCITT financial-audit-trail profile draft. **The spec is honest about all of this** (Appendix A is literally titled "Composition, not invention"; §9 says "ALIGN ≠ conform").

**So why build it, not just adopt?** Three honest reasons, descending legitimacy:
1. **A real net-new fix in our own stack:** AWP added a transparency log + external time anchor that paybot-core lacked (the "no absolute timestamp" gap) — genuine engineering, using off-the-shelf primitives.
2. **A working implementation buys traction + control** (368/368 green) even when the spec isn't novel.
3. **A framing error** ("a new protocol / the Incorruptible Witness") that the audit caught and the spec corrected.

**The verdict: we DID adopt the commodity 80%; the genuine effort went into the un-owned 20%.** That is the right place to have spent it.

## 5. The defensible 20% (the actual moat)

1. **Neutral third-party witness topology.** Almost every shipping competitor is *self-hosted self-attestation* — agentstamp's own author admits that's "documentation, not evidence." A truly neutral, non-colluding witness (you cannot witness your own actions and claim independence) is the differentiator — **if you operate the independent infrastructure.** This is an *operating model*, not a protocol.
2. **The typed honesty boundary** (integrity-since-witness ≠ verified-against ≠ asserted-by) — found in no competitor.
3. **Verified-human-authorizes-agent-action** bound into the record (principal binding).
4. **eIDAS-qualified time** path (regulated-grade timestamping).

None of these live in the envelope bytes. All survive any future format change. **The moat is the neutral position + the witness semantics — never the wire format.**

---

## 6. Standards positioning — DSSE now, SCITT-aligned, COSE deferred (DECIDED)

Two independent roundtables (8 agents, **unanimous, zero dissent**) decided: **keep the DSSE/in-toto envelope; do not pivot to SCITT's COSE_Sign1.** Reasons: a pivot is architecturally incoherent (a "chimera" breaking in-toto verifier compatibility — the value is in the *predicate payload*, not the envelope), costs 15-25 dev-days rewriting 368 tests on a pre-RFC moving target, and adds zero product value. DSSE also wins native multi-signature (human + agent co-signing) and stays hand-auditable (JSON, not CBOR). **SCITT becomes relevant only if a real customer demands it — then it's a small additive export adapter (~3-5 days), not a rebuild.** Captured as a spec §9 migration gate + trigger; nothing to build now. (Competitor VCP made the same composition call and also avoided COSE — using RFC 6962 — signal the market hasn't converged on SCITT-COSE.)

## 7. The open / paid split (why publishing helps, not cannibalizes)

- **Open (Apache-2.0):** the `WitnessRecord` schema + the `awp verify` reference verifier + SDK. Generic name `agent-witness-protocol`; neutral namespace `https://awp.dev/witness-record/v1`. CC-BY-4.0 on the spec document (authorship: Renata Baldissara-Kunnela).
- **Paid (proprietary):** the production engine + the **operated neutral witness service** (PayBotFin) that issues receipts at scale, multi-tenant, with metering/billing and hosted assurance.
- **Why it compounds:** AWP is the verifier customers use to **independently check our hosted receipts offline** — so the more AWP spreads, the more "AWP-verifiable receipt" becomes a recognized artifact, and the neutral hosted witness is its natural supplier. Giving the verifier away *enables* the paid service. Naming firewall enforced in code (`naming-firewall-local.test.ts`).
- **Concrete dependency:** the witness today depends on AWP via a local `file:../awp` path — it **cannot deploy elsewhere until AWP is published.** Publishing unblocks the product.

## 8. Value, honestly rated

- **AWP → open-source community: 6/10.** Artifact quality ~9, but OSS value = quality × adoption-readiness × neutrality, and the last two are early. The schema + typed honesty boundary + offline-verify property are a genuine, clean contribution; realistic upside is "respected niche utility," not "de-facto standard," unless a neutral steward (foundation) adopts it. Abandonware risk if PayBotFin stays the sole user.
- **Witness service → PayBotFin: 7/10.** Strategically central — the only defensible position — but the moat is *trust/positioning + operating the neutral infra*, not the (replaceable) code. Necessary-but-not-sufficient; the gap to a sellable hosted product is large (undeployed, no self-serve/billing yet).

## 9. Risks & where the real energy belongs

| Risk | Note |
|------|------|
| Publishing the placeholder namespace would freeze a wrong wire format forever | Mitigated: namespace decided `awp.dev`, fixtures regenerated via the chain (story AWP-PUBLISH-1). |
| npm supply-chain takeover defeats every "verify-it-yourself" claim | provenance + 2FA + pinned deps (story). |
| Reliance liability (PASS treated as proof of authenticity) | in-code + SECURITY.md honesty boundary. |
| Abandonware optics if sole consumer | CI + CHANGELOG + clean release signal a real project. |
| **The real risk (per @architect):** adversarial-audit robustness of the principal-binding model + landing the **first design partner** | This — not the envelope — is where effort should go. |

## 10. The ask (decisions for Renata)

1. **Publish AWP** as `agent-witness-protocol` v0.2.0 (Apache-2.0) on the `awp.dev` namespace — via story `AWP-PUBLISH-1` (validated, @po GO). 🔒 Gated on: register `awp.dev`, make repo public, first `npm publish`.
2. **Keep DSSE/in-toto; no code change** (decided). Add the spec §9 migration gate via the chain.
3. **Point energy at the 20%:** harden principal-binding against adversarial audit + land the first design partner. That is the moat; the bytes are commodity.

---

*Bottom line: AWP is honest composition with a small, genuinely-owned core. Don't sell it as new cryptography — sell the neutral witness that issues an honest, independently-verifiable receipt. Publish the verifier, operate the witness, and spend the real effort on the 20% that's yours.*
