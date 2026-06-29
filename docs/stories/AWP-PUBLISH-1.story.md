# Story AWP-PUBLISH-1 — Publish AWP (agent-witness-protocol) v0.2.0 to npm

**Status:** Validated — @po GO (10/10 checklist). Namespace + envelope decided. Ready for @dev; blocked only on 🔒 `awp.dev` registration + operator publish GO.
**Repo:** github.com/RBKunnela/awp (+ consumer: paybotfin-witness)
**Created:** 2026-06-29
**Source:** Roundtable (8 agents, unanimous PUBLISH-AFTER-GATES) + advisory-council (cognitive lenses) — see `AIOX-Enterprise/docs/paybot/PAYBOTFIN-AWP-WITNESS-CLAIMS-MAP.md` §9.
**Chain:** @sm draft → @po validate → @dev implement → @qa 12-check (2-pass) → @devops publish. Operator-gated steps marked 🔒.

---

## ✅ NAMESPACE DECIDED (operator, 2026-06-29)

**Permanent namespace = `https://awp.dev`** → `predicateType` + schema `$id` = `https://awp.dev/witness-record/v1`. **Irreversible once published.**
Chosen (neutral domain) per roundtable 5/8 + all 5 advisory lenses: keeps naming firewall, matches in-toto/SLSA/Sigstore, preserves the donate-to-foundation option. Brand stays on the hosted witness service, not the protocol.

**🔒 NEW OPERATOR DEPENDENCY (blocks Task 1):** register the `awp.dev` domain (~$15/yr). The namespace string does not need to resolve to be valid, but owning it prevents anyone else from claiming the identity and enables the future foundation/spec-site path.

## ✅ ENVELOPE DECIDED (two roundtables, 8 agents, unanimous, 2026-06-29)

**Keep DSSE/in-toto (JSON) as the normative envelope. Do NOT pivot to COSE_Sign1 / literal SCITT profile.** Stay "SCITT-aligned, not conformant." Rationale: a COSE pivot is architecturally incoherent (breaks in-toto verifier compat; AWP's value is the in-toto *predicate payload*, not the envelope) + 15-25 dev-days on a pre-RFC moving target for zero differentiation. Publish proceeds on DSSE as-is; namespace is envelope-agnostic. Report: `AIOX-Enterprise/docs/paybot/competitive/awp-scitt-envelope-roundtable-2026-06-29.md`; rationale in claims-map §9.

→ **Adds one doc task (Task 10): spec §9 migration gate** — define a *deferred, additive* COSE_Sign1 receipt export + the revisit trigger + the CTO-objection answer. Specified, not built.

---

## Story

**As** the AWP maintainer (FriendlyAI Oy),
**I want** AWP published to npm as `agent-witness-protocol` with its permanent namespace, CI, and release hardening,
**so that** anyone can `npm i` the offline verifier, the PayBot witness can depend on a real published package (not `file:../awp`), and the open→paid funnel has a credible, verifiable artifact.

## Semantic intent (SVG-1)
A stranger can install AWP and independently verify a witness receipt offline, with zero trust in PayBotFin; the wire identity is permanent and correct from v1; nothing ships that isn't gated by green tests.

---

## In scope
- Set permanent namespace `https://awp.dev/witness-record/v1` in schema `$id`, `PREDICATE_TYPE`, statement doc; **regenerate all signed fixtures/samples**.
- CI (GitHub Actions): lint → typecheck → build → test, as **required** status checks on `main`.
- Release hygiene: pkg metadata (`repository`/`author`/`homepage`/`bugs`), `CHANGELOG.md`, `prepublishOnly` build+test guard, version bump → **0.2.0** (namespace change is breaking).
- Security/legal hygiene: `SECURITY.md` + disclosure contact, `NOTICE` (FriendlyAI Oy), README namespace-≠-endorsement note, full-history secret-scan before public, pin `zod`.
- 🔒 Make repo public + first `npm publish --provenance` (@devops only, operator GO).

## Out of scope (follow-up stories)
- **AWP-PUBLISH-2:** repoint paybotfin-witness off `file:../awp` → `^0.2.0` + re-run 196/196 + E2E. (Separate consumer migration.)
- paybot-core AW-7/8 consumption; witness deploy; neutral-foundation governance.

---

## Tasks (ordered; effort from @dev/@devops)

1. **🔒 Lock namespace + claim npm name** (S) — operator sets `https://awp.dev`; `npm view agent-witness-protocol` to confirm unclaimed (404 = free); reserve `@paybotfin/awp` defensively.
2. **Set namespace in 3 source spots** (S) — `src/schema/witness-record.ts` `PREDICATE_TYPE`, `src/schema/witness-record.schema.json` `$id`, `src/envelope/statement.ts` doc. Landmine: `statement.ts:160` enforces `predicateType === PREDICATE_TYPE` (hard equality, fail-closed) → old-namespace receipts now fail.
3. **Regenerate signed sample + all fixtures** (M) — re-run the fixture generator (named in `samples/receipt.json` `_comment`); re-signs DSSE envelope AND recomputes `checkpoint_root`/inclusion (leaf hash changes). Landmine: any test asserting a literal root/leafHash/base64 payload breaks — fix those. Target: 368/368 green post-regen, 0 skip, **zero `placeholder.invalid` strings** (grep = 0).
4. **Add CI** (M) — `.github/workflows/ci.yml`: install → lint → typecheck → build → `vitest run`. Make required checks on `main`.
5. **Release hygiene** (S) — pkg metadata; `CHANGELOG.md` (0.2.0 entry: namespace finalized, first public release); `"prepublishOnly": "npm run build && npm test"`; bump version → 0.2.0.
6. **Security/legal files** (S) — `SECURITY.md` (disclosure contact, supported-versions, "verification is best-effort; integrity-since-witness only, NOT authenticity-at-origin/identity"); `NOTICE` (Copyright FriendlyAI Oy); README namespace-≠-endorsement sentence; confirm test fixtures use TEST keys only.
7. **🔒 Secret-scan full git history** (S) — gitleaks/trufflehog across all commits before public; abort if any real secret ever committed.
8. **Release pipeline** (S) — tag-triggered `v*`, `needs:` CI green, `npm publish --provenance` (OIDC, no long-lived token), **npm account 2FA**, signed git tag.
9. **🔒 Make repo public + first publish** (S) — @devops only, after operator GO + @qa PASS.
10. **Spec §9 migration gate** (S, doc-only — via the chain, NOT a code change) — add to `docs/spec/AWP-v0.1.md` §9: (a) a *deferred, additive* COSE_Sign1 receipt-export path; (b) the revisit trigger — "named customer requires COSE/SCITT **OR** SCITT reaches final RFC + conformance suite **OR** Q4-2026 review"; (c) the CTO-objection answer — a customer-keyed witness is deliberately not SCITT's always-online global registry, so "align ≠ conform" is a choice not a gap. Specified, not built. (Per 8-agent unanimous roundtable.)

---

## Acceptance criteria (@po)
1. **Given** a fresh machine with only npm, **When** `npm i -g agent-witness-protocol && awp verify samples/receipt.json`, **Then** `RESULT: PASS` offline with the honesty footer printed.
2. **Given** the published package, **When** any receipt is inspected, **Then** every `$id`/`predicateType` = `https://awp.dev/witness-record/v1` — **zero** `placeholder.invalid` (grep = 0).
3. **Given** a one-byte tamper of `samples/receipt.json`, **When** re-verified, **Then** `RESULT: FAIL` at the `signature` check, fail-closed.
4. **Given** regenerated fixtures, **When** `npm test`, **Then** 368/368 pass, 0 skip, re-signed samples.
5. **Given** a PR to the public repo, **When** CI runs, **Then** lint+typecheck+build+test are **required** checks blocking merge on red.
6. **Given** `npm i agent-witness-protocol` as a library, **When** importing subpaths `/schema /verify /envelope /anchor /log`, **Then** all resolve with shipped types.
7. **Given** the public repo, **When** a researcher finds a verify-bypass, **Then** `SECURITY.md` gives a disclosure path.
8. **Given** Apache-2.0 + `NOTICE` + README, **When** a third party emits a record bearing the namespace, **Then** docs state the namespace is a format identifier, not endorsement.
9. **Given** the published spec, **When** a reader asks "why not a literal SCITT profile?", **Then** §9 states the deliberate DSSE/in-toto choice + the deferred COSE-export migration gate + the revisit trigger.

## Definition of Done
All 8 AC green · @qa 2-pass PASS (12-check) · CI required & green · `SECURITY.md`+`NOTICE`+CHANGELOG present · secret-scan clean · 🔒 operator GO on namespace + public + first publish · package live on npm · AWP-PUBLISH-2 (witness repoint) filed.

## Risks
- **R1 (architect/dev, HIGH):** a receipt signed under the placeholder namespace escaping = permanent two-namespace fork (verify fails-closed). → Task 3 regen is the only re-sign path; grep-gate placeholder=0.
- **R2 (cyber, HIGH):** npm supply-chain takeover silently defeats every "verify-it-yourself" claim. → provenance + 2FA + pinned zod (Task 8).
- **R3 (legal, MED):** reliance liability (someone treats PASS as proof of authenticity). → in-code + `SECURITY.md` honesty boundary (Task 6).
- **R4 (analyst/pm, MED):** abandonware optics if PayBotFin is sole consumer. → CI + CHANGELOG + clean release signal it's a real project, not a stub.

## Wire-format versioning policy (architect — lock in CHANGELOG/README)
- npm SemVer (`0.2.0`…) = **code** axis (verifier fixes, additive schema).
- `/vN` in predicateType + `$id` = **wire-format breaking-change** axis; `/v1` is frozen at first publish.
- Adding a claim-class enum value = additive/safe; removing one = breaking → `/v2`.
