# ADR — AWP open source / PayBot private packaging

| Field | Value |
|-------|--------|
| **Status** | **LOCKED** · Chefe **ACCEPT + GO 1057** |
| **Date** | 2026-07-31 |
| **IDs** | Chefe 1050 (question) · 1053 (RT+AC) · **1057 (ACCEPT+GO)** |
| **Validation** | AC-2026-07-31-1053 **PROCEED 8.6** · RT-2026-07-31-1053 **DECIDED Option A 8.5** |
| **Parent vision** | Chefe **1000** (LAG + AWP + PayBot ledger moat) · `THE-CASE-FOR-AWP` §7 |

---

## Decision (normative)

1. **AWP** (Agent Witness Protocol: WitnessRecord schema, envelopes, reference offline verifier `awp verify`, SDK) remains **open source** under **Apache-2.0** (package `agent-witness-protocol`).
2. **PayBot / PayBotFin production engine** (facilitator, governance, multi-tenant **witness issuance service**, metering/billing, key custody paths) remains **private** and is sold as a **hosted** product (and later optional enterprise deployment under separate contract — not a free dump of core).
3. **Do not** close, unpublish, or dual-license-retract AWP to “prevent cloning.” Clone friction of the wire format is not a moat.
4. **Public clients OK:** `paybot-sdk`, `paybot-mcp`, docs that teach verify + integrate — without shipping private issuance guts.

---

## Rationale (one screen)

| Layer | Stance | Why |
|-------|--------|-----|
| Schema + offline verify | **OSS** | Independent re-check is the product claim (“evidence, not diary”). Closed verify = self-attestation optics + liability risk. |
| Neutral multi-tenant witness ops | **Private / paid** | Topology, keys, SLAs, tenancy, metering = scarce goods. |
| Wire format secrecy | **Not a moat** | ~80% is DSSE/in-toto, RFC 9162, OTS/RFC 3161 — commodity either way. |
| Full stack (Core · LAG · Sight · Protect) | **Private / product lines** | System integration + honesty policy is the durable differentiator (vision 1000). |

Industry pattern (CT, Sigstore, in-toto, SCITT, open client / closed service): open verification surfaces; monetize operation and productization.

---

## Consequences

### Do

- Keep npm `agent-witness-protocol` public, tested, honesty boundary in verifier output + SECURITY.md.
- Issue pilot receipts from **private** witness; customers verify with **public** `npx awp verify`.
- Energy: first **design partner**, principal-binding hardening, dogfood closed loop (material action → leaf → offline pack).
- Naming firewall: OSS does not brand as “PayBot-only”; neutral protocol name.

### Do not

- Reverse Apache-2.0 for published AWP artifacts.
- Open `paybot-core` / production witness engine early.
- Claim “we replaced SIEM” or bank GA until every-action ledger loop + Chefe product accept.
- Sell Protect external SKU language before W7 retro + Chefe GO (separate lock).

---

## Options considered (and rejected)

| Option | Result |
|--------|--------|
| **A** AWP open + PayBot private | **ACCEPTED** (unanimous RT + AC) |
| **B** Close AWP anti-clone | Rejected — kills independent evidence |
| **C** Open PayBot core too | Rejected — premature |
| **D** Freeze docs/npm after open | Rejected — theater post 0.2.0 |

---

## SoT / links

- This ADR · mirror: `sentinel-agentic-lab/docs/decisions/` + validation verdicts  
- Case: `awp/docs/THE-CASE-FOR-AWP.md` §7  
- Verdict: `docs/validation/2026-07-31-VERDICT-AWP-OSS-PAYBOT-PRIVATE-1053.md`  
- Vision: handoff / decision **1000** LAG+AWP+PayBot  

**Accept brain:** Chefe only. Pedro executes packaging boundaries; Maia consolidates commercial language.

— Pedro · Chefe **1057**
