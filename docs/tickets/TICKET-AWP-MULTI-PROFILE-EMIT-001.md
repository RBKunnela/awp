# TICKET-AWP-MULTI-PROFILE-EMIT-001 — Emit AWP profiles beyond `pay`

| Field | Value |
|-------|--------|
| **ID** | TICKET-AWP-MULTI-PROFILE-EMIT-001 |
| **Status** | **OPEN** |
| **Chefe** | GO **1069** (after 1066 multi-profile Q) |
| **Repos** | paybotfin-witness · paybot-core · agent-witness-protocol (verify already multi-profile) |
| **Accept brain** | Chefe product · Pedro executes |
| **Date** | 2026-07-31 |

## Problem

AWP protocol already supports profiles **`pay` · `doc` · `principal` · `composite`** (schema + `validateProfile` + OSS verify).  
Origin story was PayBot **payments**; product vision now is **any governed agent action** (docs, principal-bound acts, composite e-commerce).

Gap is **issuance**, not redesign of the wire:

- OSS samples: full crypto bundle `samples/receipt.json` is pay-shaped; predicate samples for all 4 profiles are in `agent-witness-protocol/samples/profiles/` (Chefe 1069).
- Witness service has `allowed_profiles` / `profile` on leaves but defaults and production paths still **pay-first**.
- paybot-core does not yet systematically attach AWP receipts for non-pay actions (doc generate, principal-bound authorize, composite).

## Goal

Platform can **issue** valid AWP receipt bundles for all four profiles so a customer can:

```bash
npx awp verify ./receipt-doc.json   # etc.
```

with honest profile minimums and honesty boundary intact.

## Acceptance criteria

1. **Mapping table** (doc in this ticket or ADR): which PayBot/Core events → which AWP profile + example `intent.action` verbs.
2. **Witness** accepts and signs leaves for `doc`, `principal`, `composite` when tenant `allowed_profiles` permits (not only `pay`).
3. **At least one dogfood path per profile** (lab/DEV OK):
   - pay (already closest)
   - doc (e.g. credit-note / report artifact by hash)
   - principal (intent-bound credential)
   - composite (pay+doc scene)
4. Each path produces a file that **`npx awp verify` → PASS** (full bundle, not predicate-only).
5. **paybot-core** integration note: where emission is hooked (authorize/settle/doc/action) vs deferred.
6. No overclaim: integrity-since-witness only; no “all agent actions in production” until closed loop proven.
7. Links updated: AWP README multi-profile § already points here.

## Out of scope

- Redesigning WitnessRecord schema  
- SCITT/COSE pivot  
- Opening paybot-core OSS  
- Bank dual-control / GA Protect language  

## Dependencies

- `agent-witness-protocol` (npm) — consume published package, not `file:` long-term  
- ADR AWP OSS / PayBot private (Chefe 1057)  
- Vision 1000 ledger (every-action leaves = later wave; this ticket is emission profiles)

## Suggested owners

| Slice | Owner |
|-------|--------|
| Profile→event mapping + dogfood fixtures | Pedro |
| Witness multi-profile sign path | Pedro / AIOX (paybotfin-witness) |
| Core attach points | Pedro (paybot-core) |
| Commercial language | Maia after evidence |

## References

- AWP profiles: `awp/src/schema/profiles.ts` · spec § profiles  
- Samples: `awp/samples/profiles/`  
- Chefe 1066 (Q) · 1069 (GO)
