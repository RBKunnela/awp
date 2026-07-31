# TICKET-AWP-MULTI-PROFILE-EMIT-001 — Emit AWP profiles beyond `pay`

| Field | Value |
|-------|--------|
| **ID** | TICKET-AWP-MULTI-PROFILE-EMIT-001 |
| **Status** | **DONE** (lab dogfood + witness multi-profile) · Chefe **1072** |
| **Opened** | Chefe **1069** |
| **Closed** | 2026-07-31 Chefe **1072** |
| **Repos** | paybotfin-witness · paybot-core · agent-witness-protocol |

## Problem
Protocol multi-profile existed; issuance was pay-first; no full `awp verify` samples for doc/principal/composite.

## Delivered (1072)

| AC | Result |
|----|--------|
| 1 Mapping table | `paybot-core/docs/tickets/AWP-MULTI-PROFILE-MAPPING-AND-EMIT.md` + `profile-mapping.ts` |
| 2 Witness multi-profile | `resolveWitnessProfile` — honor `record.profile` if in `allowed_profiles`; else 403 |
| 3 Dogfood per profile | `samples/receipts/{pay,doc,principal,composite}.json` |
| 4 `npx awp verify` PASS | **4/4 PASS** offline (generated + verified on Hetzner) |
| 5 Core integration note | mapping doc §2–3; authorize emit still compact bag (honest defer for full schema) |
| 6 No overclaim | integrity-since-witness only |
| 7 Links | AWP README §9 updated |

## Tests
- paybotfin-witness: multi-profile POST integration (pay/doc/principal/composite) + profile_not_allowed 403
- AWP: gen script `npm run gen:multi-profile-receipts`

## Not claimed
- Production Cloudflare every-action closed loop
- authorize_allow already a full WitnessRecord (still compact bag until follow-up)

## References
- tools/generate-multi-profile-receipts.mjs
- witness.route.ts resolveWitnessProfile
- Chefe 1066 · 1069 · 1072
