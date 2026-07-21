# AWP namespace domain options (Cloudflare inventory)

**Date:** 2026-07-21  
**Account:** Cloudflare FriendlyAI  
**Wire namespace in code today:** `https://awp.paybotfin.com/witness-record/v1`  
**Why not `.dev`:** many enterprise networks block or distrust `.dev` TLDs.  
**Why not `paybotfin.awp.com`:** that requires owning apex **`awp.com`** (registered by a third party; not in FriendlyAI Cloudflare). Correct ownership order is **`awp.` + your apex** → `awp.paybotfin.com`.

The predicate string does **not** need to resolve for verification to work. Ownership prevents identity capture and enables a future foundation / spec site.

---

## A) Domains you already own (Cloudflare zones) — usable now

Pick one and use either the apex or a subdomain as the public protocol home / `$id` host.

| Domain | CF plan | Fit for AWP | Suggested wire / site |
|--------|---------|-------------|------------------------|
| **friendlyai.fi** | Enterprise | **Best owned option** (company root, least product-branded) | `https://awp.friendlyai.fi/witness-record/v1` |
| **aiagentsprompt.com** | Enterprise | Acceptable neutral-ish | `https://awp.aiagentsprompt.com/witness-record/v1` |
| **paybotfin.com** | Enterprise | Weak (product brand — naming firewall) | Prefer only if product-scoped receipts |
| **paybotcore.com** / **paybot-core.com** | Free | Weak (product brand) | Avoid for open protocol |
| **agentictestari.com** | Free | Product brand | Avoid for open protocol |
| **getaiwatch.com** | Free | Unrelated product | Possible only if rebranded |
| **graph-files.com**, **llmhitch.com** | Free | Unrelated | Not recommended |
| **autovaultclaw.com**, **metasocialclaw.com**, **payclawd.com** | Free | Unrelated claw brands | Not recommended |

### Hostinger portfolio (also yours, not all on CF)

Includes `friendlyai.fi`, `friendlyaiagent.com`, `agenticfriendlyai.com`, `openbrainspark.io`, and others. Same rule: prefer neutral protocol naming over product brands.

---

## B) Not owned — do not claim

| Domain | Status |
|--------|--------|
| **awp.dev** | Registered elsewhere (NS: GoDaddy). Live HTTP 200. **Not yours on CF.** |
| **agentwitness.dev** | Registered (CF nameservers, **not** this FriendlyAI CF account) |
| **awp.fi**, **awp.app**, **agentwitness.com** | Registered |

---

## C) Likely available to register (RDAP 404 — verify at registrar before buy)

| Candidate | Notes |
|-----------|--------|
| **agent-witness.dev** | Strong match to package name |
| **awprotocol.dev** | Short protocol brand |
| **awp-protocol.dev** | Explicit |
| **witness-protocol.dev** | Longer, clear |
| **agentwitness.org** | Org TLD option |
| **agent-witness.com** | Com option |
| **awpreceipt.com** | Product-y |
| **agentwitness.fi** | .fi if available for FI entity |

---

## Recommendation

1. **If you want permanent neutral wire ASAP without buying:** switch namespace to  
   `https://awp.friendlyai.fi/witness-record/v1`  
   (you control DNS today) and re-run `npm run regen:fixtures` + tests.  
2. **If you want category-leading neutral brand:** register **`agent-witness.dev`** or **`awprotocol.dev`**, add the zone to Cloudflare, then set wire to  
   `https://agent-witness.dev/witness-record/v1` (or chosen host).  
3. **Do not leave marketing claiming you “own awp.dev”** until the registrar account proves it.

Reply with your pick (e.g. `awp.friendlyai.fi` or `agent-witness.dev`) and the wire will be switched + fixtures regenerated in one pass.
