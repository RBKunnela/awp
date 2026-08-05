# Patterns — AWP doctrine

## Offline demo without issuer account
**When to use**: show AWP works in 60s.  
**How**: `npx awp verify` on the sample shipped in the package.  
**Trade-offs**: proves verifier, not a real customer eng.

## Issue-then-verify
**When to use**: production-like dogfood.  
**How**: act via PayBot path → obtain receipt → verify offline.  
**Trade-offs**: needs issuer wiring; not always on by default.

## Doctrine skill load (this skill)
**When to use**: any agent (Grok, GPT, local, Claude, Copilot) answering AWP questions.  
**How**: host loads SKILL.md; opens chapter only if needed.  
**Trade-offs**: skill must be updated when docs change (fold-in).
