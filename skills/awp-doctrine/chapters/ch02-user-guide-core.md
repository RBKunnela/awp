# Chapter 2: AWP user guide — core

## Core Idea
AWP lets **anyone** re-check a portable receipt offline without logging into a vendor console.

## Frameworks Introduced
- **Issuer → receipt file → verify**:
  - When to use: after any agent act that must be auditable.
  - How: platform issues receipt.json → `npx awp verify path`.
- **Honesty boundary table**: integrity-since-witness ≠ full real-world truth.

## Key Concepts
- **Receipt body**: the JSON (or pack) you keep; without it, verify does nothing.
- **Issuer**: witness service or payment platform that creates the body.
- **PASS/FAIL**: fail-closed chain (envelope, signature, schema, inclusion, checkpoint, anchor…).
- **Profiles**: pay, doc, principal, composite — not only money.

## Mental Models
- Think of AWP like **checksum + signature for agent acts**, not a bank.
- Think of the sample receipt as **unit test of the verifier**, not production eng evidence.

## Anti-patterns
- **Verify without a receipt**: installs package, expects magic — wrong layer.
- **Equating payment UI success with AWP PASS**: different checks until wired.

## Key Takeaways
1. Install AWP to verify; get receipts from an issuer.
2. One flipped byte → FAIL (integrity).
3. Multi-profile: docs and principals can be witnessed too.

## Connects To
- ch01 packaging
- ch03 PayBot trio
- ch04 chain internals
