---
name: awp-doctrine
description: "Knowledge base from AWP (Agent Witness Protocol) open docs + packaging ADR. Use when verifying agent receipts, explaining what AWP proves vs does not prove, integrating paybot-sdk/mcp with offline verify, or packaging open AWP vs private PayBot."
---

## What this skill is (and is not)

| This skill (doctrine) | AWP npm (`agent-witness-protocol`) |
|----------------------|-------------------------------------|
| Markdown for **agents** to answer correctly | Cryptographic **verify** tool |
| No crypto, no PASS/FAIL | Needs install + a `receipt.json` |
| Explains honesty boundary & packaging | Runs `npx awp verify` |

**Any LLM host** can load these files. Claude not required.

# Agent Witness Protocol (AWP) — doctrine skill
**Sources**: AWP README + ADR-AWP-OSS-PAYBOT-PRIVATE (Chefe 1057)  
**Generated**: 2026-08-05 | **Method**: book-to-skill extract + structured skill (host-agnostic)  
**Tokens**: load SKILL.md first; open chapter files only when needed

## How to use (any LLM / any host)

This is **not Claude-only**. Any agent that can read files:
1. Load this `SKILL.md` for core rules
2. If the question needs depth, `Read` the linked chapter file
3. Answer from the skill — do not invent verify steps

```
Ask: "What does AWP prove?"
Ask: "How do I verify a receipt offline?"
Ask: "AWP vs PayBot private?"
Ask: "ch02" or "honesty boundary"
```

## Core frameworks & decision rules

### 1) AWP is verify, not invent
- **Use AWP when** you have a `receipt.json` (or pack) from an issuer and need offline PASS/FAIL.
- **Do not use AWP alone when** you only have a bank screen / chat log — that is not a receipt body.
- Install = verify. Issuer (PayBotFin witness / platform) = produces the body.

### 2) Honesty boundary (what PASS means)
| Proves | Does **not** prove |
|--------|---------------------|
| Receipt consistent + correctly signed | Authenticity of the original real-world act |
| Unaltered since witnessed | Human identity |
| Inclusion in signed log + time bound (when present) | Completeness (“every action was recorded”) |
| Integrity-**since-witness** | Vendor console honesty without the file |

### 3) Packaging lock (Chefe 1057)
- **AWP open** (`agent-witness-protocol`) = public verify package.
- **PayBot private** = product issuer / hosted witness / commercial plane.
- **Do** publish verify + samples + schema.
- **Do not** conflate “npm install AWP” with “production witness of the world.”

### 4) Multi-profile
Receipts are not only payments: profiles include `pay`, `doc`, `principal`, `composite` (see chapter files / README).

### 5) Offline verify loop
```bash
npm install agent-witness-protocol
npx awp verify node_modules/agent-witness-protocol/samples/receipt.json
# → RESULT: PASS
# flip one byte in the receipt → RESULT: FAIL
```

### 6) With PayBot family
- **paybot-mcp / paybot-sdk**: agent payment / authorize flows (may attach witness).
- **This skill + awp CLI**: verify evidence offline after issuance.
- Payment success ≠ AWP PASS until platform wires witness receipts.

## Chapter index

| # | Title | When to load |
|---|-------|----------------|
| [ch01](chapters/ch01-packaging-adr.md) | AWP open / PayBot private packaging | OSS vs product boundary |
| [ch02](chapters/ch02-user-guide-core.md) | User guide — what AWP is / is not | Install, verify, honesty |
| [ch03](chapters/ch03-integration-paybot.md) | Integration with paybot-sdk / mcp | Stack wiring |
| [ch04](chapters/ch04-receipt-chain.md) | Receipt chain & WitnessRecord | Crypto/log/anchor mental model |

## Topic index
- **receipt body / receipt.json** → ch02  
- **npx awp verify** → ch02  
- **honesty boundary** → ch02  
- **PayBot private vs AWP open** → ch01  
- **paybot-sdk / paybot-mcp** → ch03  
- **DSSE / inclusion / checkpoint / anchor** → ch04  
- **profiles pay/doc/principal** → ch02  

## Supporting files
- [glossary.md](glossary.md)
- [patterns.md](patterns.md)
- [cheatsheet.md](cheatsheet.md)

## Scope & limits
Covers AWP open doctrine + packaging ADR from house sources only. Not a substitute for live witness API docs or legal advice. For live issuer URLs: witness.paybotfin.com · awp.paybotfin.com schema.

## Smoke provenance
- Extractor: `book-to-skill` (fork RBKunnela/book-to-skill) `scripts/extract.py`
- Workdir: `/tmp/book_skill_work_awp/`
- Host: **any LLM** — skill is markdown files
