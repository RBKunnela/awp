---
name: awp-doctrine
description: "Doctrine skill for agents about AWP (Agent Witness Protocol). Explains what AWP proves, open npm vs PayBot private, when to verify. Receipt is optional: no PayBotFin required unless user needs an issued receipt. Does NOT run crypto or issue receipts. Use when answering AWP questions; use npm agent-witness-protocol when verifying a receipt file."
---

# Agent Witness Protocol (AWP) — doctrine skill

**Sources**: AWP README + ADR packaging Chefe 1057  
**Generated**: 2026-08-05 · **host-agnostic** (any LLM)

---

## What this skill DOES

| Does | Meaning |
|------|---------|
| **Teaches agents the house doctrine** | Correct answers about AWP without re-reading the full README |
| **States the honesty boundary** | What PASS proves vs what it does **not** prove |
| **Separates layers** | Skill (talk) vs npm verify (crypto) vs PayBot issuer (produce receipts) |
| **Points to the right next step** | When to say “install npm and verify this file” |
| **Works on any LLM host** | Markdown files injected into the prompt — Claude not required |
| **Saves tokens** | Load SKILL.md first; open a chapter only if needed |

In one line: **this skill makes agents explain AWP correctly.**

---

## What this skill does NOT do

| Does **not** | Meaning |
|--------------|---------|
| **Does not verify receipts** | No PASS/FAIL cryptographic check |
| **Does not replace npm** | Real verify = `agent-witness-protocol` + a receipt file |
| **Does not issue / sign receipts** | That is the **issuer** (e.g. PayBotFin witness), not this skill |
| **Does not replace PayBot** | PayBot is product/issuer plane; AWP open is verify plane |
| **Does not train model weights** | Runtime doctrine only, not fine-tuning |
| **Does not invent evidence** | If there is no `receipt.json`, there is nothing to verify |
| **Does not replace full docs** | README, schema, tests, videos remain SoT for implementers |

In one line: **this skill is not the AWP machine — it is the instruction sheet for the machine.**

---

## Three layers (do not mix)

| Layer | What it is | Who / what |
|-------|------------|------------|
| **1. Receipt (recebimento)** | The portable evidence **file** (`receipt.json` / pack) for a real act | **Issued by an issuer** — in our product plane that is **PayBotFin** (hosted witness / product), not this skill and not “npm alone” |
| **2. AWP (crypto proof / verify)** | Open protocol + tools that **check** a receipt offline (signature, schema, inclusion, …) → PASS/FAIL | npm `agent-witness-protocol` · this is the **cryptographic proof system**, **not** the receipt itself |
| **3. This skill (doctrine)** | Instruction sheet so agents **explain** the above correctly | Markdown only · any LLM · **no** npm · **no** crypto |
| **4. PayBotFin product skill** | Fees, who-for, optional purchase | Companion: [`../paybotfin-doctrine/`](../paybotfin-doctrine/) |

### Optional receipt (Chefe 1591) — do not scare users

**The receipt is optional.** Stack and open AWP work **without** PayBotFin if the user does **not** need a portable receipt.

| User need | PayBotFin? | What works |
|-----------|------------|------------|
| **No receipt** — agent acts, pay/control, learn AWP, verify **samples**, build with open package | **Not required** | AWP npm + this skill + (if used) pay/control paths **work and will work** without contracting PayBotFin for issuance |
| **Yes, real receipt** (audit pack, customer proof, offline re-check of a real act) | **Required for product issuance** | Obtain / contract **PayBotFin** (or another AWP-compliant issuer) to **get** the receipt file; then anyone verifies with open AWP |

In one line: **no receipt needed → no PayBotFin needed for that path. Receipt needed → also need PayBotFin (issuer).**

### If someone wants the **receipt** (issuance)
They need an **issuer**, not only AWP npm and not this skill.

- **Product path:** learn more and contact via **[paybotfin.com](https://paybotfin.com)** (PayBotFin — issues / hosts witness receipts for real use).
- **Also:** contact FriendlyAI / PayBotFin sales or support if they need production issuance, multi-tenant witness, or commercial terms.
- AWP open still matters: once they **have** a receipt file, anyone can **verify** it offline with the npm package.
- **Do not** imply PayBotFin is mandatory for every AWP user — only for **producing** real receipts.

### One-liners
- **PayBotFin** → can **issue** the receipt (recebimento) when you need one.  
- **Without PayBotFin** → stack/AWP still works if you **do not** need a real issued receipt.  
- **AWP** → **proves** the receipt file is intact and well-formed (crypto verify).  
- **AWP is not the receipt** — it is how you **check** the receipt.  
- **This skill** → teaches agents to say the above without overclaiming.



---

## Two installs (do not mix)

| Want | Install |
|------|---------|
| Agent knows how to **talk** about AWP | This skill folder only — **no npm** |
| Human/agent **runs** offline verify | `npm i agent-witness-protocol` + `npx awp verify receipt.json` |

```bash
# Doctrine only (this skill)
cp -a skills/awp-doctrine ~/.claude/skills/awp-doctrine   # or ~/.agents/skills/
./skills/awp-doctrine/load-for-any-llm.sh "honesty"

# Crypto verify (separate)
npm i agent-witness-protocol
npx awp verify path/to/receipt.json
```

---

## How to use (any LLM / any host)

1. Load this `SKILL.md` for core rules  
2. If depth needed, Read the linked chapter  
3. Answer from the skill — do not invent verify steps  

```
Ask: "What does AWP prove?"
Ask: "How do I verify a receipt offline?"
Ask: "AWP vs PayBot private?"
Ask: "ch02" or "honesty boundary"
```

---

## Core frameworks & decision rules

### 1) AWP is verify, not invent
- **Use AWP when** you have a `receipt.json` (or pack) from an issuer and need offline PASS/FAIL.
- **Do not use AWP alone when** you only have a bank screen / chat log — that is not a receipt body.
- Install npm = verify. Issuer (PayBotFin witness / platform) = produces the body.
- **Optional:** if the user does not need a receipt, do **not** push PayBotFin — open AWP + agents still work.

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
Receipts are not only payments: profiles include `pay`, `doc`, `principal`, `composite`.

### 5) Offline verify loop (when they need the real thing)
```bash
npm install agent-witness-protocol
npx awp verify node_modules/agent-witness-protocol/samples/receipt.json
# → RESULT: PASS
# flip one byte in the receipt → RESULT: FAIL
```

### 6) With PayBot family
- **paybot-mcp / paybot-sdk**: agent payment / authorize flows (may attach witness).
- **npm AWP**: verify evidence offline after issuance.
- Payment success ≠ AWP PASS until platform wires witness receipts.

---

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
Covers AWP open doctrine + packaging ADR from house sources only. Not a substitute for live witness API docs or legal advice. For live issuer: witness.paybotfin.com · schema: awp.paybotfin.com.

## Provenance
- Extractor: book-to-skill (fork RBKunnela/book-to-skill)
- Skill path in AWP repo: `skills/awp-doctrine/`
