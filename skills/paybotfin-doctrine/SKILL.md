---
name: paybotfin-doctrine
description: "Doctrine skill for agents about PayBotFin product: what it is, public pricing, who it is for, optional vs required for receipts. Not compulsory for AWP. Does NOT bill or issue receipts itself. Use when explaining PayBotFin commercially or when a user asks about fees / need for witness."
---

# PayBotFin — product doctrine skill

**Sources**: paybotfin.com public list (Chefe 3779) · AWP packaging (Chefe 1057) · optional-receipt (Chefe 1591/1594)  
**Generated**: 2026-08-05 · **host-agnostic** (any LLM)

---

## What this skill DOES

| Does | Meaning |
|------|---------|
| **Teaches what PayBotFin is** | Neutral **hosted witness / product** plane for AI-agent actions |
| **States public pricing** | Free verify vs paid Pro / Enterprise (list from paybotfin.com) |
| **Says who it is for** | Fintech, gov, AI platforms, auditors — when proof matters |
| **Optional vs required** | **Not compulsory** for AWP; required only if user needs **issued receipts** |
| **Explains the receipt** | What it is and **why** someone would need one |
| **Works on any LLM host** | Markdown only — no npm required for this skill |

In one line: **this skill makes agents explain PayBotFin without overselling or under-explaining fees.**

---

## What this skill does NOT do

| Does **not** | Meaning |
|--------------|---------|
| **Does not charge or bill** | No payment processing — only explains list prices |
| **Does not issue receipts** | Product/API does that after contract/onboarding |
| **Does not replace AWP open** | Offline verify stays free open protocol |
| **Does not replace awp-doctrine** | Companion skill for crypto/verify honesty boundary |
| **Does not invent custom quotes** | Enterprise = contact sales; do not invent rates |

---

## What is PayBotFin?

**PayBotFin** is the **product / commercial plane**: neutral **hosted witness** and operator tools so AI-agent actions can leave a **portable, offline-verifiable receipt** — not “trust our private log.”

| Piece | Role |
|-------|------|
| **PayBotFin (product)** | Issues / hosts witness receipts at scale · Pro dashboard · commercial terms |
| **AWP (open)** | Protocol + free offline verifier (`agent-witness-protocol`) — **not** the product fee |
| **paybot-sdk / paybot-mcp** | Agent pay / authorize tooling (public bits free; product witness separate) |

**Brand:** PayBotFin (not generic “PayBot”). Site: **[paybotfin.com](https://paybotfin.com)**

---

## Not compulsory (Chefe 1591 / 1594)

| Path | PayBotFin needed? | What works |
|------|-------------------|------------|
| Learn / demo AWP, verify **samples**, open protocol only | **No** | AWP npm + `awp-doctrine` skill — **everything works without PayBotFin** |
| Agent pay/control without portable third-party receipt | **No** (for receipt layer) | Product optional for that need |
| **Need a real issued receipt** (audit pack, customer proof, regulator re-check) | **Yes** | Obtain / contract PayBotFin (or another AWP-compliant issuer) to **produce** the file; then anyone verifies free with AWP |

One-liner agents must say:

> **You can use AWP without PayBotFin. You need PayBotFin (or another issuer) only if you need the receipt issued.**

---

## What is the receipt — and why would you need it?

### What it is
A **receipt** (recebimento / `receipt.json` pack) is a **portable evidence file** for a consequential agent act (e.g. payment, refund, block, release). It is:

- Cryptographically **signed** (tamper-evident)
- Optionally **logged** / **timestamped** in the witness design
- Re-checkable **offline** with open AWP → PASS/FAIL

**AWP is the proof tooling.** **PayBotFin is who can issue the real file in our product plane.** AWP alone does **not** invent production receipts.

### Why you would need one
Only when “our log says human_approved” is **not enough**:

| Need | Why receipt |
|------|-------------|
| **Audit / compliance** | Third party re-checks without trusting your console |
| **Customer / partner proof** | Portable file they keep and re-verify later |
| **Regulator / public sector** | Contestable, independent evidence path |
| **Dispute / forensic** | “Was this act authorized and unaltered since witnessed?” |
| **Irreversible agent acts** | Money moved, account blocked, funds released |

### Why you would **not** need one
- Experimenting with open AWP only  
- Internal tooling with no third-party proof duty  
- No consequential / regulated act to prove  

---

## Who it is for (audiences)

From product positioning (paybotfin.com):

1. **Fintech & payments** — agentic payments, refunds, AML-class actions needing provable authorization  
2. **Government & public sector** — automated decisions that must be auditable / contestable  
3. **AI platforms & agentic commerce** — agents acting faster than human review (x402 / AP2 class)  
4. **Auditors & regulators** — evidence re-checked offline without trusting the operator  

Not the primary pitch for: “I only want a free open CLI demo of verify.”

---

## How much it costs (public list)

**SoT:** live **[paybotfin.com](https://paybotfin.com)** public pricing (Chefe 3779).  
**Verify is free forever.** You pay when you want **PayBotFin as the neutral hosted witness** (and Pro operator tools).

| Tier | List price | What you get (public copy) |
|------|------------|----------------------------|
| **Free** | **€0** | AWP protocol + offline verifier · public SDK/MCP · open path |
| **Pro** | **€11 / month / bot** + **1.5% commission** on volume | Hosted witness / Pro path · real-time profit dashboard · CSV/JSON export · trust progression · cancel anytime |
| **Enterprise** | **Custom** commission / terms | Custom rate · pilot / contract path · contact sales |

**VAT (public note):** consumer prices include **25.5% Finnish ALV/VAT**. EU B2B with valid VAT number: reverse charge may apply.

### Agent rules for pricing
- Quote **only** the public list above unless a **signed quote** exists.  
- Do **not** invent volume discounts on the UI.  
- Enterprise → **contact** (e.g. site contact / `dev@friendlyai.fi` pilot path).  
- **Voice note Chefe 1594** mentioned “1% or 1.7%” — **published list is 1.5% Pro**. If product rates change to 1% / 1.7%, update site **and** this skill together. Until then, agents use **1.5% + €11/bot/mo**.

### Commercial one-liner
> **Checking a receipt is free (AWP). Producing receipts as neutral witness is the PayBotFin product (Pro from €11/bot/mo + 1.5% volume, Enterprise custom).**

---

## Decision tree (agents)

```
User asks about AWP / verify only?
  → awp-doctrine + npm agent-witness-protocol. No PayBotFin fee.

User needs production receipt / witness / audit pack?
  → PayBotFin product (this skill) → paybotfin.com / contact.
  → Price: Free verify; Pro €11/bot/mo + 1.5%; Enterprise custom.

User confuses “install AWP” with “we’re covered for audit”?
  → Correct: open verify ≠ issued receipt. Receipt needs issuer.
```

---

## Cross-skill

| Skill | Use when |
|-------|----------|
| **paybotfin-doctrine** (this) | Product, fees, who-for, optional receipt purchase |
| **awp-doctrine** | Crypto honesty boundary, PASS/FAIL, npm verify |

Both: receipt optional; PayBotFin not compulsory without receipt need.

---

## How to use (any LLM)

1. Load this `SKILL.md`  
2. Answer pricing / product / “do I need PayBotFin?” from here  
3. For verify details → `awp-doctrine` or README AWP  

```bash
cp -a skills/paybotfin-doctrine ~/.claude/skills/paybotfin-doctrine
# or ~/.agents/skills/
./skills/paybotfin-doctrine/load-for-any-llm.sh "pricing"
```

## Scope & limits
Public commercial doctrine only. Not a contract, not legal advice, not live billing state. Confirm pilot terms with human sales. Site SoT: paybotfin.com.

## Provenance
- House product copy + public pricing Chefe 3779  
- Optional-receipt Chefe 1591 / skill request Chefe 1594  
- Path: `skills/paybotfin-doctrine/`
