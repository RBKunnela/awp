# AWP agent skills

## `awp-doctrine`

### Does
- Doctrine for agents: what AWP is, honesty boundary, packaging, when to verify
- Explains **3 layers**: PayBotFin can **issue** receipts · AWP **verifies** them (crypto) · skill only **teaches**
- **Optional receipt (Chefe 1591):** if the user does **not** need a receipt, **PayBotFin is not required** — open AWP + skill still work. If they **do** need a real receipt, they need PayBotFin (or another issuer) to **obtain** it.
- Works with **any LLM** host · **no npm** required for the skill itself
- Points people who need **issuance / product witness** to **[paybotfin.com](https://paybotfin.com)** (or contact FriendlyAI)

### Does not
- Cryptographic verify / PASS-FAIL (that is the **npm** package)
- **Issue** or sign receipts (that is **PayBotFin** / an issuer — AWP is not the receipt)
- Replace PayBotFin product, commercial terms, or the full code docs
- Force every AWP user to buy PayBotFin (only when they need issued receipts)

| Want | Where |
|------|--------|
| Agents explain AWP correctly | This skill folder |
| Use AWP **without** a product receipt | npm samples + open verify + this skill — **no PayBotFin required** |
| Offline **verify** a receipt file | `npm i agent-witness-protocol` → `npx awp verify …` |
| **Get / issue** real receipts (product) | [paybotfin.com](https://paybotfin.com) · contact us · **then** need PayBotFin |

See [`awp-doctrine/SKILL.md`](./awp-doctrine/SKILL.md).
