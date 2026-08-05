# AWP agent skills

## `awp-doctrine`

### Does
- Doctrine for agents: what AWP is, honesty boundary, packaging, when to verify
- Explains **3 layers**: PayBotFin can **issue** receipts · AWP **verifies** them (crypto) · skill only **teaches**
- Works with **any LLM** host · **no npm** required for the skill itself
- Points people who need **issuance / product witness** to **[paybotfin.com](https://paybotfin.com)** (or contact FriendlyAI)

### Does not
- Cryptographic verify / PASS-FAIL (that is the **npm** package)
- **Issue** or sign receipts (that is **PayBotFin** / an issuer — AWP is not the receipt)
- Replace PayBotFin product, commercial terms, or the full code docs

| Want | Where |
|------|--------|
| Agents explain AWP correctly | This skill folder |
| Offline **verify** a receipt file | `npm i agent-witness-protocol` → `npx awp verify …` |
| **Get / issue** real receipts (product) | [paybotfin.com](https://paybotfin.com) · contact us |

See [`awp-doctrine/SKILL.md`](./awp-doctrine/SKILL.md).
