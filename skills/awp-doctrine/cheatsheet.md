# Cheatsheet — AWP decisions

## Decision rules
| Situation | Do | Because |
|-----------|-----|---------|
| Have receipt.json | `npx awp verify` | Only path that proves integrity-since-witness |
| Only payment UI green | Do not claim AWP PASS | Different check |
| User asks “is AWP free?” | Open verify yes; hosted issuer may be product | Packaging lock 1057 |
| Need customer-proof pack | Issue receipt + keep file + verify offline | Portable evidence |
| Flip one byte in receipt | Expect FAIL | Fail-closed design |
| RAG vs skill | Skill for stable AWP doctrine; RAG for live eng logs | Volatility |

## Defaults
- Sample path: `node_modules/agent-witness-protocol/samples/receipt.json`
- Schema: `https://awp.paybotfin.com/witness-record/v1`
- Witness health: `https://witness.paybotfin.com/health`

## Smells
- “We installed AWP so we’re covered” without receipts → missing issuer layer.
- Dumping full README every turn → use this skill instead (token discipline).
