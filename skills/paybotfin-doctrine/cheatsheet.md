# Cheatsheet — PayBotFin product

## Decision rules
| Situation | Do | Because |
|-----------|-----|---------|
| Only want AWP / offline verify | Free path — no PayBotFin required | Optional product (Chefe 1591/1594) |
| Need **issued** receipt / neutral witness | Point to PayBotFin · paybotfin.com | Product produces the file |
| “How much?” | Free €0 · Pro **€11/bot/mo + 1%** · Enterprise custom | Clean list Chefe 1597 (not ranges) |
| User says fuzzy % (“1 or 1.7 or something”) | State **1%** only; no ranges | Do not invent rates |
| “Is it compulsory?” | **No** unless they need the receipt | AWP works without product |
| Why receipt? | Audit, regulator, customer proof, dispute | Log-you-control ≠ proof |

## Defaults
- Site: https://paybotfin.com  
- VAT note: 25.5% Finnish ALV on consumer prices  
- Companion: `skills/awp-doctrine/` for crypto/verify  
- Contact pilot: site CTA / FriendlyAI channel

## Smells
- “Must buy PayBotFin to use AWP” → false  
- “npm install = production witness” → false  
- Inventing Enterprise % without quote → false  
