# Using AWP with paybot-sdk and paybot-mcp

This is the integrator’s companion to the root README.

## Layers

| Layer | Package | User action |
|-------|---------|-------------|
| Agent host | `paybot-mcp` | MCP tools (`paybot_pay`, …) |
| Client | `paybot-sdk` | `PayBotClient.pay()` / x402 handler |
| Control plane | paybot-core (hosted/self-host) | authorize + optional settle |
| Evidence | `agent-witness-protocol` | `npx awp verify` offline |
| Issuer (hosted) | paybotfin-witness | Builds receipt with AWP ops (prod path) |

## What works today (verified)

1. `npm i agent-witness-protocol` in AIOX-Enterprise and clean projects  
2. `npx awp verify …/samples/receipt.json` → **PASS**  
3. Library `verify(receipt, { publicKey: receipt.public_key_pem })` → **PASS**  
4. One-byte inclusion flip → **FAIL** isolated to `inclusion`  
5. paybot-sdk / paybot-mcp install and payment tools are independent of AWP  

## What is not automatic yet

- MCP `paybot_pay` does **not** return an AWP receipt today.  
- paybot-core does not emit AWP on every authorize by default.  
- Production multi-tenant witness is separate (must depend on npm AWP, not `file:`).

## Recommended user workflow

```text
1. Agent pays / acts via paybot-mcp or paybot-sdk
2. Platform stores decision + (when available) AWP receipt file
3. Auditor: npx awp verify receipt.json
4. Treat payment success ≠ AWP PASS until receipts are wired
```

## Library gotcha

CLI reads `public_key_pem` from the receipt file automatically.  
Library **requires** `options.publicKey` — pass `receipt.public_key_pem`.

## Exhaustive smoke

```bash
npm i agent-witness-protocol
node tools/exhaustive-npm-smoke.mjs   # from this repo with package installed
```
