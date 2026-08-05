# Chapter 3: Using AWP with paybot-sdk and paybot-mcp

## Core Idea
Public trio: **paybot-mcp / paybot-sdk** (act/pay path) + **agent-witness-protocol** (offline evidence).

## Frameworks Introduced
- **Issue then verify**:
  - When to use: agent payments or authorize decisions that must leave evidence.
  - How: run flow via MCP/SDK → export/witness receipt → `awp verify`.
- **Integration honesty**: wiring matures; not every path emits AWP yet.

## Key Concepts
- **paybot-mcp**: agent tools for payment/authorize style flows.
- **paybot-sdk**: same in code.
- **AWP package**: verify only.

## Anti-patterns
- **Assuming every PayBot success has a receipt**: check integration status.
- **Putting prod secrets in skill files**: never.

## Key Takeaways
1. MCP/SDK = do the act; AWP = check the evidence file.
2. Use samples for offline demos without issuer account.
3. Hosted witness (witness.paybotfin.com) is the scale issuer path.

## Connects To
- ch02 user guide
- ch01 open vs private
