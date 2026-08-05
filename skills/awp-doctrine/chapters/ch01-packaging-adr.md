# Chapter 1: AWP open / PayBot private packaging (Chefe 1057)

## Core Idea
AWP is the **open verify layer**; PayBot is the **private product/issuer plane**. Never market “install npm = full production witness.”

## Frameworks Introduced
- **Packaging lock**: open protocol package vs hosted commercial issuer.
  - When to use: any discussion of open-source AWP, npm, or “is PayBot free?”
  - How: point AWP = verify; PayBotFin witness = issue at scale.

## Key Concepts
- **AWP open**: offline verification, samples, schema, CLI.
- **PayBot private**: multi-tenant issuer, product surface, commercial terms.
- **SoT**: ADR in repo + product packaging lock.

## Anti-patterns
- **Claiming AWP install replaces PayBot**: fails honesty; confuses verify with issue.
- **Hiding that a receipt body is required**: users think the package invents evidence.

## Key Takeaways
1. Open verify and private issue are complementary, not the same binary.
2. Samples prove the **chain works**; real eng receipts need an issuer.
3. Packaging decisions are Chefe-normative (1057) — follow Do / Do not lists in ADR.

## Connects To
- ch02 honesty boundary
- ch03 paybot-sdk/mcp integration
