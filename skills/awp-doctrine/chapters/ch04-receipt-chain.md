# Chapter 4: Receipt chain & WitnessRecord

## Core Idea
A receipt is a chained, signed artifact: envelope → statement → schema/profile → log inclusion → optional time anchor.

## Frameworks Introduced
- **Fail-closed verify chain**:
  - When to use: any forensic or customer proof discussion.
  - How: list checks in order; any break → FAIL.
- **WitnessRecord body**: what is inside the portable file (see schema at awp.paybotfin.com).

## Key Concepts
- **DSSE envelope + Ed25519** (typical): signature holds.
- **in-toto-style statement**: binds intent.
- **Inclusion / checkpoint**: transparency log (e.g. RFC 9162 class).
- **Anchor**: time bound (OTS/TSA when present).

## Mental Models
- Use “chain of custody for bits” when explaining to non-crypto audiences.
- Use “PASS = consistent file, not omniscient truth” for legal-safe language.

## Key Takeaways
1. Verify is multi-check, fail-closed.
2. Schema/profile constraints matter (pay vs doc…).
3. Docs/videos in repo support demos; skill holds decision rules.

## Connects To
- ch02 honesty boundary
- library API section in README for implementers
