# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No (pre-public / placeholder namespace) |

Only the latest **0.2.x** release line receives security fixes.

## Test keys (not secrets)

Fixture files under `test/**` and `samples/` embed **deterministic Ed25519 TEST keys** so auditors can re-derive signatures offline. They are intentional, public, and **must never** be used in production. Gitleaks allowlists those paths via `.gitleaks.toml`.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems that could enable verify-bypass, signature forgery acceptance, or supply-chain compromise of this package.

Prefer, in order:

1. **GitHub Security Advisories** for this repository:  
   https://github.com/RBKunnela/awp/security/advisories/new  
2. If you cannot use advisories, open a **private** contact via the maintainer on GitHub:  
   https://github.com/RBKunnela  

Include: affected version, minimal reproduction, impact (e.g. false PASS), and whether a fix is proposed.

We aim to acknowledge reports within **7 days** and to publish coordinated fixes and advisories when warranted.

## Honesty boundary (read carefully)

**AWP verification is not a guarantee of truth about the real world.**

A successful `awp verify` (RESULT: PASS) means, at most:

- The receipt’s cryptographic structure re-performed correctly under the protocol rules known to this verifier: signatures, hashes, inclusion/consistency proofs, and related checks that the library implements.

It does **not** prove:

| Claim | Status |
|-------|--------|
| **Integrity since witness** | What PASS is designed to support (tamper-evidence of the witnessed payload under the embedded keys/proofs). |
| **Authenticity at origin** | **Not proven.** AWP does not establish that the original actor, agent, or customer is who they claim to be beyond material present in the receipt. |
| **Completeness** | **Not proven.** Missing actions leave no receipt; absence of a FAIL is not evidence that every action was witnessed. |
| **Identity / KYC / legal personhood** | **Not proven.** Key material and claim fields are not a substitute for identity systems. |
| **Producer honesty** | **Not proven.** A neutral witness topology reduces self-attestation risk; it does not make the producer trustworthy. |

Verification is **best-effort cryptographic re-performance**: the verifier re-runs the math and schema checks it knows how to run. Bugs, incomplete check coverage, clock/anchor assumptions, and future wire-format versions can all affect outcomes. Treat PASS as “this artifact still matches its cryptographic commitments,” not as “this event is authentic, complete, or endorsed by FriendlyAI Oy or the `paybotfin.com` namespace.”

The namespace `https://paybotfin.com/witness-record/v1` is a **format identifier**, not an endorsement of any particular emitter or receipt. Production `.com` host is intentional — many enterprises block or distrust `.dev` TLDs.

## Supply-chain notes for consumers

- Prefer installing from the published npm package with integrity checks enabled.
- Pin dependencies thoughtfully; this package depends on `zod` for schema validation.
- Do not treat test fixtures or sample keys in this repository as production secrets — they are for local verification demos only.
