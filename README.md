# Agent Witness Protocol (AWP)

### Offline-verifiable receipts for what AI agents do.

**Install and use today:**

```bash
npm install agent-witness-protocol
npx awp verify node_modules/agent-witness-protocol/samples/receipt.json
# → RESULT: PASS
```

[![npm](https://img.shields.io/npm/v/agent-witness-protocol.svg)](https://www.npmjs.com/package/agent-witness-protocol)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-368%2F368-brightgreen.svg)](#prove-it-works)
[![YouTube](https://img.shields.io/badge/YouTube-@FriendlyAI__fi-FF0000.svg?logo=youtube&logoColor=white)](https://www.youtube.com/@FriendlyAI_fi)

> **Wire type (live):** [`https://awp.paybotfin.com/witness-record/v1`](https://awp.paybotfin.com/witness-record/v1) ·  
> **Schema:** [`…/schema.json`](https://awp.paybotfin.com/witness-record/v1/schema.json) · **npm:** `agent-witness-protocol@0.2.0`

---

## What problem this solves

An agent paid someone, refunded an order, or wrote a document. Later someone asks:

> *What did it do, who authorized it, and was the log altered?*

If the only answer is the vendor’s console, that is a diary — not independent evidence.

**AWP** defines a **portable receipt file** anyone can re-check **offline**, without trusting the producer.

```text
Agent acts  →  (optional) PayBot governs / pays  →  witness issues AWP receipt
                                                    ↓
                              anyone:  npx awp verify receipt.json  →  PASS / FAIL
```

### Honesty boundary (read this once)

`awp verify` proves **integrity-since-witness only**:

| Proves | Does **not** prove |
|--------|---------------------|
| Receipt is consistent and correctly signed | Authenticity of the original act |
| Unaltered since witnessed | Identity of a human |
| Inclusion in a signed log + time bound (when present) | Completeness (“everything was recorded”) |

That line is printed on every report. It is a feature (liability firewall), not a bug.

---

## Install

```bash
npm install agent-witness-protocol
```

**ESM only** (same as paybot-sdk). In `package.json` set `"type": "module"`, or use `.mjs`.

| Surface | Import / command |
|---------|------------------|
| Full package | `import { verify, validateWitnessRecord } from 'agent-witness-protocol'` |
| Subpaths | `agent-witness-protocol/schema`, `/verify`, `/envelope`, `/anchor`, `/log` |
| CLI | `npx awp verify <file.json>` |
| Schema (non-TS) | `node_modules/agent-witness-protocol/…/witness-record.schema.json` or [live schema](https://awp.paybotfin.com/witness-record/v1/schema.json) |

---

## Prove it works (60 seconds)

```bash
npm install agent-witness-protocol

# 1) Clean sample shipped in the package
npx awp verify node_modules/agent-witness-protocol/samples/receipt.json
# RESULT: PASS  (signature, schema, inclusion, checkpoint, anchor, …)

# 2) Library
node --input-type=module <<'EOF'
import { verify, PREDICATE_TYPE } from 'agent-witness-protocol';
import { readFileSync } from 'node:fs';
const receipt = JSON.parse(
  readFileSync('node_modules/agent-witness-protocol/samples/receipt.json', 'utf8')
);
const report = verify(receipt, { publicKey: receipt.public_key_pem });
console.log(PREDICATE_TYPE);
console.log(report.ok ? 'PASS' : 'FAIL', report.checks.filter(c => !c.ok).map(c => c.name));
EOF
```

**Tamper isolation (from a clone of this repo):** flip one hex char in the inclusion path → `FAIL` names `inclusion`; other layers can still PASS.

```bash
git clone https://github.com/RBKunnela/awp.git && cd awp && npm i && npm run build
node bin/awp.js verify test/verify/fixtures/full-receipt-tampered.json
# RESULT: FAIL  failed checks: inclusion
```

**Exhaustive smoke (maintainers):**

```bash
npm i agent-witness-protocol   # or use local build
node tools/exhaustive-npm-smoke.mjs
```

---

## How a user should use AWP (roles)

| You are… | What you do with AWP |
|----------|----------------------|
| **Agent builder** | After a governed action, **keep the receipt JSON** your platform/witness returns. Do not re-implement crypto. |
| **Auditor / customer** | Run `npx awp verify receipt.json` offline. Share the file, not console screenshots. |
| **Platform (PayBotFin)** | **Issue** receipts via a witness service that imports this package (never reimplements Merkle/DSSE). |
| **Integrator** | Validate shapes with `validateWitnessRecord` / `validateProfile`; verify bundles with `verify()`. |

### What a receipt is

One JSON file chaining four layers:

```text
DSSE + in-toto envelope  →  RFC 9162 inclusion  →  C2SP checkpoint  →  time anchor (OTS / RFC 3161)
```

CLI checks (named, fail-closed):  
`envelope-shape`, `payloadType`, `signature`, `statement`, `schema`, `profile`, `claim-class`, `chain-link`, `checkpoint`, `inclusion`, `anchor`.

---

## Using AWP **with** paybot-sdk and paybot-mcp

These are **three layers** of one stack. Today they connect as follows:

```text
┌─────────────────────────────────────────────────────────────┐
│  AI host (Claude, Cursor, custom agent)                     │
│    └── paybot-mcp   (MCP tools: pay, balance, history, …)   │
└────────────────────────────┬────────────────────────────────┘
                             │ calls
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  paybot-sdk   (PayBotClient.pay / register / x402 handler)  │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS + API key
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  paybot-core (facilitator + governance)  [private / hosted] │
│    authorize · policy · optional x402 settle · audit chain  │
└────────────────────────────┬────────────────────────────────┘
                             │ (production path — witness service)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  paybotfin-witness (issues AWP receipt bundles)             │
│    imports agent-witness-protocol — does NOT reimplement    │
└────────────────────────────┬────────────────────────────────┘
                             │ receipt.json
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  agent-witness-protocol   npx awp verify   (offline, you)   │
└─────────────────────────────────────────────────────────────┘
```

### Install the public trio

```bash
npm install agent-witness-protocol paybot-sdk paybot-mcp
```

| Package | License | Role |
|---------|---------|------|
| [`agent-witness-protocol`](https://www.npmjs.com/package/agent-witness-protocol) | Apache-2.0 | **Verify** (and build) receipts |
| [`paybot-sdk`](https://www.npmjs.com/package/paybot-sdk) | MIT | Bot payments + x402 client |
| [`paybot-mcp`](https://www.npmjs.com/package/paybot-mcp) | Apache-2.0 | MCP tools wrapping the SDK |

### 1) Agent payments via MCP (paybot-mcp)

```json
{
  "mcpServers": {
    "paybot": {
      "command": "npx",
      "args": ["paybot-mcp"],
      "env": {
        "PAYBOT_API_KEY": "pb_...",
        "PAYBOT_FACILITATOR_URL": "https://api.paybotcore.com",
        "PAYBOT_BOT_ID": "my-agent"
      }
    }
  }
}
```

Tools include `paybot_pay`, `paybot_balance`, `paybot_history`, `paybot_register`, limits, pools, etc.  
Omit `PAYBOT_WALLET_KEY` → **mock** settlement (no on-chain funds).

Get a key (once):

```bash
node --input-type=module -e "import { PayBotClient } from 'paybot-sdk'; const a = await PayBotClient.signup('you@example.com', 'strong-password', { botId: 'my-agent' }); console.log(a.apiKey);"
```

### 2) Same flow in code (paybot-sdk)

```ts
import { PayBotClient } from 'paybot-sdk';

const client = new PayBotClient({
  apiKey: process.env.PAYBOT_API_KEY!,
  botId: 'my-agent',
  facilitatorUrl: 'https://api.paybotcore.com',
  // walletPrivateKey: process.env.PAYBOT_WALLET_KEY, // only for real settlement
});

const result = await client.pay({
  resource: 'https://api.example.com/data',
  amount: '0.01',
  payTo: '0x…',
});
// Keep result + any receipt your platform attaches for AWP verify later
```

### 3) Verify evidence offline (this package)

Whenever you hold a **receipt file** from a witness / platform:

```bash
npx awp verify ./receipts/action-2026-07-21.json
```

Or in TypeScript:

```ts
import { verify } from 'agent-witness-protocol';
import { readFileSync } from 'node:fs';

const receipt = JSON.parse(readFileSync('./receipts/action.json', 'utf8'));
// Library: pass the key explicitly (CLI auto-reads public_key_pem from the file)
const report = verify(receipt, { publicKey: receipt.public_key_pem });

if (!report.ok) {
  for (const c of report.checks) if (!c.ok) console.error(c.name, c.reason);
  process.exit(1);
}
console.log('PASS — integrity-since-witness');
```

### Integration reality (honest)

| Capability | Status today |
|------------|----------------|
| Install & verify AWP receipts from npm | **Works** |
| PayBot SDK/MCP payments (mock or live facilitator) | **Works** (public packages) |
| Hosted multi-tenant **witness** issuing receipts in prod | **In progress** (DEV path; uses this package) |
| Automatic “every MCP pay() returns an AWP receipt” | **Not automatic yet** — platform must attach/issue receipt via witness |
| Self-issued demo receipts for tests | Use package `samples/receipt.json` or generate with AWP ops APIs |

So the **user path that works end-to-end today** is:

1. Use **paybot-mcp / paybot-sdk** for agent payments and governance against the facilitator.  
2. Use **agent-witness-protocol** to **verify any receipt you receive** (sample, witness service, or partner).  
3. Treat “payment success” and “AWP PASS” as **two different checks** until your platform wires them together.

---

## Library API (quick)

```ts
import {
  validateWitnessRecord,
  validateProfile,
  verify,
  PREDICATE_TYPE,
} from 'agent-witness-protocol';

// 1) Shape only
const v = validateWitnessRecord(json);
if (!v.ok) throw new Error(JSON.stringify(v.errors));
const p = validateProfile(v.record); // pay | doc | principal | composite

// 2) Full receipt bundle (envelope + log + anchor)
//    Library requires publicKey; CLI can read public_key_pem from the file.
const report = verify(receiptBundle, {
  publicKey: receiptBundle.public_key_pem,
});
```

CLI options: `--pubkey`, `--prev`, `--tsa-pubkey`, `--tsa-qualified`, `--json`.

---

## How the receipt chain works

![AWP verification chain](docs/assets/awp-verification-chain.png)

| Layer | Standard | CLI check |
|-------|----------|-----------|
| Signed record | DSSE + in-toto Statement | `signature`, `statement` |
| Schema / profile / honesty | AWP WitnessRecord | `schema`, `profile`, `claim-class` |
| Log membership | RFC 9162 inclusion | `inclusion` |
| Log head | C2SP checkpoint | `checkpoint` |
| Time | OpenTimestamps / RFC 3161 | `anchor` |

![Neutral witness](docs/assets/neutral-witness.png)

---

## WitnessRecord (what is inside)

![WitnessRecord anatomy](docs/assets/witness-record-anatomy.png)

| Block | Meaning |
|-------|---------|
| **intent** | Agent, action, target, params **hash**, policy decision |
| **authorization** | Credential that permitted it + what was verified |
| **artifacts** | Inputs/outputs by **hash**, never content |
| **verifications** | Typed testimony (`claim_class` closed enum) |

Profiles: `pay` · `doc` · `principal` · `composite`.

---

## Videos

| Lang | Link |
|------|------|
| EN | https://www.youtube.com/watch?v=wzfkXXsyvM8 |
| FI | https://www.youtube.com/watch?v=kx9qwmpT8Oo |
| PT | https://www.youtube.com/watch?v=Y3QoJZ7vfw8 |
| DE | https://www.youtube.com/watch?v=POPD2NnXHOE |
| FR | https://www.youtube.com/watch?v=hLClWBNlpIM |
| IT | https://www.youtube.com/watch?v=L5EQY424lLc |
| AR | https://www.youtube.com/watch?v=tLF23iGZXe8 |

Channel: [@FriendlyAI_fi](https://www.youtube.com/@FriendlyAI_fi)

---

## Docs in this repo

| Doc | Content |
|-----|---------|
| [spec/AWP-v0.1.md](docs/spec/AWP-v0.1.md) | Normative specification |
| [receipts.md](docs/receipts.md) | Bundle wire format + leaf rule |
| [anchoring.md](docs/anchoring.md) | Time anchors |
| [THE-CASE-FOR-AWP.md](docs/THE-CASE-FOR-AWP.md) | Strategy / 80–20 honesty |
| [Architecture PDF](docs/awp-cryptographic-architecture-statement.pdf) | Plain-language crypto report |

---

## Open core vs hosted witness

| Open (this package) | Hosted (PayBotFin / separate) |
|---------------------|--------------------------------|
| Schema + verify + sample | Multi-tenant issuance at scale |
| Anyone re-checks offline | Metered neutral witness service |

---

## Roadmap

- [x] Schema, envelope, log, anchors, `awp verify`  
- [x] 368/368 tests, CI  
- [x] Live namespace on `awp.paybotfin.com`  
- [x] **npm `agent-witness-protocol@0.2.0`**  
- [ ] Production multi-tenant witness (depends on this package via npm, not `file:`)  
- [ ] Automatic receipt attach from paybot-core authorize/settle  
- [ ] Optional SCITT export adapter (customer-triggered)  

---

## Support

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support%20AWP-ffdd00.svg?logo=buymeacoffee&logoColor=black&style=for-the-badge)](https://buymeacoffee.com/aiagentsprp)

https://buymeacoffee.com/aiagentsprp

---

## License

- **Code:** [Apache-2.0](./LICENSE)  
- **Spec document:** CC-BY-4.0 (Renata Baldissara-Kunnela)  
- **Copyright:** FriendlyAI Oy — [NOTICE](./NOTICE)

The `awp.paybotfin.com` namespace is a **format identifier**, not an endorsement of any emitter.

---

### Bottom line

```bash
npm install agent-witness-protocol
npx awp verify node_modules/agent-witness-protocol/samples/receipt.json
```

Use **paybot-sdk / paybot-mcp** to **act**.  
Use **AWP** to **prove** the act was recorded without trusting the producer.
