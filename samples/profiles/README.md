# Profile predicate samples (pay · doc · principal · composite)

These JSON files are **WitnessRecord predicates** (schema + profile minimums).
They are for learning and for `validateWitnessRecord` / `validateProfile`.

| File | Profile | Example action |
|------|---------|----------------|
| `pay.json` | pay | payment under mandate |
| `doc.json` | doc | `doc.generate` with artifact hash |
| `principal.json` | principal | human credential bound to this intent |
| `composite.json` | composite | pay + doc scene (e-commerce) |

## Full crypto verify vs shape/profile validate

| Artifact | Command / API |
|----------|----------------|
| Full receipt bundle (envelope + log + anchors) e.g. `samples/receipt.json` | `npx awp verify samples/receipt.json` |
| Predicate-only samples here | Library `validateWitnessRecord` + `validateProfile` (not full `awp verify` — no DSSE/inclusion yet) |

### Library check (shape + profile)

```bash
npm install agent-witness-protocol
node --input-type=module <<'JS'
import { readFileSync } from 'node:fs';
import { validateWitnessRecord, validateProfile } from 'agent-witness-protocol';

for (const name of ['pay', 'doc', 'principal', 'composite']) {
  const rec = JSON.parse(readFileSync(`node_modules/agent-witness-protocol/samples/profiles/${name}.json`, 'utf8'));
  const shape = validateWitnessRecord(rec);
  const prof = shape.ok ? validateProfile(shape.record) : { ok: false, failures: shape.errors };
  console.log(name, shape.ok && prof.ok ? 'OK' : 'FAIL', prof);
}
JS
```

From a git clone of this repo (after `npm i && npm run build`):

```bash
node --input-type=module <<'JS'
import { readFileSync } from 'node:fs';
import { validateWitnessRecord, validateProfile } from '../../dist/index.js';
for (const name of ['pay', 'doc', 'principal', 'composite']) {
  const rec = JSON.parse(readFileSync(`./${name}.json`, 'utf8'));
  const s = validateWitnessRecord(rec);
  const p = s.ok ? validateProfile(s.record) : s;
  console.log(name, s.ok && p.ok ? 'OK' : p);
}
JS
```

Full signed multi-profile **receipt bundles** for `awp verify` ship as the issuer path matures (see ticket `TICKET-AWP-MULTI-PROFILE-EMIT-001`). Until then use `samples/receipt.json` for end-to-end crypto verify (pay-shaped demo).


## Full crypto verify (all profiles)

See sibling dir [`../receipts/`](../receipts/) — `npx awp verify samples/receipts/doc.json` etc. (Chefe 1072).
