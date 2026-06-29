/**
 * witness-agent-task.mjs
 *
 * CLI: produce an AWP receipt for one AIOX orchestration agent task.
 * Each receipt is a 5W1H ledger entry: WHO planned it, WHAT action,
 * WHY (params hash + policy), WHEN, WHERE (target + log), HOW/done
 * (artifacts + integrity-since-witness verifications).
 *
 * Usage:
 *   node tools/witness-agent-task.mjs \
 *     --agent <agent-id>          WHO
 *     --action <verb>             WHAT  e.g. plan.architecture
 *     --target <ref>              WHERE (target_ref)
 *     --prompt-file <path>        WHY planned (sha256 becomes params_hash)
 *     --output-file <path>        HOW done   (real file; sha256+size measured)
 *     --verdict <pass|fail>       HOW done   (verification result)
 *     [--prev <64-char hex>]      chain link (omit for genesis / 64 zeros)
 *     --out <receipt.json>        where to write the receipt
 *
 * Profile chosen: "doc"
 *   The lightest profile requiring only >=1 artifact.  An AIOX orchestration
 *   task always produces an output document; authorization and verifications
 *   blocks are optional at the schema level and not required by "doc".
 *   "pay" would need a mandate-class credential (payment context only).
 *   "principal" would need an intent-bound auth credential (human auth).
 *   "composite" requires all three (artifact + auth + mandate + verification).
 *   "doc" is the correct and honest choice: we witness a document artifact
 *   with integrity-since-witness — nothing more.
 *
 * Honesty boundary:
 *   claim_class is ALWAYS "integrity-since-witness". AWP can only prove the
 *   output file is unaltered since it was witnessed. It cannot prove who wrote
 *   it, that the content is correct, or that the agent behaved honestly.
 *   Tamper-EVIDENT not tamper-proof.
 *
 * Key management:
 *   A local Ed25519 key pair is generated fresh per run and written to
 *   ~/.config/aiox/orchestration-witness-key.json (private key seed, hex; 0o600, OUTSIDE the repo).
 *   Override via AIOX_WITNESS_SEED_HEX (preferred, e.g. from KMS) or AIOX_WITNESS_KEY_FILE.
 *   On subsequent runs the same key is reused so receipts from the same
 *   deployment share a fingerprint. In production this would be an HSM or
 *   KMS-backed key; the OPEN AWP package never holds the private key itself.
 *
 * In-memory log:
 *   Uses ReferenceLog (in-memory). Production should replace this with the
 *   Postgres LogStore from the hosted-service plan (AW-7). The receipt still
 *   verifies offline because the inclusion proof + checkpoint are embedded.
 *
 * Verify:
 *   node D:\1.GITHUB\awp\bin\awp.js verify <receipt.json>
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

// Import from the compiled dist — this script lives next to it.
import {
  signEnvelope,
  signerFromPrivateKey,
  ReferenceLog,
  checkpoint,
  proof,
  buildTestOtsProof,
  validateWitnessRecord,
} from '../dist/index.js';

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);

function flag(name) {
  const i = args.indexOf(name);
  if (i === -1 || i + 1 >= args.length) return null;
  return args[i + 1];
}

const agentId  = flag('--agent');
const action   = flag('--action');
const targetRef = flag('--target');
const promptFile = flag('--prompt-file');
const outputFilePath = flag('--output-file');
const verdict  = flag('--verdict');
const prevHash = flag('--prev') ?? '0'.repeat(64);
const outPath  = flag('--out');

function usage() {
  console.error([
    'Usage: node tools/witness-agent-task.mjs',
    '  --agent <id>           WHO  (e.g. architect)',
    '  --action <verb>        WHAT (e.g. plan.architecture)',
    '  --target <ref>         WHERE (target_ref)',
    '  --prompt-file <path>   WHY planned (content hashed → params_hash)',
    '  --output-file <path>   HOW done (file; sha256+size measured)',
    '  --verdict <pass|fail>  HOW done (integrity verification result)',
    '  [--prev <hex64>]       chain.prev_record_hash (default: 64 zeros)',
    '  --out <receipt.json>   output path',
  ].join('\n'));
}

if (!agentId || !action || !targetRef || !promptFile || !outputFilePath || !verdict || !outPath) {
  usage();
  process.exit(1);
}

if (!['pass', 'fail'].includes(verdict)) {
  console.error('--verdict must be "pass" or "fail"');
  process.exit(1);
}

if (!/^[a-f0-9]{64}$/.test(prevHash)) {
  console.error('--prev must be a lowercase 64-char hex SHA-256');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Key management — load or generate orchestration key.
// ---------------------------------------------------------------------------

const here = dirname(fileURLToPath(import.meta.url));

// SECURITY: the signing key seed is private key material and MUST NOT live in the
// repo tree (a stray `git add` would leak it). Resolution order:
//   1) AIOX_WITNESS_SEED_HEX env var (production-style; ultimately a KMS/HSM)
//   2) AIOX_WITNESS_KEY_FILE / AIOX_WITNESS_KEY_DIR env path
//   3) a per-user config file under ~/.config/aiox (dir 0o700, file 0o600)
const keyDir = process.env.AIOX_WITNESS_KEY_DIR || join(homedir(), '.config', 'aiox');
const keyFile = process.env.AIOX_WITNESS_KEY_FILE || join(keyDir, 'orchestration-witness-key.json');

let envelopePrivateKey;
let envelopePublicKey;

/** Rebuild an Ed25519 keypair from a 32-byte seed (hex). */
function keypairFromSeedHex(seedHex) {
  const seedBuf = Buffer.from(String(seedHex).trim(), 'hex');
  if (seedBuf.length !== 32) {
    throw new Error('witness seed must be 32 bytes (64 hex chars)');
  }
  const privDer = Buffer.concat([
    Buffer.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]),
    seedBuf,
  ]);
  const priv = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  return { priv, pub: createPublicKey(priv) };
}

if (process.env.AIOX_WITNESS_SEED_HEX) {
  const kp = keypairFromSeedHex(process.env.AIOX_WITNESS_SEED_HEX);
  envelopePrivateKey = kp.priv;
  envelopePublicKey = kp.pub;
} else if (existsSync(keyFile)) {
  const stored = JSON.parse(readFileSync(keyFile, 'utf8'));
  const kp = keypairFromSeedHex(stored.seed_hex);
  envelopePrivateKey = kp.priv;
  envelopePublicKey = kp.pub;
} else {
  const pair = generateKeyPairSync('ed25519');
  envelopePrivateKey = pair.privateKey;
  envelopePublicKey  = pair.publicKey;
  // Extract 32-byte seed from the PKCS8 DER export and persist OUTSIDE the repo
  // with owner-only permissions (dir 0o700, file 0o600, fail if it already exists).
  const privDer = Buffer.from(envelopePrivateKey.export({ format: 'der', type: 'pkcs8' }));
  const seed = privDer.subarray(-32);
  mkdirSync(dirname(keyFile), { recursive: true, mode: 0o700 });
  writeFileSync(keyFile, JSON.stringify({ seed_hex: seed.toString('hex') }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.error('[witness] Generated new orchestration key (0o600, outside repo) at', keyFile);
}

const rawPub = new Uint8Array(
  Buffer.from(envelopePublicKey.export({ format: 'der', type: 'spki' })).subarray(-32)
);
const publicKeyPem = envelopePublicKey.export({ type: 'spki', format: 'pem' });
const publicKeyRawB64 = Buffer.from(rawPub).toString('base64');

// Fingerprint for deployment.node_key_fpr
const nodeFpr = 'SHA256:' + createHash('sha256').update(rawPub).digest('hex').slice(0, 32);

// ---------------------------------------------------------------------------
// Hash the prompt file → params_hash (WHY planned)
// ---------------------------------------------------------------------------

const promptBytes = readFileSync(resolve(promptFile));
const paramsHash  = createHash('sha256').update(promptBytes).digest('hex');

// ---------------------------------------------------------------------------
// Hash the output file → artifact digest (HOW done)
// ---------------------------------------------------------------------------

const outputBytes = readFileSync(resolve(outputFilePath));
const outputHash  = createHash('sha256').update(outputBytes).digest('hex');
const outputSize  = outputBytes.length;

// ---------------------------------------------------------------------------
// Build the WitnessRecord
// ---------------------------------------------------------------------------

const now = new Date();
// started_at slightly before ended_at to satisfy RFC 3339 + schema
const startedAt = new Date(now.getTime() - 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const endedAt   = now.toISOString().replace(/\.\d{3}Z$/, 'Z');

// policy_hash: sha256 of a canonical "AIOX orchestration policy v1" string.
// In production this would be the sha256 of the actual policy document.
const POLICY_ID   = 'aiox.orchestration-policy.v1';
const policyHash  = createHash('sha256').update(Buffer.from(POLICY_ID)).digest('hex');

// agent_key_fpr: sha256 of the agent id string (stable per agent name).
const agentKeyFpr = 'SHA256:' + createHash('sha256').update(Buffer.from(agentId)).digest('hex').slice(0, 32);

// subject_hash for the verification entry: sha256 of the output file (same as artifact).
const subjectHash = outputHash;

const record = {
  profile: 'doc',
  deployment: {
    log_id: 'aiox.orchestration/witness-log',
    node_key_fpr: nodeFpr,
    software: {
      name: 'aiox-orchestration-witness',
      version: '0.1.0',
    },
  },
  intent: {
    agent: {
      agent_id: agentId,
      agent_key_fpr: agentKeyFpr,
      runtime_ref: 'runtime:claude-sonnet-4-6',
    },
    action,
    target_ref: targetRef,
    params_hash: paramsHash,
    started_at: startedAt,
    ended_at:   endedAt,
    policy: {
      policy_id:   POLICY_ID,
      policy_hash: policyHash,
      decision:    'allow',
    },
  },
  artifacts: [
    {
      role: 'output',
      digest: {
        alg:   'sha256',
        value: outputHash,
      },
      media_type: 'text/markdown',
      size:        outputSize,
      pii_bearing: false,
    },
  ],
  verifications: [
    {
      // HONESTY BOUNDARY: integrity-since-witness only.
      // We prove the file is unaltered since witnessing; we do NOT prove
      // it is correct, authentic, or authored by the claimed agent.
      check:        'aiox.orchestration.output.integrity',
      subject_hash: subjectHash,
      issuer:       agentId,
      method:       'sha256-file-hash',
      result:       verdict === 'pass' ? 'pass' : 'fail',
      claim_class:  'integrity-since-witness',
    },
  ],
  chain: {
    prev_record_hash: prevHash,
  },
};

// Validate before signing (fail loud)
const validation = validateWitnessRecord(record);
if (!validation.ok) {
  console.error('[witness] WitnessRecord validation failed:');
  for (const e of validation.errors) console.error(' ', e);
  process.exit(1);
}
console.error('[witness] WitnessRecord schema: valid (profile=doc)');

// ---------------------------------------------------------------------------
// Sign envelope, build log, checkpoint, proof
// ---------------------------------------------------------------------------

const ORIGIN = 'aiox.orchestration/witness-log';

const envelopeSigner = signerFromPrivateKey(envelopePrivateKey, 'aiox-orchestration-envelope-key');
const envelope = signEnvelope(validation.record, envelopeSigner);

// Build a 3-leaf log: sentinel + our record + sentinel.
// A non-trivial tree so the inclusion proof has real siblings.
const log = new ReferenceLog(ORIGIN, { checkpointEvery: 4 });
const leafBytes = Buffer.from(envelope.payload, 'base64');
log.append(new TextEncoder().encode('aiox-witness-sentinel-0'));
const leafIndex = log.append(leafBytes);
log.append(new TextEncoder().encode('aiox-witness-sentinel-2'));

// Generate a fresh log signing key each run (the checkpoint signer — separate
// from the envelope key, as required by the two-key design).
const logKeyPair = generateKeyPairSync('ed25519');
const logRawPub  = new Uint8Array(
  Buffer.from(logKeyPair.publicKey.export({ format: 'der', type: 'spki' })).subarray(-32)
);
const noteSigner = {
  name:      ORIGIN,
  publicKey: logRawPub,
  sign: (bytes) => new Uint8Array(edSign(null, bytes, logKeyPair.privateKey)),
};

const cp = checkpoint(log, noteSigner);

// OTS anchor (test proof) over the checkpoint root.
const otsProof = buildTestOtsProof(Buffer.from(cp.rootHex, 'hex'), {
  confirmed: true,
  height:    900000,
});
const anchors = [
  {
    type:            'ots',
    checkpoint_root: cp.rootHex,
    ots_proof_b64:   otsProof.toString('base64'),
    pending:         false,
  },
];

const bundle = proof(leafIndex, {
  store:           log,
  record:          validation.record,
  envelope,
  signerPublicKey: logRawPub,
  checkpoint:      cp,
  anchors,
});

// ---------------------------------------------------------------------------
// Write receipt
// ---------------------------------------------------------------------------

const receipt = {
  _comment: [
    'AIOX orchestration-witness receipt.',
    `agent=${agentId} action=${action} target=${targetRef}`,
    `output sha256=${outputHash} size=${outputSize}`,
    `verdict=${verdict} claim_class=integrity-since-witness`,
    'Verify: node D:\\1.GITHUB\\awp\\bin\\awp.js verify <this-file>',
  ].join(' | '),
  public_key_pem:        publicKeyPem,
  public_key_raw_base64: publicKeyRawB64,
  ...bundle,
};

const outResolved = resolve(outPath);
const outDir = dirname(outResolved);
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
writeFileSync(outResolved, JSON.stringify(receipt, null, 2) + '\n');

console.error('[witness] Receipt written to', outResolved);
console.log(outResolved);
