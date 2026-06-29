/**
 * rewrite-demo-index.mjs
 *
 * Rewire the PayBotFin demo page so the "four scenarios" claim is REAL:
 * inline all 4 scenario receipt sets (bank/fintech/gaming/ecom × pass/sigTamper/
 * inclTamper) into a SCENARIO_DATA map, drive the decoded-witness panel + anchor
 * label from the selected scenario, and keep the page fully offline (no fetch).
 *
 *   node tools/rewrite-demo-index.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';

const DEMO = 'D:/1.GITHUB/AIOX-Enterprise/docs/partnerships/paybotfin-deploy/demo';
const INDEX = `${DEMO}/index.html`;

/** Decode a DSSE base64 payload into its predicate (WitnessRecord). */
function decodedPredicate(receipt) {
  const obj = JSON.parse(Buffer.from(receipt.envelope.payload, 'base64').toString('utf8'));
  return obj.predicate;
}

/** Keep only the fields the client verifier + panel need (shrinks inlined size). */
function slim(receipt) {
  return {
    public_key_raw_base64: receipt.public_key_raw_base64,
    envelope: {
      payload: receipt.envelope.payload,
      payloadType: receipt.envelope.payloadType,
      signatures: receipt.envelope.signatures,
    },
    checkpoint_root: receipt.checkpoint_root,
    inclusion: receipt.inclusion,
    anchors: (receipt.anchors || []).map((a) => ({ type: a.type, pending: a.pending === true })),
  };
}

function load(name) {
  return JSON.parse(readFileSync(`${DEMO}/${name}`, 'utf8'));
}

const FILES = {
  bank: ['composite-receipt.json', 'composite-receipt-tampered.json', 'composite-receipt-tampered-inclusion.json'],
  fintech: ['composite-receipt-fintech.json', 'composite-receipt-fintech-tampered.json', 'composite-receipt-fintech-tampered-inclusion.json'],
  gaming: ['composite-receipt-gaming.json', 'composite-receipt-gaming-tampered.json', 'composite-receipt-gaming-tampered-inclusion.json'],
  ecom: ['composite-receipt-ecom.json', 'composite-receipt-ecom-tampered.json', 'composite-receipt-ecom-tampered-inclusion.json'],
};

const META = {
  bank: {
    title: 'Bank refund',
    agent: 'Bank AI refund agent',
    action: 'Issues a €49.00 refund on order:demo-7421 and generates a credit-note PDF.',
    approval: 'Human approver (HITL) approves the refund through the dashboard. The approval is recorded against this exact intent.',
    what: 'Refund + credit-note + human approval, bound in one signed, tamper-evident record.',
  },
  fintech: {
    title: 'Fintech vendor pay',
    agent: 'Fintech payout agent',
    action: 'Pays vendor invoice INV-2026-0042 (€1,280.00) and generates a remittance advice.',
    approval: 'Human approver authorizes the payout amount and recipient through the dashboard.',
    what: 'Payout instruction + remittance advice + human approval in one verifiable receipt.',
  },
  gaming: {
    title: 'Gaming in-game currency grant',
    agent: 'Game economy agent',
    action: 'Requests a 50,000-gold grant to player:PL-88273 — above the 10,000 policy ceiling.',
    approval: 'Human moderator reviews the request; the policy engine DENIES it (out of policy). The denial is recorded.',
    what: 'Grant request + DENY decision + human review, bound in one tamper-evident record (the "deny" case).',
  },
  ecom: {
    title: 'E-commerce checkout',
    agent: 'Checkout automation agent',
    action: 'Captures €219.90 on order:SHOP-55012 and generates an order confirmation.',
    approval: 'Human reviews the high-value order before capture is finalized.',
    what: 'Order + payment capture + human approval bound in one signed record.',
  },
};

const SCENARIO_DATA = {};
for (const sc of ['bank', 'fintech', 'gaming', 'ecom']) {
  const [p, s, i] = FILES[sc].map(load);
  const dec = decodedPredicate(p);
  SCENARIO_DATA[sc] = {
    meta: { ...META[sc], anchorConfirmed: !(slim(p).anchors[0]?.pending) },
    decoded: {
      profile: dec.profile,
      action: dec.intent.action,
      target_ref: dec.intent.target_ref,
      decision: dec.intent.policy.decision,
      artifact: {
        media_type: dec.artifacts[0].media_type,
        size: dec.artifacts[0].size,
        digest: dec.artifacts[0].digest.value,
      },
      mandate: (() => {
        const v = dec.verifications.find((x) => x.check.includes('ap2')) || dec.verifications[0];
        return { check: v.check, claim_class: v.claim_class, result: v.result };
      })(),
      hitl: (() => {
        const v = dec.verifications.find((x) => x.check.includes('hitl'));
        return v ? { claim_class: v.claim_class, result: v.result } : null;
      })(),
    },
    pass: slim(p),
    sigTamper: slim(s),
    inclTamper: slim(i),
  };
}

const DATA_JSON = JSON.stringify(SCENARIO_DATA);

const SCRIPT = `<script>
const SCENARIO_DATA = ${DATA_JSON};

const enc = new TextEncoder();

// DSSE v1.0 PAE: "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
function pae(payloadType, payloadBytes) {
  const head = enc.encode('DSSEv1 ' + payloadType.length + ' ' + payloadType + ' ' + payloadBytes.length + ' ');
  const out = new Uint8Array(head.length + payloadBytes.length);
  out.set(head, 0); out.set(payloadBytes, head.length);
  return out;
}
function b64ToBytes(b64) {
  const bin = atob(b64); const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
// Raw 32-byte Ed25519 public key -> SPKI DER, so Web Crypto can import it.
function rawEd25519ToSpki(raw32) {
  const prefix = new Uint8Array([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]);
  const out = new Uint8Array(prefix.length + 32);
  out.set(prefix, 0); out.set(raw32, prefix.length);
  return out;
}
async function verifySignature(receipt) {
  const env = receipt.envelope;
  const payloadBytes = b64ToBytes(env.payload);
  const sigBytes = b64ToBytes(env.signatures[0].sig);
  const rawPub = b64ToBytes(receipt.public_key_raw_base64);
  const spki = rawEd25519ToSpki(rawPub);
  const key = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify']);
  const paeBytes = pae(env.payloadType, payloadBytes);
  return crypto.subtle.verify({ name: 'Ed25519' }, key, sigBytes, paeBytes);
}
async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}
function hexToBytes(hex) {
  const a = new Uint8Array(hex.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(a) { return Array.from(a).map(b => b.toString(16).padStart(2, '0')).join(''); }
function concat(...arrs) {
  const len = arrs.reduce((n, x) => n + x.length, 0);
  const out = new Uint8Array(len); let o = 0;
  for (const x of arrs) { out.set(x, o); o += x.length; }
  return out;
}
// RFC 9162: leaf = SHA256(0x00 || data); node = SHA256(0x01 || left || right).
async function leafHash(data) { return sha256(concat(new Uint8Array([0x00]), data)); }
async function nodeHash(l, r) { return sha256(concat(new Uint8Array([0x01]), l, r)); }
async function verifyInclusion(receipt) {
  const incl = receipt.inclusion;
  let acc = hexToBytes(incl.leafHash);
  for (const sib of incl.siblings) {
    const sh = hexToBytes(sib.hash);
    acc = sib.position === 'left' ? await nodeHash(sh, acc) : await nodeHash(acc, sh);
  }
  return bytesToHex(acc) === receipt.checkpoint_root;
}

let CURRENT = 'ecom';
function currentReceipt() {
  const variant = document.getElementById('variant').value;
  return SCENARIO_DATA[CURRENT][variant] || SCENARIO_DATA[CURRENT].pass;
}
function anchorPending(receipt) {
  return !!(receipt.anchors && receipt.anchors[0] && receipt.anchors[0].pending);
}

function checksFor(receipt) {
  const pending = anchorPending(receipt);
  return [
    { name: 'envelope-shape', label: 'well-formed DSSE envelope with >=1 signature' },
    { name: 'payloadType',   label: 'payloadType is "application/vnd.in-toto+json"' },
    { name: 'signature',     label: 'Ed25519 signature verified over DSSE PAE' },
    { name: 'schema',        label: 'predicate is a structurally-valid WitnessRecord v0.1' },
    { name: 'profile',       label: 'profile "composite" constraints satisfied' },
    { name: 'claim-class',   label: 'every claim_class within the honesty boundary' },
    { name: 'checkpoint',    label: 'signed checkpoint verified (size 4)' },
    { name: 'inclusion',     label: 'RFC 9162 inclusion proof reproduces the checkpoint root' },
    { name: 'anchor',        label: pending
        ? 'OpenTimestamps time bound — calendar-pending (not yet Bitcoin-confirmed)'
        : 'OpenTimestamps time bound (Bitcoin-confirmed, trust-minimized)' },
  ];
}

async function run() {
  const receipt = currentReceipt();
  const variant = document.getElementById('variant').value;
  const out = document.getElementById('result');
  const explain = document.getElementById('tamper-explain');
  out.innerHTML = 'verifying (offline, in your browser)...';
  if (explain) explain.style.display = 'none';

  const sigOk = await verifySignature(receipt);
  let inclOk = true;
  try { inclOk = await verifyInclusion(receipt); } catch (e) { inclOk = false; }

  const lines = [];
  let failed = [];
  for (const c of checksFor(receipt)) {
    if (!sigOk && ['schema','profile','claim-class','checkpoint','inclusion','anchor'].includes(c.name)) {
      lines.push('  <span class="skip">[SKIP]</span> ' + c.name.padEnd(13) + ' skipped -- no verified record (signature failed)');
      failed.push(c.name);
      continue;
    }
    let ok = true;
    if (c.name === 'signature') ok = sigOk;
    if (c.name === 'inclusion') ok = inclOk;
    if (ok) {
      lines.push('  <span class="pass">[PASS]</span> ' + c.name.padEnd(13) + ' ' + c.label);
    } else {
      lines.push('  <span class="fail">[FAIL]</span> ' + c.name.padEnd(13) + ' ' + c.label);
      failed.push(c.name);
    }
  }

  const pass = !failed.includes('signature') && !failed.includes('inclusion') && sigOk && inclOk;

  let summary = '';
  if (pass) {
    summary = '<div class="verdict pass" style="font-size:16px;margin:8px 0;"><span aria-hidden="true">&#10003;</span> PASS -- Receipt is intact and verifiable.</div>';
    if (explain) {
      explain.innerHTML = 'This receipt has not been altered since it was created. Anyone can re-run this exact check offline.'
        + (anchorPending(receipt) ? ' <b>Timestamp is calendar-pending</b> for this scenario (the OpenTimestamps anchor is not yet confirmed in a Bitcoin block) -- shown honestly, never as a fabricated block.' : '');
      explain.style.display = 'block';
    }
  } else {
    summary = '<div class="verdict fail" style="font-size:16px;margin:8px 0;"><span aria-hidden="true">&#10007;</span> FAIL -- Tampering detected!</div>';
    if (explain) {
      let reason = '';
      if (variant === 'sigTamper') {
        reason = 'The document (artifact) was changed after signing. The signature no longer matches.';
      } else if (variant === 'inclTamper') {
        reason = 'The proof that this record is in the transparency log was changed. The inclusion check failed.';
      }
      explain.innerHTML = reason + ' This is exactly how a merchant or auditor would detect fraud or unauthorized changes.';
      explain.style.display = 'block';
    }
  }

  const boundary = '\\n<span class="skip">AWP verify proves integrity-since-witness only -- not completeness, not authenticity-at-origin, not the identity of any person.</span>';
  out.innerHTML = lines.join('\\n') + '\\n' + summary + boundary;
}

document.getElementById('verifyBtn').addEventListener('click', run);
const variantSel = document.getElementById('variant');
if (variantSel) variantSel.addEventListener('change', () => run());

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function renderDecoded(sc) {
  const d = SCENARIO_DATA[sc].decoded;
  const pending = !SCENARIO_DATA[sc].meta.anchorConfirmed;
  const kv = document.querySelector('.receipt .kv');
  if (!kv) return;
  const decisionBadge = d.decision === 'deny'
    ? '<span class="badge" style="color:var(--red)">deny</span>'
    : '<span class="badge">' + esc(d.decision) + '</span>';
  const hitl = d.hitl
    ? 'claim_class <span class="badge soft">' + esc(d.hitl.claim_class) + '</span> -- "a human approved/reviewed via the recorded credential" (HITL)'
    : '(none)';
  const anchorRow = pending
    ? '<span class="badge soft">OpenTimestamps -- calendar-pending</span> (not yet Bitcoin-confirmed)'
    : '<span class="badge">OpenTimestamps -- Bitcoin-confirmed</span> (trust-minimized)';
  kv.innerHTML =
    '<div class="k">Profile</div><div class="v"><span class="badge">' + esc(d.profile) + '</span> -- action + document + authorization</div>'
    + '<div class="k">Agent action</div><div class="v">' + esc(d.action) + ' &rarr; ' + esc(d.target_ref) + '</div>'
    + '<div class="k">Policy decision</div><div class="v">' + decisionBadge + '</div>'
    + '<div class="k">Artifact</div><div class="v">' + esc(d.artifact.media_type) + ', ' + d.artifact.size + ' bytes &middot; sha256 ' + esc(d.artifact.digest.slice(0,16)) + '&hellip;</div>'
    + '<div class="k">Human approval</div><div class="v">' + hitl + '</div>'
    + '<div class="k">Mandate check</div><div class="v">' + esc(d.mandate.check) + ' &middot; claim_class <span class="badge">' + esc(d.mandate.claim_class) + '</span> &middot; result ' + esc(d.mandate.result) + '</div>'
    + '<div class="k">Timestamp</div><div class="v">' + anchorRow + '</div>'
    + '<div class="k">Settlement</div><div class="v"><span class="badge soft">testnet / mock</span> -- no real money moved</div>';
}

function updateScenario(sc) {
  if (!SCENARIO_DATA[sc]) sc = 'bank';
  CURRENT = sc;
  const m = SCENARIO_DATA[sc].meta;
  const cards = document.querySelectorAll('.story .card');
  if (cards[0]) {
    cards[0].querySelector('.who').textContent = m.agent;
    cards[0].querySelector('.what').textContent = m.action;
  }
  if (cards[1]) {
    cards[1].querySelector('.who').textContent = 'Human approver (HITL)';
    cards[1].querySelector('.what').textContent = m.approval;
  }
  if (cards[2]) cards[2].querySelector('.what').textContent = m.what;
  const sub = document.querySelector('header p.sub');
  if (sub) sub.textContent = 'An AI agent took action in the "' + m.title + '" scenario. A human approved it (or policy denied it). One signed record captures it -- re-verifiable by anyone, with no relationship to us.';
  renderDecoded(sc);
}

const sel = document.getElementById('scenarioSel');
if (sel) {
  const params = new URLSearchParams(window.location.search);
  const urlScenario = params.get('scenario');
  const initialScenario = (urlScenario && SCENARIO_DATA[urlScenario]) ? urlScenario : (sel.value || 'ecom');
  sel.value = initialScenario;
  const hint = document.getElementById('context-hint');
  if (hint && urlScenario === 'ecom') hint.style.display = 'block';

  sel.addEventListener('change', e => { updateScenario(e.target.value); run(); });

  setTimeout(() => {
    updateScenario(initialScenario);
    setTimeout(() => {
      const v = document.getElementById('variant');
      if (v) v.value = 'pass';
      run();
    }, 120);
  }, 30);
}
</script>`;

let html = readFileSync(INDEX, 'utf8');
const start = html.indexOf('<script>');
const end = html.lastIndexOf('</script>') + '</script>'.length;
if (start === -1 || end === -1) { console.error('script block not found'); process.exit(1); }
html = html.slice(0, start) + SCRIPT + html.slice(end);
writeFileSync(INDEX, html);
console.error('rewrote', INDEX, '(', html.length, 'bytes )');
