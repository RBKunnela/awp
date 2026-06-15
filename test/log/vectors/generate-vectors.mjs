/**
 * Regenerate the committed RFC 9162 / C2SP known-answer vectors from the SHIPPED
 * implementation (dist/log). Run from the package root after `npm run build`:
 *
 *   node test/log/vectors/generate-vectors.mjs
 *
 * Vectors are deterministic: leaves are the ASCII bytes of `leaf-0`, `leaf-1`, …
 * The checkpoint/signed-note vector uses a FIXED Ed25519 seed (test-only key, in
 * this file) so the signed note is byte-reproducible — never a production key.
 *
 * Coverage of the dual-rule disambiguation: `merkle-rule-divergence.json` records
 * the SAME leaves under BOTH the standard RFC9162 raw-byte node rule and the
 * separate utf8-hex-text node rule, with their DIFFERING roots, so the boundary
 * is captured as data, not just prose.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import {
  merkleTreeHash,
  hashLeaf,
  hashNode,
  hashNodeUtf8Hex,
  buildInclusionProof,
  buildConsistencyProof,
  toHex,
  encodeCheckpoint,
  signNote,
  keyId,
} from '../../../dist/log/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const enc = (s) => new TextEncoder().encode(s);
const leaves = (n) => Array.from({ length: n }, (_, i) => enc(`leaf-${i}`));

function write(name, obj) {
  writeFileSync(join(here, name), JSON.stringify(obj, null, 2) + '\n');
  console.log('wrote', name);
}

// --- 1. Inclusion known-answer (tree of 7 leaves, prove index 3) -------------
{
  const es = leaves(7);
  const root = merkleTreeHash(es);
  const proof = buildInclusionProof(es, 3);
  write('inclusion-known-answer.json', {
    description: 'RFC 9162 RFC9162_SHA256 raw-byte inclusion proof, 7 leaves, leaf index 3',
    leafCount: 7,
    leafInputsUtf8: es.map((_, i) => `leaf-${i}`),
    leafIndex: 3,
    leafHashHex: toHex(proof.leafHash),
    rootHex: toHex(root),
    siblingsHex: proof.siblings.map((s) => ({ hashHex: toHex(s.hash), position: s.position })),
  });
}

// --- 2. Consistency append-only pass (m=4 -> n=7) ----------------------------
{
  const es = leaves(7);
  const rootM = merkleTreeHash(es.slice(0, 4));
  const rootN = merkleTreeHash(es);
  const proof = buildConsistencyProof(es, 4);
  write('consistency-append-only.json', {
    description: 'RFC 9162 consistency proof: size 4 -> size 7 by appends only (PASSES)',
    first: 4,
    second: 7,
    leafInputsUtf8: es.map((_, i) => `leaf-${i}`),
    oldRootHex: toHex(rootM),
    newRootHex: toHex(rootN),
    pathHex: proof.path.map(toHex),
  });
}

// --- 3. Consistency rewrite detection (m=4 -> n=7, leaf 1 rewritten) ---------
{
  const original = leaves(7);
  const rewritten = leaves(7);
  rewritten[1] = enc('REWRITTEN');
  const origRootM = merkleTreeHash(original.slice(0, 4));
  const rewrittenRootN = merkleTreeHash(rewritten);
  // Honest proof over the REWRITTEN tree; verified against the ORIGINAL size-4
  // root it must FAIL (the rewrite of an early leaf is evident).
  const proofRewritten = buildConsistencyProof(rewritten, 4);
  write('consistency-rewrite-detected.json', {
    description:
      'Consistency proof built over a tree whose leaf 1 was rewritten; checked against the ORIGINAL size-4 root it must FAIL',
    first: 4,
    second: 7,
    rewrittenLeafIndex: 1,
    originalSize4RootHex: toHex(origRootM),
    rewrittenSize7RootHex: toHex(rewrittenRootN),
    rewrittenProofPathHex: proofRewritten.path.map(toHex),
    expectedVerifyResultAgainstOriginalRoot: false,
  });
}

// --- 4. C2SP checkpoint + signed-note (fixed test key) -----------------------
{
  // Fixed 32-byte Ed25519 seed (test-only). PKCS8 prefix + seed.
  const seed = Buffer.alloc(32, 7); // deterministic seed of 0x07 bytes
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const rawPub = new Uint8Array(spki.subarray(spki.length - 32));
  const name = 'awp.example/log';
  const signer = {
    name,
    publicKey: rawPub,
    sign: (bytes) => new Uint8Array(nodeSign(null, bytes, privateKey)),
  };
  const es = leaves(7);
  const root = merkleTreeHash(es);
  const body = encodeCheckpoint({ origin: name, size: 7, root });
  const note = signNote(body, signer);
  write('checkpoint-signed-note.json', {
    description: 'C2SP tlog-checkpoint over (origin, size=7, root) wrapped in a signed-note (test key)',
    origin: name,
    size: 7,
    rootHex: toHex(root),
    publicKeyHex: toHex(rawPub),
    keyIdHex: toHex(keyId(name, rawPub)),
    checkpointBody: body,
    signedNote: note,
  });
}

// --- 5. Dual Merkle rule divergence (the boundary, as data) ------------------
{
  const a = hashLeaf(enc('leaf-0'));
  const b = hashLeaf(enc('leaf-1'));
  const rawRoot = hashNode(a, b); // standard RFC9162 raw-byte rule
  const hexRoot = hashNodeUtf8Hex(a, b); // separate utf8-hex-text variant
  write('merkle-rule-divergence.json', {
    description:
      'Same two leaves, two node rules. RFC9162 raw-byte (THIS log) vs utf8-hex-text (the separate batch variant). Roots DIFFER.',
    leafInputsUtf8: ['leaf-0', 'leaf-1'],
    leftLeafHashHex: toHex(a),
    rightLeafHashHex: toHex(b),
    rfc9162RawByteRootHex: toHex(rawRoot),
    utf8HexTextRootHex: toHex(hexRoot),
    rootsDiffer: toHex(rawRoot) !== toHex(hexRoot),
  });
}

console.log('all vectors regenerated');
