/**
 * Exhaustive smoke of agent-witness-protocol as published on npm.
 * Run: node tools/exhaustive-npm-smoke.mjs
 * Or from a clean dir after: npm i agent-witness-protocol
 *
 * Covers: package resolve, library exports, schema validate, full verify PASS,
 * one-byte inclusion FAIL isolation, wrong pubkey, malformed JSON, CLI exit codes.
 */
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

const results = [];
function ok(name, pass, detail = '') {
  results.push({ name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
}

// Prefer installed package; fall back to local dist for in-repo runs before install
let pkgRoot;
let awp;
try {
  pkgRoot = dirname(require.resolve('agent-witness-protocol/package.json'));
  awp = await import('agent-witness-protocol');
  ok('resolve agent-witness-protocol from node_modules', true, pkgRoot);
} catch {
  pkgRoot = root;
  const { pathToFileURL } = await import('node:url');
  awp = await import(pathToFileURL(join(root, 'dist/index.js')).href);
  ok('resolve local dist (package not in node_modules)', true, pkgRoot);
}

const {
  validateWitnessRecord,
  validateProfile,
  verify,
  PREDICATE_TYPE,
  PAYLOAD_TYPE,
} = awp;

ok('PREDICATE_TYPE is production host', PREDICATE_TYPE === 'https://awp.paybotfin.com/witness-record/v1', PREDICATE_TYPE);
ok('PAYLOAD_TYPE is in-toto', PAYLOAD_TYPE === 'application/vnd.in-toto+json', PAYLOAD_TYPE);

const samplePath = join(pkgRoot, 'samples/receipt.json');
ok('sample receipt ships in package', existsSync(samplePath), samplePath);
const receipt = JSON.parse(readFileSync(samplePath, 'utf8'));

// Library verify PASS — publicKey is required (CLI embeds it from the file)
const pubkey = receipt.public_key_pem || receipt.public_key_raw_base64;
ok('sample embeds public key', Boolean(pubkey));
const passReport = verify(receipt, { publicKey: pubkey });
ok('library verify PASS on sample', passReport.ok === true, `checks=${passReport.checks?.length}`);
const checkNames = (passReport.checks || []).map((c) => c.name);
for (const need of ['signature', 'statement', 'schema', 'profile', 'claim-class', 'inclusion', 'checkpoint', 'anchor']) {
  ok(`check present: ${need}`, checkNames.includes(need), checkNames.join(','));
}

// Schema-only path on predicate if we can decode — at least validate fixture vectors if available
const vectorPath = join(root, 'test/schema/vectors/valid-pay.json');
if (existsSync(vectorPath)) {
  const rec = JSON.parse(readFileSync(vectorPath, 'utf8'));
  const v = validateWitnessRecord(rec);
  ok('validateWitnessRecord valid-pay', v.ok === true, v.ok ? '' : JSON.stringify(v.errors));
  if (v.ok) {
    const p = validateProfile(v.record);
    ok('validateProfile pay', p.ok === true, p.ok ? '' : JSON.stringify(p.failures));
  }
} else {
  ok('validateWitnessRecord (skipped — no local vectors in npm layout)', true, 'n/a');
}

// Tamper: flip one hex char in inclusion sibling
const tampered = JSON.parse(JSON.stringify(receipt));
const sib = tampered.inclusion.siblings[0].hash;
const flipped = (sib[0] === 'a' ? 'b' : 'a') + sib.slice(1);
tampered.inclusion.siblings[0].hash = flipped;
const failReport = verify(tampered, { publicKey: pubkey });
ok('tampered inclusion → verify FAIL', failReport.ok === false);
const failed = (failReport.checks || []).filter((c) => !c.ok).map((c) => c.name);
ok('tamper isolates inclusion', failed.includes('inclusion'), failed.join(','));
const stillPass = (failReport.checks || []).filter((c) => c.ok).map((c) => c.name);
ok('tamper keeps signature PASS', stillPass.includes('signature'));
ok('tamper keeps schema PASS', stillPass.includes('schema'));

// Wrong public key (garbage PEM should fail signature)
const wrongKey = verify(receipt, {
  publicKey:
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA//////////////////////////////////////////8=\n-----END PUBLIC KEY-----\n',
});
ok('wrong key → FAIL', wrongKey.ok === false);

// Malformed
try {
  const m = verify({ not: 'a receipt' }, { publicKey: pubkey });
  ok('malformed receipt → FAIL or throws', m.ok === false, JSON.stringify(m).slice(0, 80));
} catch (e) {
  ok('malformed receipt → throws (acceptable)', true, e.message?.slice(0, 60));
}

// CLI
const binCandidates = [
  join(pkgRoot, 'bin/awp.js'),
  join(root, 'bin/awp.js'),
];
const bin = binCandidates.find((p) => existsSync(p));
if (bin) {
  const r1 = spawnSync(process.execPath, [bin, 'verify', samplePath], { encoding: 'utf8' });
  ok('CLI exit 0 on sample', r1.status === 0, `status=${r1.status}`);
  ok('CLI prints RESULT: PASS', (r1.stdout + r1.stderr).includes('RESULT: PASS'));
  ok('CLI prints honesty boundary', (r1.stdout + r1.stderr).includes('integrity-since-witness'));

  const tmp = mkdtempSync(join(tmpdir(), 'awp-smoke-'));
  const badPath = join(tmp, 'tampered.json');
  writeFileSync(badPath, JSON.stringify(tampered));
  const r2 = spawnSync(process.execPath, [bin, 'verify', badPath], { encoding: 'utf8' });
  ok('CLI exit non-zero on tamper', r2.status !== 0, `status=${r2.status}`);
  ok('CLI names inclusion on tamper', (r2.stdout + r2.stderr).includes('inclusion'));
} else {
  ok('CLI bin present', false, 'bin/awp.js not found');
}

// Summary
const failedCount = results.filter((r) => !r.pass).length;
console.log('\n=== SUMMARY ===');
console.log(`total=${results.length} pass=${results.length - failedCount} fail=${failedCount}`);
if (failedCount) {
  console.log('Failed:');
  for (const r of results.filter((x) => !x.pass)) console.log(' -', r.name, r.detail);
  process.exit(1);
}
console.log('All exhaustive smoke checks passed.');
process.exit(0);
