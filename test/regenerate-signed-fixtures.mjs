/**
 * AWP-PUBLISH-1 Task 3 — regenerate every signed fixture after the permanent
 * namespace lands (`https://awp.dev/witness-record/v1`).
 *
 * Run from package root:
 *
 *   npm run build
 *   node test/regenerate-signed-fixtures.mjs
 *
 * Chains:
 *   - test/envelope/vectors/generate-vectors.mjs
 *   - test/verify/fixtures/generate-fixtures.mjs
 *   - test/verify/fixtures/generate-full-receipt.mjs
 *
 * Log vectors (test/log/vectors/generate-vectors.mjs) do not embed PREDICATE_TYPE
 * and are left alone.
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function run(rel) {
  const script = join(root, rel);
  console.log('\n===', rel, '===');
  const r = spawnSync(process.execPath, [script], {
    cwd: root,
    stdio: 'inherit',
  });
  if (r.status !== 0) {
    process.exit(r.status ?? 1);
  }
}

run('test/envelope/vectors/generate-vectors.mjs');
run('test/verify/fixtures/generate-fixtures.mjs');
run('test/verify/fixtures/generate-full-receipt.mjs');

console.log('\nAll signed fixtures regenerated under awp.dev namespace.');
console.log('Next: npm test  (expect 368 pass) && rg "placeholder\\.invalid" src test samples');
