/**
 * Profile vector tests — each canonical sample record in
 * `test/schema/vectors/` must pass BOTH the structural validator and its
 * profile's constraint validator. These vectors become the sample receipts in
 * later stories, so a green run here is the "at least one valid record per
 * profile" Quality-Foundation requirement (AW-1 Tests & docs).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  validateRecordAndProfile,
  type Profile,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, 'vectors');

function loadVector(name: string): unknown {
  return JSON.parse(readFileSync(join(vectorsDir, name), 'utf8'));
}

const cases: ReadonlyArray<{ file: string; profile: Profile }> = [
  { file: 'valid-pay.json', profile: 'pay' },
  { file: 'valid-doc.json', profile: 'doc' },
  { file: 'valid-principal.json', profile: 'principal' },
  { file: 'valid-composite.json', profile: 'composite' },
];

describe('[VECTOR] profile sample receipts', () => {
  it.each(cases)('$file passes schema + $profile profile', ({ file, profile }) => {
    const result = validateRecordAndProfile(loadVector(file));
    if (!result.ok) {
      // Surface the exact failure to make a broken vector obvious.
      throw new Error(
        `${file} failed at ${result.stage}: ${JSON.stringify(result, null, 2)}`,
      );
    }
    expect(result.ok).toBe(true);
    expect(result.profile).toBe(profile);
  });
});
