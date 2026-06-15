/**
 * JSON Schema parity tests — the `witness-record.schema.json` document is the
 * non-TypeScript view of the same record. These tests do NOT pull in a
 * JSON-Schema validation engine (kept dependency-free for AW-1); they assert
 * that the schema document is well-formed and structurally agrees with the Zod
 * types on the load-bearing invariants: required top-level blocks, the
 * claim-class enum, the digest-alg enum, and the namespace placeholder.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  CLAIM_CLASSES,
  DIGEST_ALGS,
  PROFILES,
  PREDICATE_TYPE,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = join(here, '..', '..', 'src', 'schema', 'witness-record.schema.json');

interface JsonSchemaDoc {
  $schema: string;
  $id: string;
  required: string[];
  properties: {
    profile: { enum: string[] };
  };
  $defs: {
    verification: { properties: { claim_class: { enum: string[] } } };
    artifactDigest: { properties: { alg: { enum: string[] } } };
  };
}

function loadSchema(): JsonSchemaDoc {
  return JSON.parse(readFileSync(schemaPath, 'utf8')) as JsonSchemaDoc;
}

describe('[UNIT] witness-record.schema.json — well-formed and consistent', () => {
  it('parses as JSON and declares draft 2020-12 (happy)', () => {
    const schema = loadSchema();
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
  });

  it('requires the same always-present top-level blocks as the Zod schema', () => {
    const schema = loadSchema();
    for (const block of ['profile', 'deployment', 'intent', 'chain']) {
      expect(schema.required).toContain(block);
    }
  });

  it('lists exactly the four profiles (parity)', () => {
    const schema = loadSchema();
    expect([...schema.properties.profile.enum].sort()).toEqual([...PROFILES].sort());
  });

  it('lists exactly the three claim classes — the honesty boundary (parity)', () => {
    const schema = loadSchema();
    expect([...schema.$defs.verification.properties.claim_class.enum].sort()).toEqual(
      [...CLAIM_CLASSES].sort(),
    );
  });

  it('lists exactly the two digest algorithms (parity)', () => {
    const schema = loadSchema();
    expect([...schema.$defs.artifactDigest.properties.alg.enum].sort()).toEqual(
      [...DIGEST_ALGS].sort(),
    );
  });

  it('uses the placeholder namespace, not a committed domain (edge)', () => {
    const schema = loadSchema();
    expect(schema.$id).toContain('placeholder');
    expect(PREDICATE_TYPE).toContain('placeholder');
  });
});
