/**
 * Honesty-boundary tests — the typed guarantees that make overclaim
 * unrepresentable (AWP spec §4, AW-1 threat model).
 *
 *  - AC5: claim_class is a closed enum; any other value is rejected.
 *  - assurance_echo is an echoed string only — there is no field that lets a
 *    record assert identity-proofing or authenticity-at-origin.
 *  - The PII-smuggling guard (AC4) is exercised here from the boundary angle.
 *
 * These tests document, in executable form, what the schema REFUSES to
 * represent — the wrong claim must not validate.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  validateWitnessRecord,
  CLAIM_CLASSES,
  type WitnessRecord,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));

function pay(): WitnessRecord {
  return JSON.parse(
    readFileSync(join(here, 'vectors', 'valid-pay.json'), 'utf8'),
  ) as WitnessRecord;
}

describe('[UNIT] claim_class enum is enforced (AC5)', () => {
  it('accepts each of the three legitimate claim classes (happy)', () => {
    for (const cc of CLAIM_CLASSES) {
      const rec = pay();
      rec.verifications![0]!.claim_class = cc;
      expect(validateWitnessRecord(rec).ok).toBe(true);
    }
  });

  it('rejects an authenticity-at-origin claim class (error — overclaim)', () => {
    const rec = pay() as unknown as { verifications: { claim_class: string }[] };
    rec.verifications[0]!.claim_class = 'authenticity-at-origin';
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('claim_class'))).toBe(true);
    }
  });

  it('rejects an identity-proofing claim class (error — overclaim)', () => {
    const rec = pay() as unknown as { verifications: { claim_class: string }[] };
    rec.verifications[0]!.claim_class = 'identity-proofing';
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });

  it('rejects an empty claim_class (edge)', () => {
    const rec = pay() as unknown as { verifications: { claim_class: string }[] };
    rec.verifications[0]!.claim_class = '';
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });

  it('exposes exactly the three sanctioned claim classes (guard)', () => {
    expect([...CLAIM_CLASSES]).toEqual([
      'integrity-since-witness',
      'verified-against',
      'asserted-by',
    ]);
  });
});

describe('[UNIT] assurance_echo is echo-only — no asserted assurance field', () => {
  it('accepts an echoed assurance string (happy)', () => {
    const rec = pay();
    rec.authorization!.credential.assurance_echo = 'eIDAS-high';
    expect(validateWitnessRecord(rec).ok).toBe(true);
  });

  it('accepts a record with no assurance_echo at all (edge — optional)', () => {
    const rec = pay();
    delete rec.authorization!.credential.assurance_echo;
    expect(validateWitnessRecord(rec).ok).toBe(true);
  });

  it('refuses any sibling field claiming asserted assurance (error — strict)', () => {
    const rec = pay() as unknown as {
      authorization: { credential: Record<string, unknown> };
    };
    // A producer trying to assert (not echo) assurance has no legal field;
    // strict mode rejects the smuggled key.
    rec.authorization.credential.assurance_asserted = 'identity-proofed';
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });
});

describe('[UNIT] PII smuggling guard from the boundary angle (AC4)', () => {
  it('refuses a plain-sha256 digest flagged PII-bearing (error)', () => {
    const rec = pay() as WitnessRecord & {
      artifacts: NonNullable<WitnessRecord['artifacts']>;
    };
    rec.artifacts = [
      {
        role: 'input',
        digest: {
          alg: 'sha256',
          value: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        },
        media_type: 'application/json',
        size: 128,
        pii_bearing: true,
      },
    ];
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });
});
