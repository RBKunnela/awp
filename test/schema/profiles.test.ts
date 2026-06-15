/**
 * Profile constraint tests for `validateProfile` / `validateRecordAndProfile`.
 *
 * Maps directly to AW-1 acceptance criteria:
 *  - AC1 profile-pay-requires-mandate-auth
 *  - AC2 profile-principal-requires-binding
 *  - AC3 profile-doc-requires-artifact
 *  - AC6 composite binds the e-commerce scene
 * Each validator has ≥3 tests across happy/error/edge.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  validateProfile,
  validateRecordAndProfile,
  type WitnessRecord,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));

function vector(name: string): WitnessRecord {
  return JSON.parse(readFileSync(join(here, 'vectors', name), 'utf8')) as WitnessRecord;
}

const pay = () => vector('valid-pay.json');
const doc = () => vector('valid-doc.json');
const principal = () => vector('valid-principal.json');
const composite = () => vector('valid-composite.json');

// ---------------------------------------------------------------------------
// AC1 — pay requires a mandate-class authorization + ≥1 verification.
// ---------------------------------------------------------------------------
describe('[UNIT] validateProfile pay (AC1)', () => {
  it('passes for a full pay record (happy)', () => {
    const r = validateProfile(pay());
    expect(r.ok).toBe(true);
  });

  it('fails when the authorization block is missing (error)', () => {
    const rec = pay();
    delete (rec as Partial<WitnessRecord>).authorization;
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'AUTHORIZATION_REQUIRED')).toBe(true);
    }
  });

  it('fails when the credential is not mandate-class (error)', () => {
    const rec = pay();
    rec.authorization!.credential.type = 'oidc';
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(
        r.failures.some((f) => f.constraint === 'MANDATE_CLASS_CREDENTIAL_REQUIRED'),
      ).toBe(true);
    }
  });

  it('fails when there are zero verifications on the record (edge)', () => {
    const rec = pay();
    rec.verifications = [];
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'VERIFICATION_REQUIRED')).toBe(true);
    }
  });

  it('accepts sd-jwt-vc as a mandate-class credential (edge)', () => {
    const rec = pay();
    rec.authorization!.credential.type = 'sd-jwt-vc';
    expect(validateProfile(rec).ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC2 — principal requires intent binding (challenge or presentation).
// ---------------------------------------------------------------------------
describe('[UNIT] validateProfile principal (AC2)', () => {
  it('passes with presentation_binding present (happy)', () => {
    expect(validateProfile(principal()).ok).toBe(true);
  });

  it('passes with challenge_binding present instead (edge)', () => {
    const rec = principal();
    delete rec.authorization!.credential.presentation_binding;
    rec.authorization!.credential.challenge_binding = {
      challenge: 'chal-001',
      canonicalization: 'awp-canon-v1',
      evidence_hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      display_mechanism: 'none',
    };
    expect(validateProfile(rec).ok).toBe(true);
  });

  it('fails when neither binding is present (error — session is not enough)', () => {
    const rec = principal();
    delete rec.authorization!.credential.presentation_binding;
    delete rec.authorization!.credential.challenge_binding;
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'INTENT_BINDING_REQUIRED')).toBe(true);
    }
  });

  it('fails when the authorization block is missing entirely (error)', () => {
    const rec = principal();
    delete (rec as Partial<WitnessRecord>).authorization;
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'AUTHORIZATION_REQUIRED')).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// AC3 — doc requires ≥1 artifact; authorization optional.
// ---------------------------------------------------------------------------
describe('[UNIT] validateProfile doc (AC3)', () => {
  it('passes with ≥1 artifact and no authorization (happy — proves less)', () => {
    const rec = doc();
    expect(rec.authorization).toBeUndefined();
    expect(validateProfile(rec).ok).toBe(true);
  });

  it('fails with zero artifacts (error)', () => {
    const rec = doc();
    rec.artifacts = [];
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'ARTIFACT_REQUIRED')).toBe(true);
    }
  });

  it('fails when the artifacts block is absent (edge)', () => {
    const rec = doc();
    delete (rec as Partial<WitnessRecord>).artifacts;
    expect(validateProfile(rec).ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC6 — composite binds intent + ≥1 artifact + authorization.
// ---------------------------------------------------------------------------
describe('[UNIT] validateProfile composite (AC6)', () => {
  it('passes for the full e-commerce scene (happy)', () => {
    expect(validateProfile(composite()).ok).toBe(true);
  });

  it('fails when the artifact is missing (error)', () => {
    const rec = composite();
    rec.artifacts = [];
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'ARTIFACT_REQUIRED')).toBe(true);
    }
  });

  it('fails when the authorization is missing (error)', () => {
    const rec = composite();
    delete (rec as Partial<WitnessRecord>).authorization;
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'AUTHORIZATION_REQUIRED')).toBe(true);
    }
  });

  it('fails when the credential is not mandate-class (error)', () => {
    const rec = composite();
    rec.authorization!.credential.type = 'oidc';
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(
        r.failures.some((f) => f.constraint === 'MANDATE_CLASS_CREDENTIAL_REQUIRED'),
      ).toBe(true);
    }
  });

  it('fails when there are zero verifications (error)', () => {
    const rec = composite();
    rec.verifications = [];
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.failures.some((f) => f.constraint === 'VERIFICATION_REQUIRED')).toBe(true);
    }
  });

  it('reports BOTH missing constraints when artifact and auth are absent (edge)', () => {
    const rec = composite();
    delete (rec as Partial<WitnessRecord>).authorization;
    rec.artifacts = [];
    const r = validateProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const codes = r.failures.map((f) => f.constraint);
      expect(codes).toContain('AUTHORIZATION_REQUIRED');
      expect(codes).toContain('ARTIFACT_REQUIRED');
    }
  });
});

// ---------------------------------------------------------------------------
// Combined structural + profile validator.
// ---------------------------------------------------------------------------
describe('[UNIT] validateRecordAndProfile', () => {
  it('returns ok with record + profile for a valid record (happy)', () => {
    const r = validateRecordAndProfile(pay());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.profile).toBe('pay');
  });

  it('short-circuits at stage:schema for a malformed record (error)', () => {
    const r = validateRecordAndProfile({ profile: 'pay' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.stage).toBe('schema');
  });

  it('reaches stage:profile when shape is valid but minimums unmet (edge)', () => {
    const rec = pay();
    rec.verifications = [];
    const r = validateRecordAndProfile(rec);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.stage).toBe('profile');
  });
});
