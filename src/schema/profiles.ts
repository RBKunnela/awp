/**
 * @module schema/profiles
 *
 * Profile constraint validators for WitnessRecord v0.1. A profile is NOT a
 * separate schema — it is a CONSTRAINT SET layered on the one schema (AWP spec
 * §4). `validateWitnessRecord` (in `./witness-record`) checks structure;
 * `validateProfile` here checks the per-profile minimums:
 *
 *  - `pay`       — authorization present, credential is mandate-class, and ≥1
 *                  verification entry exists on the record.
 *  - `doc`       — ≥1 artifact; authorization optional (unattended generation is
 *                  witnessable — it just proves less).
 *  - `principal` — authorization whose credential is bound to THIS intent
 *                  (challenge_binding OR presentation_binding) — not a session.
 *  - `composite` — the e-commerce scene: intent + ≥1 artifact + authorization,
 *                  i.e. at least the union of the pay and doc minimums.
 *
 * Each failure is TYPED (a `constraint` code + a human message) so a caller can
 * branch on the missing constraint rather than parse prose.
 *
 * Dependencies: `./witness-record` (types + the structural validator + the
 *               mandate-class credential list).
 * Used by: `./index` (barrel), producers (validate before signing), verifiers
 *          (validate before trusting), and the AW-1 acceptance tests.
 */

import {
  MANDATE_CLASS_CREDENTIAL_TYPES,
  validateWitnessRecord,
  type MandateClassCredentialType,
  type Profile,
  type WitnessRecord,
} from './witness-record.js';

/**
 * A machine-readable code for one unmet profile constraint. Callers branch on
 * this; the human `message` is for logs and error surfaces.
 */
export type ProfileConstraintCode =
  | 'AUTHORIZATION_REQUIRED'
  | 'MANDATE_CLASS_CREDENTIAL_REQUIRED'
  | 'VERIFICATION_REQUIRED'
  | 'ARTIFACT_REQUIRED'
  | 'INTENT_BINDING_REQUIRED';

/** One typed profile-constraint failure. */
export interface ProfileFailure {
  /** Machine-readable constraint code. */
  constraint: ProfileConstraintCode;
  /** Human-readable explanation naming the missing constraint. */
  message: string;
}

/**
 * The result of {@link validateProfile}: `ok: true` when every constraint for
 * the record's profile is met, else the list of typed failures. Never throws.
 */
export type ProfileResult =
  | { ok: true; profile: Profile }
  | { ok: false; profile: Profile; failures: ProfileFailure[] };

/**
 * True when the record carries an authorization whose credential type is in the
 * mandate class ({@link MANDATE_CLASS_CREDENTIAL_TYPES}).
 *
 * @param record - A structurally-valid WitnessRecord.
 * @returns Whether a mandate-class credential is present.
 */
function hasMandateClassCredential(record: WitnessRecord): boolean {
  const type = record.authorization?.credential.type;
  return (
    type !== undefined &&
    (MANDATE_CLASS_CREDENTIAL_TYPES as readonly string[]).includes(type as MandateClassCredentialType)
  );
}

/**
 * True when the record's authorization credential is bound to THIS intent via
 * either of the two standardized primitives (WebAuthn challenge binding or
 * OpenID4VP presentation binding). Session-level auth with neither binding is
 * insufficient for the `principal` profile.
 *
 * @param record - A structurally-valid WitnessRecord.
 * @returns Whether the credential is intent-bound.
 */
function hasIntentBinding(record: WitnessRecord): boolean {
  const credential = record.authorization?.credential;
  if (!credential) return false;
  return (
    credential.challenge_binding !== undefined ||
    credential.presentation_binding !== undefined
  );
}

/** True when the record has at least one artifact. */
function hasArtifact(record: WitnessRecord): boolean {
  return (record.artifacts?.length ?? 0) > 0;
}

/** True when the record has at least one verification entry. */
function hasVerification(record: WitnessRecord): boolean {
  return (record.verifications?.length ?? 0) > 0;
}

/**
 * Collect the unmet constraints for a record under ITS declared profile.
 * Returns an empty array when the profile's minimums are all satisfied.
 *
 * @param record - A structurally-valid WitnessRecord.
 * @returns The list of typed failures (empty when the profile is satisfied).
 */
function collectFailures(record: WitnessRecord): ProfileFailure[] {
  const failures: ProfileFailure[] = [];

  switch (record.profile) {
    case 'pay': {
      // pay = mandate-class authorization + ≥1 verification on the record.
      if (!record.authorization) {
        failures.push({
          constraint: 'AUTHORIZATION_REQUIRED',
          message: 'profile "pay" requires an authorization block',
        });
      } else if (!hasMandateClassCredential(record)) {
        failures.push({
          constraint: 'MANDATE_CLASS_CREDENTIAL_REQUIRED',
          message:
            'profile "pay" requires a mandate-class credential ' +
            `(one of: ${MANDATE_CLASS_CREDENTIAL_TYPES.join(', ')})`,
        });
      }
      if (!hasVerification(record)) {
        failures.push({
          constraint: 'VERIFICATION_REQUIRED',
          message: 'profile "pay" requires at least one verification entry',
        });
      }
      break;
    }

    case 'doc': {
      // doc = ≥1 artifact; authorization optional (proves less, and says so).
      if (!hasArtifact(record)) {
        failures.push({
          constraint: 'ARTIFACT_REQUIRED',
          message: 'profile "doc" requires at least one artifact',
        });
      }
      break;
    }

    case 'principal': {
      // principal = authorization bound to THIS intent (challenge/presentation).
      if (!record.authorization) {
        failures.push({
          constraint: 'AUTHORIZATION_REQUIRED',
          message: 'profile "principal" requires an authorization block',
        });
      } else if (!hasIntentBinding(record)) {
        failures.push({
          constraint: 'INTENT_BINDING_REQUIRED',
          message:
            'profile "principal" requires the credential to be bound to this intent ' +
            'via challenge_binding or presentation_binding (a session is not enough)',
        });
      }
      break;
    }

    case 'composite': {
      // composite = union of pay + doc minimums: intent (always present) +
      // ≥1 artifact + an authorization block.
      if (!record.authorization) {
        failures.push({
          constraint: 'AUTHORIZATION_REQUIRED',
          message: 'profile "composite" requires an authorization block',
        });
      } else if (!hasMandateClassCredential(record)) {
        failures.push({
          constraint: 'MANDATE_CLASS_CREDENTIAL_REQUIRED',
          message:
            'profile "composite" requires a mandate-class credential ' +
            `(one of: ${MANDATE_CLASS_CREDENTIAL_TYPES.join(', ')})`,
        });
      }
      if (!hasArtifact(record)) {
        failures.push({
          constraint: 'ARTIFACT_REQUIRED',
          message: 'profile "composite" requires at least one artifact',
        });
      }
      if (!hasVerification(record)) {
        failures.push({
          constraint: 'VERIFICATION_REQUIRED',
          message: 'profile "composite" requires at least one verification entry',
        });
      }
      break;
    }
  }

  return failures;
}

/**
 * Validate a structurally-valid WitnessRecord against the constraint set for
 * its declared `profile` (AWP spec §4 profiles).
 *
 * Precondition: `record` should already satisfy the structural schema (call
 * {@link validateWitnessRecord} first, or use {@link validateRecordAndProfile}).
 * This function trusts the shape and checks only the profile minimums.
 *
 * @param record - A structurally-valid WitnessRecord.
 * @returns `{ ok: true, profile }` when every constraint is met, else
 *          `{ ok: false, profile, failures }` with one typed failure per unmet
 *          constraint. Never throws.
 *
 * @example
 * const r = validateProfile(record);
 * if (!r.ok) {
 *   for (const f of r.failures) console.error(f.constraint, f.message);
 * }
 */
export function validateProfile(record: WitnessRecord): ProfileResult {
  const failures = collectFailures(record);
  if (failures.length === 0) {
    return { ok: true, profile: record.profile };
  }
  return { ok: false, profile: record.profile, failures };
}

/**
 * Discriminated result for {@link validateRecordAndProfile}: a structural
 * failure (`stage: 'schema'`), a profile failure (`stage: 'profile'`), or
 * success with the typed record.
 */
export type FullValidationResult =
  | { ok: true; record: WitnessRecord; profile: Profile }
  | { ok: false; stage: 'schema'; errors: string[] }
  | { ok: false; stage: 'profile'; profile: Profile; failures: ProfileFailure[] };

/**
 * Convenience: run the structural validator and then the profile validator in
 * one call, short-circuiting on the first failing stage. This is the function
 * most producers and verifiers actually want.
 *
 * @param input - The candidate value (e.g. parsed JSON).
 * @returns Success with `{ record, profile }`, or a stage-tagged failure.
 *          Never throws.
 *
 * @example
 * const r = validateRecordAndProfile(JSON.parse(raw));
 * if (!r.ok && r.stage === 'schema') { /* malformed record *\/ }
 * if (!r.ok && r.stage === 'profile') { /* shape ok, profile minimums unmet *\/ }
 */
export function validateRecordAndProfile(input: unknown): FullValidationResult {
  const structural = validateWitnessRecord(input);
  if (!structural.ok) {
    return { ok: false, stage: 'schema', errors: structural.errors };
  }
  const profile = validateProfile(structural.record);
  if (!profile.ok) {
    return {
      ok: false,
      stage: 'profile',
      profile: profile.profile,
      failures: profile.failures,
    };
  }
  return { ok: true, record: structural.record, profile: structural.record.profile };
}
