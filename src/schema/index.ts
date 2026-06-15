/**
 * @module schema
 *
 * Barrel for the AWP open schema: the WitnessRecord v0.1 types, the structural
 * validator, the honesty-boundary enums, and the per-profile constraint
 * validators. This is the public surface every producer and verifier imports.
 *
 * Dependencies: `./witness-record`, `./profiles`.
 * Used by: the package root `src/index.ts` and all downstream consumers.
 */

export {
  // Constants / namespaces
  STATEMENT_TYPE,
  PAYLOAD_TYPE,
  PREDICATE_TYPE,
  // Honesty-boundary + profile enums
  PROFILES,
  CLAIM_CLASSES,
  CREDENTIAL_TYPES,
  MANDATE_CLASS_CREDENTIAL_TYPES,
  DIGEST_ALGS,
  // Schema + validators
  WitnessRecordSchema,
  validateWitnessRecord,
  isWitnessRecord,
} from './witness-record.js';

export type {
  Profile,
  ClaimClass,
  CredentialType,
  MandateClassCredentialType,
  DigestAlg,
  Software,
  Deployment,
  Agent,
  Policy,
  Intent,
  ChallengeBinding,
  PresentationBinding,
  StatusCheck,
  Credential,
  Authorization,
  ArtifactDigest,
  OriginClaim,
  Provenance,
  Artifact,
  Verification,
  Chain,
  ErasureEvent,
  WitnessRecord,
  WitnessRecordResult,
} from './witness-record.js';

export {
  validateProfile,
  validateRecordAndProfile,
} from './profiles.js';

export type {
  ProfileConstraintCode,
  ProfileFailure,
  ProfileResult,
  FullValidationResult,
} from './profiles.js';
