/**
 * @module verify
 *
 * Barrel for the AWP offline verifier (AW-3). `verify(input, options)` is the
 * library contract; the `awp verify <file>` CLI is a thin formatter over it.
 * Verifies — offline, zero network, zero producer relationship — a signed DSSE
 * envelope or a full receipt: signature, in-toto statement + subject binding,
 * WitnessRecord schema + profile, the claim-class honesty boundary, the
 * per-record hash-chain link, and (when present) an OpenTimestamps anchor.
 *
 * Dependencies: `./verify`, `./checks`.
 * Used by: `../cli/awp`, the package root, and downstream programmatic callers.
 */

export { verify, asReceipt } from './verify.js';
export type { VerifyReport, VerifyOptions } from './verify.js';

export {
  checkSchemaAndProfile,
  checkSignature,
  checkClaimClassHonesty,
  checkChainLink,
  checkCheckpoint,
  checkInclusion,
  checkAnchor,
  recordCommitment,
  recordLeafBytes,
  timeBoundingLine,
  HONESTY_BOUNDARY_LINE,
} from './checks.js';
export type { CheckResult, CheckContext } from './checks.js';
