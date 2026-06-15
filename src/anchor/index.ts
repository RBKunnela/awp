/**
 * @module anchor
 *
 * Barrel for the AWP external-anchor layer. Two anchor paths, both PER CHECKPOINT
 * (never per record):
 *
 *  - **OpenTimestamps (OTS)** — the free, trust-minimized, buildable-NOW anchor.
 *    OFFLINE verify (`readOtsProof` / `verifyOtsAnchor`, zero network) plus the
 *    PRODUCER-side `submitCheckpoint` (stamp a checkpoint root at OTS calendars →
 *    pending proof) and `upgradeProof` (pending → Bitcoin-confirmed). Submit /
 *    upgrade take an injected HTTP transport so callers — and tests — control the
 *    network; nothing here opens a socket on its own.
 *
 *  - **RFC 3161** — a TSA-agnostic timestamp VERIFY slot (`verifyRfc3161Anchor`):
 *    verify a TimeStampToken's message imprint, TSA signature chain, and genTime
 *    against a SUPPLIED trust anchor. A free non-qualified TSA token and a
 *    qualified eIDAS TSA token use the SAME code path; the qualified vendor is
 *    added later by CONFIG (the trust anchor + its `qualified` flag), not code.
 *
 * Honest evidentiary weight: an OTS proof is reported as trust-minimized
 * (Bitcoin), never as carrying the qualified eIDAS presumption; an RFC 3161 token
 * is reported as `qualified` ONLY when verified against a trust anchor explicitly
 * declared qualified.
 *
 * Dependencies: `./types`, `./opentimestamps`, `./ots-submit`, `./rfc3161`.
 * Used by: `../verify` (AW-6 wires the checks) and the package root.
 */

export {
  ANCHOR_TYPES,
  ANCHOR_WEIGHTS,
} from './types.js';

export type {
  AnchorType,
  AnchorWeight,
  AnchorProof,
  OtsAnchorProof,
  Rfc3161AnchorProof,
  Receipt,
} from './types.js';

export {
  readOtsProof,
  verifyOtsAnchor,
  buildTestOtsProof,
  assembleOtsProof,
  parseOtsTimestamp,
  buildTestCalendarTimestamp,
  testCalendarCommitment,
} from './opentimestamps.js';

export type { OtsReadResult } from './opentimestamps.js';

export {
  submitCheckpoint,
  upgradeProof,
  DEFAULT_OTS_CALENDARS,
} from './ots-submit.js';

export type {
  OtsHttp,
  SubmitOptions,
  SubmitResult,
  UpgradeResult,
  CalendarSubmission,
} from './ots-submit.js';

export {
  verifyRfc3161Anchor,
  verifyRfc3161Token,
  parseTimeStampToken,
} from './rfc3161.js';

export type {
  Rfc3161TrustAnchor,
  Rfc3161VerifyOptions,
  Rfc3161VerifyResult,
  TimeStampInfo,
} from './rfc3161.js';
