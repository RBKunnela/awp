/**
 * @module envelope
 *
 * Barrel for the AWP DSSE v1.0 + in-toto Statement v1 envelope (AW-2). This is
 * the portable, signed unit: a validated WitnessRecord (AW-1) wrapped in an
 * in-toto Statement and signed with the deployment's Ed25519 key, verifiable
 * offline with a tiny, re-implementable algorithm (DSSE PAE).
 *
 * The schema (AW-1) is imported, never re-defined here. Signing keys live with
 * the caller (a {@link Signer} closure) — this OPEN package holds nothing.
 *
 * Dependencies: `./canonical-json`, `./statement`, `./dsse`, `../schema`.
 * Used by: the package root `src/index.ts`, the AW-3 `awp verify` CLI, and
 *          downstream producers.
 *
 * @example
 * import { signEnvelope, verifyEnvelope, createTestSigner } from 'agent-witness-protocol';
 * const { signer, publicKey } = createTestSigner();
 * const env = signEnvelope(record, signer);
 * const result = verifyEnvelope(env, publicKey);
 * if (result.ok) console.log(result.record.profile);
 */

export {
  pae,
  encodePayload,
  statementPayloadBytes,
  signEnvelope,
  decodeEnvelope,
  verifyEnvelope,
  createTestSigner,
  signerFromPrivateKey,
  buildStatement,
} from './dsse.js';

export type {
  DsseEnvelope,
  DsseSignature,
  Signer,
  SignFn,
  PublicKeyInput,
  DecodeResult,
  VerifyEnvelopeResult,
  EnvelopeCheck,
} from './dsse.js';

export {
  buildValidatedStatement,
  checkStatementShape,
  statementAsJson,
} from './statement.js';

export type {
  WitnessStatement,
  Subject,
  BuildStatementResult,
  StatementShapeResult,
} from './statement.js';

export {
  sortObjectKeys,
  canonicalJSONStringify,
  canonicalJSONBytes,
} from './canonical-json.js';

export type { JsonValue } from './canonical-json.js';
