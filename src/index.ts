/**
 * @module agent-witness-protocol
 *
 * Package root for the OPEN Agent Witness Protocol (AWP) schema + validators.
 *
 * AW-1 ships the data definition: the WitnessRecord v0.1 types, the structural
 * validator, the typed honesty-boundary enums, and the four profile constraint
 * validators (pay | doc | principal | composite).
 *
 * AW-2 adds the envelope: the DSSE v1.0 + in-toto Statement v1 wrapper
 * (encode / decode / sign / verify) that turns a validated record into a
 * portable, signed, offline-verifiable unit.
 *
 * AW-3 adds the offline verifier: `verify(input, options)` (library) and the
 * `awp verify <file>` CLI compose the schema, envelope, honesty-boundary,
 * chain-link, and (when present) OpenTimestamps anchor checks into one fail-
 * closed per-check report — zero network, zero producer relationship. The OTS
 * anchor read path ships under `./anchor`. The Merkle log and checkpoint
 * signing arrive in later stories and re-export from here.
 *
 * Dependencies: `./schema`, `./envelope`, `./anchor`, `./verify`.
 * Used by: external consumers (`import { ... } from 'agent-witness-protocol'`)
 *          and the private producer's emitter (which depends on this package).
 *
 * @example
 * import { validateRecordAndProfile, signEnvelope, verifyEnvelope, createTestSigner }
 *   from 'agent-witness-protocol';
 * const r = validateRecordAndProfile(JSON.parse(raw));
 * if (r.ok) {
 *   const { signer, publicKey } = createTestSigner();
 *   const env = signEnvelope(r.record, signer);
 *   console.log(verifyEnvelope(env, publicKey).ok);
 * }
 */

export * from './schema/index.js';
export * from './envelope/index.js';
export * from './anchor/index.js';
export * from './log/index.js';
export * from './ops/index.js';
export * from './verify/index.js';
