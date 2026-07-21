/**
 * @module envelope/statement
 *
 * The in-toto Statement v1 wrapper around a WitnessRecord (AWP spec §4). A
 * Statement is the DSSE *payload*: it binds the governed artifact in its
 * `subject[]` and carries the WitnessRecord as its `predicate` under the AWP
 * predicate namespace. The Statement (not the bare record) is what gets
 * canonicalized, framed by DSSE PAE, and signed in `./dsse`.
 *
 * Shape (spec §4):
 * ```json
 * {
 *   "_type": "https://in-toto.io/Statement/v1",
 *   "subject": [{ "name": "<target_ref>", "digest": { "sha256": "<params_hash>" } }],
 *   "predicateType": "https://awp.paybotfin.com/witness-record/v1",
 *   "predicate": { ...WitnessRecord }
 * }
 * ```
 *
 * Subject binding (AC5): `subject[0].name === intent.target_ref` and
 * `subject[0].digest.sha256 === intent.params_hash`. This is what ties the
 * signed envelope to the specific governed action — the params hash is the
 * digest, the target ref is the name.
 *
 * This module imports the AW-1 schema (types + validator + the namespace
 * constants); it never re-defines the record (AW-2 scope: schema is import-only).
 *
 * Dependencies: `../schema` (AW-1), `./canonical-json`.
 * Used by: `./dsse` (encode/decode/verify).
 */

import {
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  validateWitnessRecord,
  type WitnessRecord,
} from '../schema/index.js';
import type { JsonValue } from './canonical-json.js';

/** One in-toto subject — the governed artifact, addressed by name + digest. */
export interface Subject {
  /** The governed artifact's name. For AWP this is `intent.target_ref`. */
  name: string;
  /** Digest set. AWP populates `sha256` from `intent.params_hash`. */
  digest: { sha256: string };
}

/**
 * An in-toto Statement v1 carrying a WitnessRecord as its predicate. The
 * `_type` and `predicateType` are fixed AWP constants; `predicate` is the
 * AW-1 record verbatim.
 */
export interface WitnessStatement {
  /** Always {@link STATEMENT_TYPE}. */
  _type: typeof STATEMENT_TYPE;
  /** Exactly one subject binding the governed action (AC5). */
  subject: [Subject];
  /** Always {@link PREDICATE_TYPE} (the AWP predicate namespace). */
  predicateType: typeof PREDICATE_TYPE;
  /** The WitnessRecord (AW-1 predicate) carried by this Statement. */
  predicate: WitnessRecord;
}

/**
 * Build an in-toto Statement v1 around a WitnessRecord, binding the subject to
 * the record's governed action (AC5: subject name = `intent.target_ref`,
 * subject digest = `intent.params_hash`).
 *
 * The record is NOT re-validated here for shape (the caller is expected to have
 * validated it, e.g. via {@link validateWitnessRecord} or the producer
 * pipeline); this function only constructs the wrapper. Use
 * {@link buildValidatedStatement} when you want validation enforced.
 *
 * @param record - The WitnessRecord to wrap as the Statement predicate.
 * @returns The in-toto Statement (subject bound to intent).
 *
 * @example
 * const stmt = buildStatement(record);
 * stmt.subject[0].name === record.intent.target_ref; // true
 */
export function buildStatement(record: WitnessRecord): WitnessStatement {
  return {
    _type: STATEMENT_TYPE,
    subject: [
      {
        name: record.intent.target_ref,
        digest: { sha256: record.intent.params_hash },
      },
    ],
    predicateType: PREDICATE_TYPE,
    predicate: record,
  };
}

/** Result of {@link buildValidatedStatement}: the statement, or schema errors. */
export type BuildStatementResult =
  | { ok: true; statement: WitnessStatement }
  | { ok: false; errors: string[] };

/**
 * Validate `input` as a WitnessRecord (AW-1 structural schema) and, only if it
 * is valid, build the in-toto Statement around it. Fail-closed: an invalid
 * record yields `{ ok: false, errors }` and never a partial statement.
 *
 * @param input - The candidate record (e.g. parsed JSON).
 * @returns `{ ok: true, statement }` when the record validates, else
 *          `{ ok: false, errors }`. Never throws.
 */
export function buildValidatedStatement(input: unknown): BuildStatementResult {
  const parsed = validateWitnessRecord(input);
  if (!parsed.ok) {
    return { ok: false, errors: parsed.errors };
  }
  return { ok: true, statement: buildStatement(parsed.record) };
}

/**
 * A structural problem found while checking a decoded Statement (used by the
 * verifier so each failure is named, never a bare boolean).
 */
export type StatementShapeFailure = { ok: false; reason: string };
/** The Statement passed every structural check. */
export type StatementShapeOk = { ok: true; statement: WitnessStatement };
/** Result of {@link checkStatementShape}. */
export type StatementShapeResult = StatementShapeOk | StatementShapeFailure;

/**
 * Verify that an already-parsed JSON value is a well-formed AWP in-toto
 * Statement and that its predicate is a valid WitnessRecord whose intent matches
 * the subject binding (AC5). This is the trust gate the DSSE verifier runs
 * AFTER the signature check and BEFORE returning the record (threat model:
 * "verify asserts `payloadType` and `_type`/`predicateType` before trusting the
 * payload").
 *
 * Checks, in order, each returning a NAMED reason on failure:
 *  - `_type` equals {@link STATEMENT_TYPE};
 *  - `predicateType` equals {@link PREDICATE_TYPE};
 *  - `subject` is an array of exactly one entry with a `name` and
 *    `digest.sha256`;
 *  - the predicate is a structurally-valid WitnessRecord (AW-1);
 *  - the subject binds the predicate's `intent.target_ref` /
 *    `intent.params_hash` (AC5) — guards against a signed-but-mismatched
 *    subject.
 *
 * @param value - The decoded payload JSON (unknown shape).
 * @returns `{ ok: true, statement }` or `{ ok: false, reason }`. Never throws.
 */
export function checkStatementShape(value: unknown): StatementShapeResult {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'statement is not a JSON object' };
  }
  const obj = value as Record<string, unknown>;

  if (obj['_type'] !== STATEMENT_TYPE) {
    return {
      ok: false,
      reason: `statement _type must be "${STATEMENT_TYPE}", got ${JSON.stringify(obj['_type'])}`,
    };
  }
  if (obj['predicateType'] !== PREDICATE_TYPE) {
    return {
      ok: false,
      reason: `statement predicateType must be "${PREDICATE_TYPE}", got ${JSON.stringify(obj['predicateType'])}`,
    };
  }

  const subject = obj['subject'];
  if (!Array.isArray(subject) || subject.length !== 1) {
    return { ok: false, reason: 'statement subject must be an array of exactly one entry' };
  }
  const subj = subject[0] as Record<string, unknown> | undefined;
  const digest = subj?.['digest'] as Record<string, unknown> | undefined;
  if (
    subj === null ||
    typeof subj !== 'object' ||
    typeof subj['name'] !== 'string' ||
    digest === undefined ||
    typeof digest['sha256'] !== 'string'
  ) {
    return { ok: false, reason: 'statement subject[0] must have a string name and digest.sha256' };
  }

  const parsed = validateWitnessRecord(obj['predicate']);
  if (!parsed.ok) {
    return { ok: false, reason: `statement predicate is not a valid WitnessRecord: ${parsed.errors.join('; ')}` };
  }

  const record = parsed.record;
  if (subj['name'] !== record.intent.target_ref) {
    return {
      ok: false,
      reason: `subject[0].name (${JSON.stringify(subj['name'])}) does not bind intent.target_ref (${JSON.stringify(record.intent.target_ref)})`,
    };
  }
  if (digest['sha256'] !== record.intent.params_hash) {
    return {
      ok: false,
      reason: 'subject[0].digest.sha256 does not bind intent.params_hash',
    };
  }

  return {
    ok: true,
    statement: {
      _type: STATEMENT_TYPE,
      subject: [{ name: subj['name'], digest: { sha256: digest['sha256'] } }],
      predicateType: PREDICATE_TYPE,
      predicate: record,
    },
  };
}

/**
 * Narrowing helper: a {@link WitnessStatement} is itself a {@link JsonValue}
 * (its fields are all JSON). This cast is centralised here so callers don't
 * repeat it. Safe because the type only contains JSON-representable fields.
 *
 * @param statement - The statement to view as a plain JSON value.
 * @returns The same object typed as {@link JsonValue}.
 */
export function statementAsJson(statement: WitnessStatement): JsonValue {
  return statement as unknown as JsonValue;
}
