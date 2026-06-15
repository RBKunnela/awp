/**
 * @module verify/verify
 *
 * The library entry point for `awp verify`: `verify(input, options): VerifyReport`.
 * The CLI is a thin formatter over this contract (AW-3 CLI-First principle).
 *
 * `verify` accepts EITHER a bare DSSE envelope (AW-2 wire shape) OR a `Receipt`
 * (an envelope plus optional external anchor proofs and a checkpoint binding).
 * It runs every applicable check, fail-closed, and returns a per-check report
 * whose `ok` is true only when ALL applicable checks passed — never a bare
 * boolean (AC4). It performs ZERO network and ZERO filesystem I/O (AC3): the
 * caller supplies already-parsed JSON; the CLI does the single file read.
 *
 * What it verifies (composing AW-1 + AW-2 + AW-4 + AW-5, no duplication):
 *  - the DSSE Ed25519 signature over the in-toto Statement (AW-2);
 *  - the in-toto Statement shape + subject binding to the intent (AW-2);
 *  - the WitnessRecord schema + the profile minimums (AW-1);
 *  - the claim-class honesty boundary (no overclaim);
 *  - the per-record hash-chain link;
 *  - when present, the signed C2SP checkpoint (AW-4) — its note signature and
 *    the root it commits;
 *  - when present, the RFC 9162 inclusion proof (AW-4) — the record's leaf folds
 *    to the signed checkpoint root;
 *  - when present, the external time anchor(s) (AW-5: OpenTimestamps and/or an
 *    RFC 3161 token) over that root, reported as an honest time BOUND on the
 *    record with the anchor's evidentiary weight.
 *
 * The checkpoint runs BEFORE inclusion and anchor so both bind to the SIGNED root
 * (not an unverified field): a full receipt is airtight only when the inclusion
 * proof, the checkpoint, and the anchor all agree on one root.
 *
 * Silent partial verification is itself a failure (threat model): when an early
 * check (signature) fails such that later checks cannot run, those later checks
 * are reported as `skipped` lines (ok:false with a reason), never dropped.
 *
 * Dependencies: `./checks`, `../envelope`, `../anchor`, `../schema`.
 * Used by: `../cli/awp`, `./index`, downstream programmatic callers.
 */

import type { PublicKeyInput } from '../envelope/index.js';
import type { Receipt, Rfc3161TrustAnchor } from '../anchor/index.js';
import type { FullReceipt } from '../ops/index.js';
import {
  checkAnchor,
  checkChainLink,
  checkCheckpoint,
  checkClaimClassHonesty,
  checkInclusion,
  checkSchemaAndProfile,
  checkSignature,
  HONESTY_BOUNDARY_LINE,
  type CheckResult,
} from './checks.js';

/**
 * Options for {@link verify}. The public key is required (verification is
 * meaningless without the key the signature must check against). The optional
 * predecessor hash drives the chain-link comparison.
 */
export interface VerifyOptions {
  /** The Ed25519 public key the envelope must verify against. */
  publicKey: PublicKeyInput;
  /** Optional predecessor record hash for the chain-link check. */
  expectedPrevRecordHash?: string;
  /**
   * Optional pinned RFC 3161 trust anchor (the TSA signing key + `qualified`
   * flag). Required to verify an RFC 3161 anchor unless the receipt embeds one
   * (`rfc3161_trust_anchor`). Never inferred — the verifier trusts no TSA
   * implicitly, and reports `qualified` weight only when this anchor declares it.
   */
  rfc3161TrustAnchor?: Rfc3161TrustAnchor;
}

/**
 * The full report `verify` returns. `ok` is the AND of every applicable check.
 * `checks` is the ordered per-check list (the legible report). `boundary` is
 * the verbatim honesty-boundary line the report always carries.
 */
export interface VerifyReport {
  /** True only when every applicable check passed. */
  ok: boolean;
  /** The ordered, named per-check results (always populated). */
  checks: CheckResult[];
  /** The verbatim honesty-boundary statement (always present). */
  boundary: string;
  /** The record profile, when the record decoded far enough to know it. */
  profile?: string;
}

/**
 * Normalize the two accepted input shapes to a `Receipt`. A bare DSSE envelope
 * (has `payload` + `signatures`) is wrapped as an anchorless receipt; a value
 * that already looks like a receipt (has an `envelope`) is used as-is.
 *
 * @param input - A DSSE envelope or a Receipt (already JSON-parsed).
 * @returns A Receipt view, or `undefined` if the shape is neither.
 */
export function asReceipt(input: unknown): Receipt | undefined {
  if (input === null || typeof input !== 'object') return undefined;
  const obj = input as Record<string, unknown>;
  if ('envelope' in obj && obj['envelope'] !== undefined) {
    return obj as unknown as Receipt;
  }
  if ('payload' in obj && 'signatures' in obj) {
    return { envelope: input };
  }
  return undefined;
}

/**
 * Verify a signed envelope or a full receipt, returning a complete per-check
 * report. Never throws on bad input — a malformed top-level shape becomes a
 * single failing `input` check.
 *
 * @param input - A DSSE envelope or a {@link Receipt} (already JSON-parsed).
 * @param options - The public key (required) and optional predecessor hash.
 * @returns A {@link VerifyReport}; `ok` true only when all applicable checks pass.
 *
 * @example
 * const report = verify(receipt, { publicKey });
 * if (!report.ok) for (const c of report.checks) if (!c.ok) console.error(c.name, c.reason);
 */
export function verify(input: unknown, options: VerifyOptions): VerifyReport {
  const receipt = asReceipt(input);
  if (receipt === undefined) {
    return {
      ok: false,
      checks: [
        {
          name: 'input',
          ok: false,
          reason: 'input is neither a DSSE envelope nor a receipt (expected an object with "payload"+"signatures", or an "envelope")',
        },
      ],
      boundary: HONESTY_BOUNDARY_LINE,
    };
  }

  const checks: CheckResult[] = [];
  const full = receipt as FullReceipt;

  // 1. signature + in-toto statement + subject binding (AW-2). This is the gate:
  //    it both proves the signature and yields the trusted decoded record.
  const sig = checkSignature(receipt.envelope, options.publicKey);
  checks.push(...sig.checks);

  if (sig.record === undefined) {
    // Signature/statement failed — later checks have no trusted record to run on.
    // Report them as skipped (not dropped): silent partial verification is a FAIL.
    for (const name of ['schema', 'profile', 'claim-class', 'chain-link', 'checkpoint', 'inclusion', 'anchor']) {
      checks.push({ name, ok: false, reason: 'skipped — no verified record (signature/statement check failed)' });
    }
    return { ok: false, checks, boundary: HONESTY_BOUNDARY_LINE };
  }

  const record = sig.record;

  // 2+3. schema + profile (AW-1). The record came from a verified statement, but
  //      we still report schema/profile explicitly so the report is complete.
  const sp = checkSchemaAndProfile(record);
  checks.push(...sp.checks);

  // 4. claim-class honesty boundary.
  checks.push(checkClaimClassHonesty(record));

  // 5. per-record chain link.
  checks.push(checkChainLink(record, options.expectedPrevRecordHash));

  // 6. signed C2SP checkpoint (AW-4) — verify FIRST so the inclusion proof and the
  //    anchors fold/bind against the SIGNED root, not an unverified field.
  const cp = checkCheckpoint(full);
  checks.push(cp.check);

  // 7. RFC 9162 inclusion proof (AW-4) — the record's leaf is in the checkpoint's
  //    tree. Folds against the signed checkpoint root when the checkpoint verified.
  checks.push(checkInclusion(full, record, cp.rootHex));

  // 8. external time anchor(s) (AW-5) — the checkpoint root existed at time T;
  //    reported as an honest time BOUND on the record, with the anchor's weight.
  checks.push(
    checkAnchor(full, record, cp.rootHex, options.rfc3161TrustAnchor),
  );

  const ok = checks.every((c) => c.ok);
  return { ok, checks, boundary: HONESTY_BOUNDARY_LINE, profile: record.profile };
}
