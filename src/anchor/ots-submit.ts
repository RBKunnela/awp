/**
 * @module anchor/ots-submit
 *
 * OpenTimestamps (OTS) PRODUCER-side anchor path: SUBMIT a checkpoint root to
 * one or more OTS calendar servers and later UPGRADE the resulting pending proof
 * to a Bitcoin-confirmed one. This is the online counterpart to the offline
 * reader in `./opentimestamps` (which verifies a finished `.ots` proof with zero
 * network). Anchoring is PER CHECKPOINT — `submitCheckpoint` takes a checkpoint
 * (root + size + origin), never a single record (spec §2; AW-5 AC5).
 *
 * Honest asynchrony (AW-5 "be honest"): a fresh OTS submission is aggregated by
 * the calendars within seconds but only commits to a Bitcoin block hours later
 * (block-time granularity). So `submitCheckpoint` returns a PENDING proof
 * (`pending: true`); `upgradeProof` is the SEPARATE, later step that turns it
 * into a confirmed proof once a calendar can serve the Bitcoin attestation. This
 * module NEVER fabricates a confirmation — `upgradeProof` only reports confirmed
 * when a calendar actually returns a Bitcoin block-header attestation.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * OTS calendar HTTP protocol (the subset this module uses), from the
 * OpenTimestamps calendar-server spec:
 *
 *   POST {calendar}/digest      body = the raw 32-byte SHA-256 commitment digest
 *     → 200, body = a SERIALIZED TIMESTAMP for that digest: a sequence of
 *       commitment operations ending in a pending/calendar attestation. (No
 *       magic header, no file-hash op — just the timestamp portion that, applied
 *       to the submitted digest, leads to an attestation.)
 *
 *   GET {calendar}/timestamp/{hex-commitment}
 *     → 200, body = an UPGRADED serialized timestamp for that commitment,
 *       containing a Bitcoin block-header attestation once the commitment has
 *       been included in a mined, sufficiently-confirmed block;
 *     → 404 while the commitment is still only pending (not yet in a block).
 *
 * A complete `.ots` proof file is then:
 *   magic-header || version(1) || file-hash-op(sha256=0x08) || <32-byte digest>
 *     || <timestamp bytes from the calendar>
 * — exactly the structure the offline reader in `./opentimestamps` parses. This
 * module assembles that file from the calendar's timestamp bytes so the same
 * reader verifies submitted and upgraded proofs alike.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Network injection (AW-5 tests MUST NOT hit the network): all HTTP goes through
 * an injected {@link OtsHttp} transport. Production callers pass a `fetch`-backed
 * transport; tests pass a deterministic mock. This module performs NO I/O on its
 * own and imports nothing network-related.
 *
 * Dependencies: Node `crypto` (sha256), `./opentimestamps` (proof assembly +
 *   the offline reader, reused — not re-implemented), `./types`, `../log` (the
 *   `Checkpoint` type + `toHex`, imported, never redefined).
 * Used by: the private producer's anchoring scheduler; `./index`.
 */

import { createHash } from 'node:crypto';
import type { Checkpoint } from '../log/index.js';
import { toHex } from '../log/index.js';
import type { OtsAnchorProof } from './types.js';
import {
  assembleOtsProof,
  parseOtsTimestamp,
  readOtsProof,
  type OtsReadResult,
} from './opentimestamps.js';

/**
 * A minimal HTTP transport for OTS calendar calls, injected so the network is
 * mockable and this module stays I/O-free. Implementations: a `fetch` wrapper in
 * production, a deterministic stub in tests.
 */
export interface OtsHttp {
  /**
   * POST the raw commitment `digest` bytes to `{calendarUrl}/digest`.
   *
   * @returns The calendar's serialized timestamp bytes (status 200), or an error
   *   describing a non-200 / transport failure. Implementations should NOT throw
   *   for an HTTP error status — return `{ ok: false }` so the caller can try the
   *   next calendar.
   */
  postDigest(
    calendarUrl: string,
    digest: Uint8Array,
  ): Promise<{ ok: true; timestamp: Uint8Array } | { ok: false; status?: number; reason: string }>;

  /**
   * GET `{calendarUrl}/timestamp/{hexCommitment}` to fetch an upgraded timestamp.
   *
   * @returns `{ ok: true, timestamp }` when the calendar can serve an upgraded
   *   (typically Bitcoin-attested) timestamp; `{ ok: false, status: 404 }` while
   *   the commitment is still pending; `{ ok: false }` on other errors.
   */
  getTimestamp(
    calendarUrl: string,
    hexCommitment: string,
  ): Promise<{ ok: true; timestamp: Uint8Array } | { ok: false; status?: number; reason: string }>;
}

/** The default OpenTimestamps public calendar servers (used if none supplied). */
export const DEFAULT_OTS_CALENDARS: readonly string[] = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
];

/** Options for {@link submitCheckpoint}. */
export interface SubmitOptions {
  /** Calendar base URLs to submit to. Defaults to {@link DEFAULT_OTS_CALENDARS}. */
  calendars?: readonly string[];
  /**
   * Require all calendars to succeed (`true`) or accept the first success
   * (`false`, default — OTS is a one-of-N aggregation, so a single calendar
   * pending proof is a valid anchor; more calendars only add redundancy).
   */
  requireAll?: boolean;
}

/** A single calendar's submission outcome (for transparency in the result). */
export interface CalendarSubmission {
  /** The calendar base URL. */
  calendar: string;
  /** Whether this calendar returned a usable pending timestamp. */
  ok: boolean;
  /** One-line reason (failure detail, or "pending timestamp stored"). */
  reason: string;
}

/** Result of {@link submitCheckpoint}. */
export type SubmitResult =
  | {
      ok: true;
      /**
       * The PENDING OTS anchor proof (`pending: true`) committing the checkpoint
       * root. Store this; later call {@link upgradeProof} to confirm it.
       */
      proof: OtsAnchorProof;
      /** Per-calendar outcomes (at least one `ok`). */
      submissions: CalendarSubmission[];
    }
  | { ok: false; reason: string; submissions: CalendarSubmission[] };

/** SHA-256 of bytes, returning the 32-byte digest. */
function sha256(data: Uint8Array): Buffer {
  return createHash('sha256').update(data).digest();
}

/**
 * Submit a CHECKPOINT's root to OTS calendar(s) and return a PENDING anchor
 * proof. The input is a {@link Checkpoint} (root + size + origin) from AW-4, NOT
 * an individual record — this is the per-checkpoint discipline (AW-5 AC5), and
 * the function only ever reads `checkpoint.root`.
 *
 * The returned proof is honestly `pending: true`: the calendars have aggregated
 * the root but it is not yet in a Bitcoin block. Persist the proof and later call
 * {@link upgradeProof} to obtain the Bitcoin-confirmed proof (hours later).
 *
 * @param checkpoint - The checkpoint whose 32-byte `root` to anchor.
 * @param http - The injected HTTP transport (mock in tests).
 * @param opts - Calendars + one-of-N vs all-of-N policy.
 * @returns A {@link SubmitResult} with the pending proof, or a failure if no
 *   calendar produced a usable timestamp. Never throws.
 *
 * @example
 * const r = await submitCheckpoint(cp, http);
 * if (r.ok) persist(r.proof); // r.proof.pending === true
 */
export async function submitCheckpoint(
  checkpoint: Pick<Checkpoint, 'root'>,
  http: OtsHttp,
  opts: SubmitOptions = {},
): Promise<SubmitResult> {
  const root = checkpoint.root;
  if (!(root instanceof Uint8Array) || root.length !== 32) {
    return {
      ok: false,
      reason: 'checkpoint.root must be a 32-byte SHA-256 (anchor per checkpoint, never per record)',
      submissions: [],
    };
  }
  const calendars = opts.calendars ?? DEFAULT_OTS_CALENDARS;
  if (calendars.length === 0) {
    return { ok: false, reason: 'no OTS calendars supplied', submissions: [] };
  }

  const rootHex = toHex(root);
  const submissions: CalendarSubmission[] = [];
  let firstTimestamp: Uint8Array | undefined;

  for (const calendar of calendars) {
    let res: Awaited<ReturnType<OtsHttp['postDigest']>>;
    try {
      res = await http.postDigest(calendar, root);
    } catch (err) {
      submissions.push({ calendar, ok: false, reason: `transport error: ${(err as Error).message}` });
      continue;
    }
    if (!res.ok) {
      submissions.push({
        calendar,
        ok: false,
        reason: `calendar rejected submission${res.status ? ` (HTTP ${res.status})` : ''}: ${res.reason}`,
      });
      continue;
    }
    // Sanity-check the returned timestamp actually parses and leads to an
    // attestation when applied to the submitted root — never store opaque bytes
    // we could not later verify.
    const proofBytes = assembleOtsProof(root, res.timestamp);
    const parsed = parseOtsTimestamp(res.timestamp, root);
    if (!parsed.ok) {
      submissions.push({ calendar, ok: false, reason: `calendar returned an unparseable timestamp: ${parsed.reason}` });
      continue;
    }
    if (firstTimestamp === undefined) firstTimestamp = res.timestamp;
    submissions.push({ calendar, ok: true, reason: 'pending timestamp stored (awaiting Bitcoin confirmation)' });
    void proofBytes;
  }

  const okCount = submissions.filter((s) => s.ok).length;
  if (okCount === 0) {
    return { ok: false, reason: `all ${calendars.length} calendar submission(s) failed`, submissions };
  }
  if (opts.requireAll && okCount < calendars.length) {
    return {
      ok: false,
      reason: `requireAll set but only ${okCount}/${calendars.length} calendars succeeded`,
      submissions,
    };
  }

  // Assemble the pending `.ots` proof from the first usable calendar timestamp.
  const proofBytes = assembleOtsProof(root, firstTimestamp as Uint8Array);
  return {
    ok: true,
    proof: {
      type: 'ots',
      checkpoint_root: rootHex,
      ots_proof_b64: Buffer.from(proofBytes).toString('base64'),
      pending: true,
    },
    submissions,
  };
}

/** Result of {@link upgradeProof}. */
export type UpgradeResult =
  | {
      /** `confirmed` ⇒ a Bitcoin block-header attestation is now present. */
      status: 'confirmed';
      /** The upgraded proof, now `pending: false`. */
      proof: OtsAnchorProof;
      /** The offline read of the upgraded proof (block heights exposed). */
      read: OtsReadResult;
      /** One-line human summary. */
      reason: string;
    }
  | {
      /** Still pending: no calendar could yet serve a Bitcoin attestation. */
      status: 'still-pending';
      /** The unchanged pending proof. */
      proof: OtsAnchorProof;
      /** One-line human summary. */
      reason: string;
    }
  | {
      /** The upgrade attempt failed (transport / malformed response). */
      status: 'error';
      /** The unchanged pending proof. */
      proof: OtsAnchorProof;
      /** One-line failure reason. */
      reason: string;
    };

/**
 * Attempt to UPGRADE a pending OTS proof to a Bitcoin-confirmed one. Queries the
 * calendar(s) for an upgraded timestamp keyed by the proof's calendar commitment;
 * if a calendar returns a timestamp carrying a Bitcoin block-header attestation,
 * the proof is rebuilt with that attestation and reported `confirmed`. If no
 * calendar can serve a confirmation yet, the proof is returned UNCHANGED and
 * reported `still-pending` — this function NEVER fabricates a confirmation (the
 * Bitcoin commitment is genuinely asynchronous, hours of block time).
 *
 * Mechanics: the calendar commitment is the digest the calendar attested over —
 * i.e. the running OTS message AT the pending attestation, recomputed by walking
 * the proof's operations from the file digest up to (but not into) the pending
 * tag. The upgraded timestamp returned for that commitment is spliced in to
 * replace the pending tail.
 *
 * @param proof - A pending {@link OtsAnchorProof} from {@link submitCheckpoint}.
 * @param http - The injected HTTP transport (mock in tests).
 * @param opts - Calendars to query (defaults to those named in the proof, else
 *   {@link DEFAULT_OTS_CALENDARS}).
 * @returns An {@link UpgradeResult}; never throws.
 *
 * @example
 * const u = await upgradeProof(pending, http);
 * if (u.status === 'confirmed') persist(u.proof); // now Bitcoin-confirmed
 */
export async function upgradeProof(
  proof: OtsAnchorProof,
  http: OtsHttp,
  opts: { calendars?: readonly string[] } = {},
): Promise<UpgradeResult> {
  if (proof.pending !== true) {
    // Already confirmed (or marked non-pending) — re-read and report as-is.
    const read = readProof(proof);
    if (read.ok && read.confirmed) {
      return { status: 'confirmed', proof, read, reason: 'proof was already Bitcoin-confirmed' };
    }
    return { status: 'still-pending', proof, reason: 'proof is not marked pending; nothing to upgrade' };
  }

  let proofBytes: Buffer;
  try {
    proofBytes = Buffer.from(proof.ots_proof_b64, 'base64');
  } catch (err) {
    return { status: 'error', proof, reason: `ots_proof_b64 is not valid base64: ${(err as Error).message}` };
  }

  // Recompute the calendar commitment(s): the message bytes at each pending
  // attestation, and the calendar URI each was served by.
  const pendings = extractPendingCommitments(proofBytes, proof.checkpoint_root);
  if (!pendings.ok) {
    return { status: 'error', proof, reason: pendings.reason };
  }
  if (pendings.commitments.length === 0) {
    return { status: 'error', proof, reason: 'pending proof carries no calendar attestation to upgrade' };
  }

  const calendars =
    opts.calendars ??
    (uniqueCalendars(pendings.commitments).length > 0
      ? uniqueCalendars(pendings.commitments)
      : DEFAULT_OTS_CALENDARS);

  for (const { commitment, calendar } of pendings.commitments) {
    const targets = opts.calendars ?? (calendar ? [calendar] : calendars);
    for (const cal of targets) {
      let res: Awaited<ReturnType<OtsHttp['getTimestamp']>>;
      try {
        res = await http.getTimestamp(cal, toHex(commitment));
      } catch {
        continue; // try the next calendar/commitment
      }
      if (!res.ok) continue; // 404 (still pending) or other — keep trying
      // The upgraded timestamp is for the COMMITMENT message; assemble a full
      // proof by prefixing the original file-hash header + the operations that
      // reach this commitment, then the upgraded tail. Simplest faithful
      // assembly: the upgraded timestamp already starts AT the commitment, so we
      // graft it onto the proof prefix up to this pending attestation.
      const upgraded = graftUpgrade(proofBytes, commitment, res.timestamp, proof.checkpoint_root);
      if (!upgraded.ok) continue;
      const read = readOtsProof(upgraded.bytes, proof.checkpoint_root);
      if (read.ok && read.confirmed) {
        return {
          status: 'confirmed',
          proof: {
            type: 'ots',
            checkpoint_root: proof.checkpoint_root,
            ots_proof_b64: Buffer.from(upgraded.bytes).toString('base64'),
            pending: false,
          },
          read,
          reason: `upgraded to Bitcoin block ${read.block_heights.join(', ')} via ${cal}`,
        };
      }
    }
  }

  return {
    status: 'still-pending',
    proof,
    reason: 'no calendar could serve a Bitcoin attestation yet (commitment not in a confirmed block)',
  };
}

/** Read a proof offline (thin reuse of the reader against the proof's own root). */
function readProof(proof: OtsAnchorProof): OtsReadResult {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(proof.ots_proof_b64, 'base64');
  } catch (err) {
    return { ok: false, reason: `ots_proof_b64 is not valid base64: ${(err as Error).message}` };
  }
  return readOtsProof(bytes, proof.checkpoint_root);
}

/** Unique calendar URIs across a set of pending commitments. */
function uniqueCalendars(commitments: PendingCommitment[]): string[] {
  const set = new Set<string>();
  for (const c of commitments) if (c.calendar) set.add(c.calendar);
  return [...set];
}

/** A calendar commitment recovered from a pending proof. */
interface PendingCommitment {
  /** The 32+-byte message the calendar attested over (the upgrade key). */
  commitment: Buffer;
  /** The calendar URI from the pending attestation body, if present. */
  calendar?: string;
}

/**
 * Walk a pending `.ots` proof and recover, for every pending/calendar
 * attestation, the running message AT that attestation (the calendar's
 * commitment) and the calendar URI. Reuses the reader's parser indirectly by
 * re-deriving the message via the documented operation rules; kept local because
 * the reader exposes only the final attestation summary, not intermediate
 * messages.
 */
function extractPendingCommitments(
  proofBytes: Buffer,
  expectedHexDigest: string,
): { ok: true; commitments: PendingCommitment[] } | { ok: false; reason: string } {
  const parsed = parseOtsHeader(proofBytes, expectedHexDigest);
  if (!parsed.ok) return parsed;
  const commitments: PendingCommitment[] = [];
  try {
    collectPending(new ByteReader(proofBytes, parsed.timestampOffset), Buffer.from(parsed.fileDigest), commitments);
  } catch (err) {
    return { ok: false, reason: `malformed pending proof: ${(err as Error).message}` };
  }
  return { ok: true, commitments };
}

/**
 * Graft an upgraded timestamp onto the proof prefix that reaches `commitment`,
 * replacing the pending attestation whose message equals `commitment`. Produces a
 * full `.ots` proof the offline reader can confirm. Returns `ok: false` if the
 * commitment is not found (so the caller tries another calendar/commitment).
 */
function graftUpgrade(
  proofBytes: Buffer,
  commitment: Buffer,
  upgradedTimestamp: Uint8Array,
  expectedHexDigest: string,
): { ok: true; bytes: Buffer } | { ok: false; reason: string } {
  const parsed = parseOtsHeader(proofBytes, expectedHexDigest);
  if (!parsed.ok) return parsed;
  // Re-serialize: header (magic+ver+filehashop+digest) + a timestamp that applies
  // the SAME operations up to the matched pending attestation, then substitutes
  // the upgraded timestamp at that point. We rebuild by copying proof bytes up to
  // the pending attestation that matches `commitment`, then appending the
  // upgraded timestamp in its place.
  const header = proofBytes.subarray(0, parsed.timestampOffset);
  const rebuilt = replacePendingWithUpgrade(
    new ByteReader(proofBytes, parsed.timestampOffset),
    Buffer.from(parsed.fileDigest),
    commitment,
    Buffer.from(upgradedTimestamp),
  );
  if (!rebuilt.ok) return rebuilt;
  return { ok: true, bytes: Buffer.concat([header, rebuilt.bytes]) };
}

// ───────────────────────── local OTS byte helpers ─────────────────────────
// These mirror the operation/attestation rules documented (and parsed) by
// `./opentimestamps`; they are kept here because grafting an upgrade needs to
// re-emit operation bytes, which the read-only reader does not expose.

const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const TAG_FORK = 0xff;
const TAG_ATTESTATION = 0x00;
const ATTEST_PENDING = Buffer.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);

/** A small forward byte reader with OTS varint support (local copy). */
class ByteReader {
  constructor(
    private readonly buf: Buffer,
    private pos = 0,
  ) {}
  get position(): number {
    return this.pos;
  }
  get remaining(): number {
    return this.buf.length - this.pos;
  }
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error('unexpected end of OTS proof');
    return this.buf[this.pos++] as number;
  }
  peek(): number {
    if (this.pos >= this.buf.length) throw new Error('unexpected end of OTS proof');
    return this.buf[this.pos] as number;
  }
  bytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('unexpected end of OTS proof');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let result = 0;
    let shift = 0;
    for (;;) {
      const b = this.u8();
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 56) throw new Error('OTS varint too large');
    }
    return result;
  }
}

/** Encode a non-negative integer as an OTS varint (LEB128). */
function encodeVarUint(value: number): Buffer {
  if (value < 0) throw new Error('varint must be non-negative');
  const out: number[] = [];
  let v = value;
  do {
    let b = v & 0x7f;
    v = Math.floor(v / 128);
    if (v > 0) b |= 0x80;
    out.push(b);
  } while (v > 0);
  return Buffer.from(out);
}

const OTS_MAGIC_LEN = 31;

/** Parse the `.ots` fixed header and return the file digest + timestamp offset. */
function parseOtsHeader(
  proofBytes: Buffer,
  expectedHexDigest: string,
):
  | { ok: true; fileDigest: Buffer; timestampOffset: number }
  | { ok: false; reason: string } {
  try {
    const r = new ByteReader(proofBytes);
    r.bytes(OTS_MAGIC_LEN); // magic (validated structurally by the reader elsewhere)
    r.varuint(); // version
    const alg = r.u8();
    if (alg !== OP_SHA256) {
      return { ok: false, reason: `OTS file-hash algorithm 0x${alg.toString(16)} is not sha256` };
    }
    const fileDigest = Buffer.from(r.bytes(32));
    if (fileDigest.toString('hex') !== expectedHexDigest.toLowerCase()) {
      return { ok: false, reason: 'proof commits a different digest than the supplied checkpoint root' };
    }
    return { ok: true, fileDigest, timestampOffset: r.position };
  } catch (err) {
    return { ok: false, reason: `malformed OTS header: ${(err as Error).message}` };
  }
}

/** Recursively collect pending commitments (message at each pending attestation). */
function collectPending(r: ByteReader, message: Buffer, out: PendingCommitment[]): void {
  let msg = message;
  for (;;) {
    const tag = r.peek();
    if (tag === TAG_ATTESTATION) {
      r.u8();
      const typeTag = r.bytes(8);
      const bodyLen = r.varuint();
      const body = r.bytes(bodyLen);
      if (typeTag.equals(ATTEST_PENDING)) {
        const br = new ByteReader(Buffer.from(body));
        const uriLen = br.varuint();
        const uri = br.bytes(uriLen).toString('utf8');
        out.push({ commitment: Buffer.from(msg), calendar: uri });
      }
      return;
    }
    if (tag === TAG_FORK) {
      r.u8();
      collectPending(r, Buffer.from(msg), out);
      continue;
    }
    const op = r.u8();
    if (op === OP_SHA256) {
      msg = sha256(msg);
    } else if (op === OP_APPEND) {
      const n = r.varuint();
      msg = Buffer.concat([msg, r.bytes(n)]);
    } else if (op === OP_PREPEND) {
      const n = r.varuint();
      msg = Buffer.concat([r.bytes(n), msg]);
    } else {
      throw new Error(`unsupported OTS op 0x${op.toString(16)} while recovering commitments`);
    }
  }
}

/**
 * Re-emit a LINEAR timestamp, replacing the pending attestation whose running
 * message equals `commitment` with `upgradedTimestamp` (the calendar's upgraded
 * bytes, which themselves apply operations to that same commitment message and
 * end in a Bitcoin attestation). Operations are re-emitted faithfully so the
 * resulting proof re-derives the same messages.
 *
 * Scope: a freshly-submitted single-calendar timestamp is LINEAR (a chain of
 * append/prepend/sha256 ending in one pending attestation) — that is the proof
 * `submitCheckpoint` stores and `upgradeProof` upgrades. A fork (which only
 * arises from merging multiple calendars' proofs) is reported as unsupported
 * here rather than mis-spliced; the caller then reports `still-pending`/error,
 * never a fabricated confirmation.
 */
function replacePendingWithUpgrade(
  r: ByteReader,
  message: Buffer,
  commitment: Buffer,
  upgradedTimestamp: Buffer,
): { ok: true; bytes: Buffer } | { ok: false; reason: string } {
  const parts: Buffer[] = [];
  let msg = message;
  for (;;) {
    const tag = r.peek();
    if (tag === TAG_ATTESTATION) {
      r.u8();
      const typeTag = r.bytes(8);
      const bodyLen = r.varuint();
      const body = r.bytes(bodyLen);
      if (typeTag.equals(ATTEST_PENDING) && msg.equals(commitment)) {
        parts.push(upgradedTimestamp); // splice the upgraded tail at this commitment
        return { ok: true, bytes: Buffer.concat(parts) };
      }
      // A different (or non-pending) attestation: re-emit verbatim and stop.
      parts.push(Buffer.from([TAG_ATTESTATION]), typeTag, encodeVarUint(bodyLen), body);
      return { ok: false, reason: 'reached an attestation that did not match the target commitment' };
    }
    if (tag === TAG_FORK) {
      return { ok: false, reason: 'forked OTS proof not supported by linear upgrade graft' };
    }
    const op = r.u8();
    if (op === OP_SHA256) {
      parts.push(Buffer.from([OP_SHA256]));
      msg = sha256(msg);
    } else if (op === OP_APPEND) {
      const n = r.varuint();
      const data = Buffer.from(r.bytes(n));
      parts.push(Buffer.from([OP_APPEND]), encodeVarUint(n), data);
      msg = Buffer.concat([msg, data]);
    } else if (op === OP_PREPEND) {
      const n = r.varuint();
      const data = Buffer.from(r.bytes(n));
      parts.push(Buffer.from([OP_PREPEND]), encodeVarUint(n), data);
      msg = Buffer.concat([data, msg]);
    } else {
      return { ok: false, reason: `unsupported OTS op 0x${op.toString(16)} while grafting upgrade` };
    }
  }
}
