/**
 * @module anchor/opentimestamps
 *
 * OpenTimestamps (OTS) anchor READ + VERIFY path — offline, zero network,
 * dependency-light (Node `crypto` only). Given an `.ots` proof and the digest
 * it should commit (a checkpoint root), this confirms that the proof's
 * commitment operations, applied to that digest, lead to a timestamp
 * attestation — and reports honestly whether that attestation is a confirmed
 * Bitcoin block header or a still-pending calendar commitment.
 *
 * Why a direct reader (AW-5 context / threat model "dependency rot"): the
 * `opentimestamps` npm package's maintenance is UNVERIFIED, and the AW-3 verify
 * path is required to make ZERO network calls. So the verify path does NOT call
 * a calendar; it walks the committed proof bytes itself. Upgrading a pending
 * proof to a confirmed one (which DOES need a calendar/Bitcoin node) is out of
 * scope here — that is a producer/online action, not the offline verify path.
 *
 * The `.ots` serialization (the subset this reader needs), from the
 * OpenTimestamps format spec:
 *  - Magic header: the 31-byte string
 *    "\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94".
 *  - 1 version byte (major version, currently 1).
 *  - A "file hash" op byte naming the digest algorithm (0x08 = sha256) followed
 *    by the digest bytes (32 for sha256) — the input the timestamp commits.
 *  - A "timestamp": a sequence of commitment OPERATIONS, optional FORKS
 *    (0xff = "push current message, continue both paths"), and ATTESTATIONS
 *    (0x00 tag + an 8-byte attestation type id + a varint-length-prefixed body).
 *
 * Operations (unary, transform the running 32+-byte "message"):
 *  - 0xf0 append      <varint len> <bytes>   → msg = msg ++ bytes
 *  - 0xf1 prepend     <varint len> <bytes>   → msg = bytes ++ msg
 *  - 0x08 sha256                              → msg = SHA256(msg)
 *  - 0x67 ripemd160 / 0x02 sha1 / 0x03 keccak256 are recognized as "unsupported
 *    here" and cause that path to be reported unverifiable (never silently
 *    passed) — sha256-only proofs (the AWP checkpoint-root case) verify fully.
 *
 * Attestations:
 *  - Bitcoin block header (`\x05\x88\x96\x0d\x73\xd7\x19\x01`): body is a varint
 *    block height. Presence ⇒ CONFIRMED (committed to Bitcoin).
 *  - Pending / calendar (`\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e`): body is a
 *    varint-prefixed calendar URI. Presence ⇒ PENDING (awaiting block).
 *
 * This reader confirms the proof STRUCTURE commits the supplied digest and
 * reports which attestation type was reached. It does NOT (and offline cannot)
 * re-derive the Bitcoin block's merkle root from the chain — that requires a
 * Bitcoin node. The honest claim is therefore "this proof commits root R and
 * carries a {confirmed Bitcoin | pending calendar} attestation," which is
 * exactly the evidentiary weight the auditor guide ascribes to OTS
 * (trust-minimized, not qualified).
 *
 * Dependencies: Node `crypto` (sha256), `./types`.
 * Used by: `../verify/checks` (the anchor check), `./index`.
 */

import { createHash } from 'node:crypto';
import type { OtsAnchorProof } from './types.js';

/** The 31-byte OpenTimestamps proof magic header. */
const OTS_MAGIC = Buffer.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d,
  0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2,
  0xe8, 0x84, 0xe8, 0x92, 0x94,
]);

/** Op byte: SHA-256 (used both as the file-hash algorithm tag and as an op). */
const OP_SHA256 = 0x08;
/** Op byte: append bytes to the running message. */
const OP_APPEND = 0xf0;
/** Op byte: prepend bytes to the running message. */
const OP_PREPEND = 0xf1;
/** Marker byte: a fork in the proof tree (push, follow both branches). */
const TAG_FORK = 0xff;
/** Marker byte: an attestation follows. */
const TAG_ATTESTATION = 0x00;
/** Recognized-but-unsupported hash ops (cause an honest "unverifiable" path). */
const OP_RIPEMD160 = 0x67;
const OP_SHA1 = 0x02;
const OP_KECCAK256 = 0x03;

/** 8-byte attestation type tag: Bitcoin block header (⇒ confirmed). */
const ATTEST_BITCOIN = Buffer.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
/** 8-byte attestation type tag: pending / calendar (⇒ awaiting block). */
const ATTEST_PENDING = Buffer.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);

/**
 * The outcome of reading an `.ots` proof against an expected digest.
 *
 *  - `ok: true` + `confirmed: true`  → reached a Bitcoin block-header
 *    attestation (height exposed). Strongest OTS state.
 *  - `ok: true` + `confirmed: false` → reached only a pending/calendar
 *    attestation (calendar URIs exposed). Honestly reported as pending.
 *  - `ok: false` → the proof does not commit the expected digest, is malformed,
 *    or uses a hash op this offline reader can't follow (`reason` names which).
 */
export type OtsReadResult =
  | {
      ok: true;
      confirmed: boolean;
      /** Bitcoin block heights reached (when confirmed). */
      block_heights: number[];
      /** Calendar URIs reached (when pending). */
      calendars: string[];
      /** Human one-line summary of the attestation state. */
      reason: string;
    }
  | { ok: false; reason: string };

/** A minimal forward byte cursor over a Buffer. */
class Cursor {
  constructor(
    private readonly buf: Buffer,
    private pos = 0,
  ) {}

  /** Bytes remaining. */
  get remaining(): number {
    return this.buf.length - this.pos;
  }

  /** Read one byte, advancing. Throws on EOF. */
  readU8(): number {
    if (this.pos >= this.buf.length) throw new Error('unexpected end of OTS proof');
    const b = this.buf[this.pos];
    this.pos += 1;
    return b as number;
  }

  /** Peek the next byte without advancing. Throws on EOF. */
  peekU8(): number {
    if (this.pos >= this.buf.length) throw new Error('unexpected end of OTS proof');
    return this.buf[this.pos] as number;
  }

  /** Read `n` raw bytes, advancing. Throws on EOF. */
  readBytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('unexpected end of OTS proof');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  /**
   * Read an OTS varint (LEB128-style, 7 bits per byte, MSB = continuation).
   * Used for lengths, attestation bodies, and Bitcoin block heights.
   */
  readVarUint(): number {
    let result = 0;
    let shift = 0;
    for (;;) {
      const b = this.readU8();
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 56) throw new Error('OTS varint too large');
    }
    return result;
  }
}

/** SHA-256 a buffer, returning the 32-byte digest. */
function sha256(data: Buffer): Buffer {
  return createHash('sha256').update(data).digest();
}

/** Accumulator the recursive walk fills in as it reaches attestations. */
interface Attestations {
  block_heights: number[];
  calendars: string[];
}

/**
 * Walk one timestamp branch: apply unary operations to `message`, recurse into
 * forks, and record any attestations reached. Throws (caught by the caller) on
 * malformed input or an unsupported hash op so the path is reported honestly
 * rather than silently treated as passing.
 *
 * @param cur - The byte cursor positioned at the start of a timestamp branch.
 * @param message - The running commitment message for THIS branch.
 * @param acc - Attestation accumulator (shared across branches).
 */
function walkTimestamp(cur: Cursor, message: Buffer, acc: Attestations): void {
  let msg = message;
  for (;;) {
    const tag = cur.peekU8();

    if (tag === TAG_ATTESTATION) {
      cur.readU8(); // consume 0x00
      const typeTag = cur.readBytes(8);
      const bodyLen = cur.readVarUint();
      const body = cur.readBytes(bodyLen);
      if (typeTag.equals(ATTEST_BITCOIN)) {
        const height = new Cursor(body).readVarUint();
        acc.block_heights.push(height);
      } else if (typeTag.equals(ATTEST_PENDING)) {
        const bcur = new Cursor(body);
        const uriLen = bcur.readVarUint();
        acc.calendars.push(bcur.readBytes(uriLen).toString('utf8'));
      }
      // Unknown attestation types are ignored (forward-compatible), not failed.
      return;
    }

    if (tag === TAG_FORK) {
      cur.readU8(); // consume 0xff
      // Follow one branch with a COPY of the current message, then continue the
      // other branch in this loop with the same message.
      walkTimestamp(cur, Buffer.from(msg), acc);
      continue;
    }

    // Otherwise it is an operation.
    const op = cur.readU8();
    switch (op) {
      case OP_SHA256:
        msg = sha256(msg);
        break;
      case OP_APPEND: {
        const n = cur.readVarUint();
        msg = Buffer.concat([msg, cur.readBytes(n)]);
        break;
      }
      case OP_PREPEND: {
        const n = cur.readVarUint();
        msg = Buffer.concat([cur.readBytes(n), msg]);
        break;
      }
      case OP_RIPEMD160:
      case OP_SHA1:
      case OP_KECCAK256:
        throw new Error(
          `OTS proof uses hash op 0x${op.toString(16)} this offline reader does not implement`,
        );
      default:
        throw new Error(`unknown OTS operation byte 0x${op.toString(16)}`);
    }
  }
}

/**
 * Read and verify an `.ots` proof against an expected SHA-256 digest (the
 * checkpoint root). Offline and deterministic: confirms the proof's file-hash
 * input equals `expectedHexDigest` and that its commitment operations reach an
 * attestation, reporting whether that attestation is a confirmed Bitcoin block
 * or a pending calendar commitment.
 *
 * @param otsBytes - The raw `.ots` proof bytes.
 * @param expectedHexDigest - Lowercase 64-char hex SHA-256 the proof must commit.
 * @returns An {@link OtsReadResult}; never throws (errors become `ok: false`).
 *
 * @example
 * const r = readOtsProof(bytes, checkpointRoot);
 * if (r.ok && r.confirmed) console.log('Bitcoin block', r.block_heights[0]);
 */
export function readOtsProof(otsBytes: Buffer, expectedHexDigest: string): OtsReadResult {
  try {
    const cur = new Cursor(otsBytes);
    const magic = cur.readBytes(OTS_MAGIC.length);
    if (!magic.equals(OTS_MAGIC)) {
      return { ok: false, reason: 'not an OpenTimestamps proof (bad magic header)' };
    }
    cur.readVarUint(); // version

    const algTag = cur.readU8();
    if (algTag !== OP_SHA256) {
      return {
        ok: false,
        reason: `OTS file-hash algorithm 0x${algTag.toString(16)} is not sha256 (AWP commits sha256 roots)`,
      };
    }
    const fileDigest = cur.readBytes(32);
    if (fileDigest.toString('hex') !== expectedHexDigest.toLowerCase()) {
      return {
        ok: false,
        reason: 'OTS proof commits a different digest than the supplied checkpoint root',
      };
    }

    const acc: Attestations = { block_heights: [], calendars: [] };
    walkTimestamp(cur, Buffer.from(fileDigest), acc);

    if (acc.block_heights.length === 0 && acc.calendars.length === 0) {
      return { ok: false, reason: 'OTS proof reached no attestation (no Bitcoin or calendar tag)' };
    }
    const confirmed = acc.block_heights.length > 0;
    const reason = confirmed
      ? `confirmed: Bitcoin block ${acc.block_heights.join(', ')} (trust-minimized time)`
      : `pending: calendar attestation (${acc.calendars.join(', ')}), awaiting Bitcoin confirmation`;
    return {
      ok: true,
      confirmed,
      block_heights: acc.block_heights,
      calendars: acc.calendars,
      reason,
    };
  } catch (err) {
    return { ok: false, reason: `malformed OTS proof: ${(err as Error).message}` };
  }
}

/**
 * Verify an {@link OtsAnchorProof} read straight from a receipt: decode its
 * base64 `.ots` bytes and check them against its declared `checkpoint_root`.
 *
 * @param proof - The OTS anchor proof from a receipt.
 * @returns An {@link OtsReadResult}; never throws.
 */
export function verifyOtsAnchor(proof: OtsAnchorProof): OtsReadResult {
  let bytes: Buffer;
  try {
    bytes = Buffer.from(proof.ots_proof_b64, 'base64');
  } catch (err) {
    return { ok: false, reason: `ots_proof_b64 is not valid base64: ${(err as Error).message}` };
  }
  return readOtsProof(bytes, proof.checkpoint_root);
}

/**
 * Build the raw bytes of a minimal, well-formed `.ots` proof for a digest:
 * `append(suffix) → sha256 → {pending calendar | Bitcoin block}` attestation.
 * For FIXTURES and TESTS only — a real proof comes from a calendar server. The
 * structure is faithful to the format so the reader exercises real parsing.
 *
 * @param digest - The 32-byte SHA-256 the proof commits (the checkpoint root).
 * @param opts - `confirmed` ⇒ a Bitcoin block-header attestation at `height`;
 *               otherwise a pending calendar attestation at `calendar`.
 * @returns The `.ots` proof bytes.
 */
export function buildTestOtsProof(
  digest: Buffer,
  opts: { confirmed: boolean; height?: number; calendar?: string } = { confirmed: false },
): Buffer {
  const parts: Buffer[] = [OTS_MAGIC, Buffer.from([0x01])]; // magic + version 1
  parts.push(Buffer.from([OP_SHA256])); // file-hash alg = sha256
  parts.push(Buffer.from(digest)); // the committed digest

  // One operation so the walk is non-trivial: append a 4-byte suffix, sha256.
  const suffix = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  parts.push(Buffer.from([OP_APPEND, suffix.length]), suffix);
  parts.push(Buffer.from([OP_SHA256]));

  // Attestation.
  parts.push(Buffer.from([TAG_ATTESTATION]));
  if (opts.confirmed) {
    parts.push(ATTEST_BITCOIN);
    const height = encodeVarUint(opts.height ?? 800000);
    parts.push(Buffer.from([height.length]), height);
  } else {
    parts.push(ATTEST_PENDING);
    const uri = Buffer.from(opts.calendar ?? 'https://alice.btc.calendar.opentimestamps.org', 'utf8');
    const uriLen = encodeVarUint(uri.length);
    const body = Buffer.concat([uriLen, uri]);
    parts.push(Buffer.from([body.length]), body);
  }
  return Buffer.concat(parts);
}

/** Encode a non-negative integer as an OTS varint (LEB128). For test builder. */
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

/**
 * Assemble a complete `.ots` proof file from a digest and a calendar's serialized
 * TIMESTAMP bytes (the operations + attestation portion an OTS calendar returns,
 * with no magic header or file-hash op of its own). The result is:
 * `magic || version(1) || file-hash-op(sha256) || <digest> || <timestamp>` — the
 * exact structure {@link readOtsProof} parses. Used by the producer-side submit /
 * upgrade path (`./ots-submit`) so submitted and upgraded proofs verify through
 * the SAME offline reader.
 *
 * @param digest - The 32-byte SHA-256 the proof commits (the checkpoint root).
 * @param timestamp - The calendar's serialized timestamp bytes for that digest.
 * @returns The assembled `.ots` proof bytes.
 * @throws {RangeError} If `digest` is not exactly 32 bytes.
 */
export function assembleOtsProof(digest: Uint8Array, timestamp: Uint8Array): Buffer {
  if (digest.length !== 32) {
    throw new RangeError(`OTS file digest must be 32 bytes (got ${digest.length})`);
  }
  return Buffer.concat([
    OTS_MAGIC,
    Buffer.from([0x01]), // version 1
    Buffer.from([OP_SHA256]), // file-hash algorithm = sha256
    Buffer.from(digest),
    Buffer.from(timestamp),
  ]);
}

/**
 * Parse a calendar's serialized TIMESTAMP bytes (no `.ots` header) against the
 * digest they apply to, confirming the operations reach an attestation, and
 * report whether that attestation is a confirmed Bitcoin block or a pending
 * calendar commitment. Used to validate a calendar's response BEFORE storing it
 * (`./ots-submit`), so opaque/unverifiable bytes are never persisted as a proof.
 *
 * @param timestamp - The calendar's serialized timestamp bytes.
 * @param digest - The 32-byte digest the timestamp's operations start from.
 * @returns An {@link OtsReadResult}; never throws.
 */
export function parseOtsTimestamp(timestamp: Uint8Array, digest: Uint8Array): OtsReadResult {
  try {
    const acc: Attestations = { block_heights: [], calendars: [] };
    walkTimestamp(new Cursor(Buffer.from(timestamp)), Buffer.from(digest), acc);
    if (acc.block_heights.length === 0 && acc.calendars.length === 0) {
      return { ok: false, reason: 'calendar timestamp reached no attestation' };
    }
    const confirmed = acc.block_heights.length > 0;
    return {
      ok: true,
      confirmed,
      block_heights: acc.block_heights,
      calendars: acc.calendars,
      reason: confirmed
        ? `confirmed: Bitcoin block ${acc.block_heights.join(', ')}`
        : `pending: calendar attestation (${acc.calendars.join(', ')})`,
    };
  } catch (err) {
    return { ok: false, reason: `malformed calendar timestamp: ${(err as Error).message}` };
  }
}

/**
 * Build a calendar-style serialized TIMESTAMP (no `.ots` header) for a digest —
 * the bytes an OTS calendar's `POST /digest` returns. For FIXTURES and TESTS
 * ONLY (mocked calendars); a real timestamp comes from a calendar server. The
 * structure is faithful to the format so the reader/assembler exercise real
 * parsing. The operations are applied to `digest`; pass `confirmed` to end in a
 * Bitcoin block-header attestation, else a pending calendar attestation.
 *
 * @param _digest - The digest the timestamp's operations start from. Unused in
 *   construction (the operations are digest-relative; the reader applies them to
 *   whatever digest the proof commits) — present to keep the call site explicit
 *   and symmetric with {@link testCalendarCommitment}.
 * @param opts - `confirmed` ⇒ Bitcoin attestation at `height`; else pending at
 *   `calendar`. `suffix` overrides the appended bytes (so submit and its later
 *   upgrade share the same operation chain → same commitment).
 * @returns The serialized timestamp bytes.
 */
export function buildTestCalendarTimestamp(
  _digest: Uint8Array,
  opts: { confirmed: boolean; height?: number; calendar?: string; suffix?: Uint8Array } = {
    confirmed: false,
  },
): Buffer {
  const parts: Buffer[] = [];
  const suffix = Buffer.from(opts.suffix ?? Buffer.from([0xca, 0x1e, 0x11, 0xda]));
  parts.push(Buffer.from([OP_APPEND, suffix.length]), suffix);
  parts.push(Buffer.from([OP_SHA256]));
  parts.push(Buffer.from([TAG_ATTESTATION]));
  if (opts.confirmed) {
    parts.push(ATTEST_BITCOIN);
    const height = encodeVarUint(opts.height ?? 800000);
    parts.push(Buffer.from([height.length]), height);
  } else {
    parts.push(ATTEST_PENDING);
    const uri = Buffer.from(opts.calendar ?? 'https://alice.btc.calendar.opentimestamps.org', 'utf8');
    const uriLen = encodeVarUint(uri.length);
    const body = Buffer.concat([uriLen, uri]);
    parts.push(Buffer.from([body.length]), body);
  }
  return Buffer.concat(parts);
}

/**
 * The 32-byte calendar commitment for a {@link buildTestCalendarTimestamp} chain
 * built with the given `suffix`: `SHA256(digest || suffix)`. The matching upgrade
 * timestamp (built from this commitment with `confirmed: true` and the SAME ops)
 * must begin at this message. Test helper mirroring the calendar's keying.
 *
 * @param digest - The submitted 32-byte digest.
 * @param suffix - The append suffix used when building the pending timestamp.
 * @returns The 32-byte commitment.
 */
export function testCalendarCommitment(digest: Uint8Array, suffix: Uint8Array): Buffer {
  return sha256(Buffer.concat([Buffer.from(digest), Buffer.from(suffix)]));
}
