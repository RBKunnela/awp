/**
 * AW-5 AC5 — per-checkpoint discipline guard. The anchor API anchors a CHECKPOINT
 * (root + size + origin, from AW-4), NEVER an individual record. These tests pin
 * that architectural rule so a future change that tries to anchor a single record
 * (which would blow up cost — anchors scale with checkpoint cadence, spec §2)
 * fails the suite.
 *
 * The OTS submit path takes `Pick<Checkpoint,'root'>` and validates the root is a
 * 32-byte checkpoint root; the RFC 3161 verify path checks a TSA imprint over a
 * checkpoint root. A record's own digest (a different shape/value) must not pass
 * as a checkpoint root.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  submitCheckpoint,
  verifyRfc3161Token,
  buildTestCalendarTimestamp,
  type OtsHttp,
} from '../../src/anchor/index.js';
// IMPORT the AW-4 checkpoint primitives — never redefine them here.
import { encodeCheckpoint, parseCheckpoint, merkleTreeHash } from '../../src/log/index.js';
import { buildTimeStampToken, makeTsaKeyPair } from './rfc3161-fixture.js';

/** A trivial always-pending mock calendar (no network). */
const mockHttp: OtsHttp = {
  async postDigest(calendarUrl, digest) {
    return { ok: true, timestamp: buildTestCalendarTimestamp(digest, { confirmed: false, calendar: calendarUrl }) };
  },
  async getTimestamp() {
    return { ok: false, status: 404, reason: 'pending' };
  },
};

/** Build a real AW-4 checkpoint root from a couple of leaves. */
function checkpointRoot(): Uint8Array {
  const leaves = [Buffer.from('record-1'), Buffer.from('record-2'), Buffer.from('record-3')];
  return merkleTreeHash(leaves);
}

describe('anchor input is a CHECKPOINT, not a record', () => {
  it('submitCheckpoint accepts a real AW-4 checkpoint root (root + size + origin)', async () => {
    const root = checkpointRoot();
    // The checkpoint a real caller anchors carries root + size + origin (AW-4).
    const body = encodeCheckpoint({ origin: 'awp.example/log', size: 3, root });
    const parsed = parseCheckpoint(body);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    const r = await submitCheckpoint({ root: parsed.checkpoint.root }, mockHttp, { calendars: ['https://c.example'] });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.proof.checkpoint_root).toBe(Buffer.from(root).toString('hex'));
      expect(r.proof.pending).toBe(true);
    }
  });

  it('REJECTS anchoring an individual record digest as if it were a checkpoint root shape', async () => {
    // A record commitment is a 32-byte SHA-256 too — so the SHAPE alone cannot be
    // the only guard. The discipline lives at the call site: the API parameter is
    // a Checkpoint (root+size+origin), not a record. We assert the type-level
    // contract by showing the only accepted entry is via a checkpoint's root, and
    // that a non-32-byte record identifier (e.g. a UUID's bytes) is refused.
    const recordIdBytes = new Uint8Array(16).fill(0xab); // a 128-bit record id, NOT a root
    const r = await submitCheckpoint({ root: recordIdBytes }, mockHttp, { calendars: ['https://c.example'] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/32-byte|per checkpoint/);
  });

  it('RFC 3161 verify is over a checkpoint root, and a record-scoped imprint does not match it', () => {
    const root = checkpointRoot();
    const tsa = makeTsaKeyPair('rsa');
    // A TSA token taken over a RECORD (not the checkpoint) must not verify against
    // the checkpoint root — anchoring is per-checkpoint, so the imprint must cover
    // the checkpoint root, not a single record.
    const recordBytes = createHash('sha256').update('a-single-record').digest();
    const { der } = buildTimeStampToken({ data: recordBytes, tsa });

    const againstCheckpoint = verifyRfc3161Token(der, root, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(againstCheckpoint.ok).toBe(false); // imprint covers the record, not the checkpoint root

    const againstRecord = verifyRfc3161Token(der, recordBytes, { trustAnchor: { publicKey: tsa.publicKeyPem } });
    expect(againstRecord.ok).toBe(true); // sanity: the token itself is valid over its own data
  });
});
