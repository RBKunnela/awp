/**
 * Tests for the OpenTimestamps PRODUCER path (AW-5 part a): submit a checkpoint
 * root to calendar(s) → pending proof, then upgrade pending → Bitcoin-confirmed.
 * The calendar/network is FULLY MOCKED (an injected {@link OtsHttp}); NO test
 * makes a real network call. Covers: submit happy path (pending), one-of-N and
 * all-of-N policy, submit failure, the pending→confirmed upgrade, honest
 * still-pending when the calendar has no block yet, and a verify of the resulting
 * confirmed proof through the offline reader. ≥3 tests per exported function.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  submitCheckpoint,
  upgradeProof,
  DEFAULT_OTS_CALENDARS,
  readOtsProof,
  verifyOtsAnchor,
  buildTestCalendarTimestamp,
  testCalendarCommitment,
  type OtsHttp,
} from '../../src/anchor/index.js';

function rootBytes(s: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(s).digest());
}
const CP_ROOT = rootBytes('checkpoint-root-AW5');
const CP_ROOT_HEX = Buffer.from(CP_ROOT).toString('hex');

/** A fixed suffix so submit and its upgrade share the same operation chain. */
const SUBMIT_SUFFIX = new Uint8Array([0xca, 0x1e, 0x11, 0xda]);

/**
 * Build a mock calendar transport.
 *  - `postDigest` returns a PENDING timestamp (append(SUBMIT_SUFFIX)→sha256→pending).
 *  - `getTimestamp`, keyed by the commitment, returns a CONFIRMED upgrade timestamp
 *    when `confirmAt` lists that calendar, else a 404 (still pending).
 */
function mockCalendar(opts?: {
  failCalendars?: string[];
  confirmCalendars?: string[];
  height?: number;
}): OtsHttp {
  const fail = new Set(opts?.failCalendars ?? []);
  const confirm = new Set(opts?.confirmCalendars ?? DEFAULT_OTS_CALENDARS);
  const height = opts?.height ?? 842000;
  return {
    async postDigest(calendarUrl, digest) {
      if (fail.has(calendarUrl)) {
        return { ok: false, status: 500, reason: 'mock calendar down' };
      }
      const timestamp = buildTestCalendarTimestamp(digest, {
        confirmed: false,
        calendar: calendarUrl,
        suffix: SUBMIT_SUFFIX,
      });
      return { ok: true, timestamp };
    },
    async getTimestamp(calendarUrl, hexCommitment) {
      if (!confirm.has(calendarUrl)) {
        return { ok: false, status: 404, reason: 'not yet confirmed' };
      }
      // The upgrade timestamp starts AT the commitment message and ends in a
      // Bitcoin attestation. Verify the caller asked about the right commitment.
      const expected = Buffer.from(testCalendarCommitment(CP_ROOT, SUBMIT_SUFFIX)).toString('hex');
      if (hexCommitment !== expected) {
        return { ok: false, status: 404, reason: 'unknown commitment' };
      }
      const timestamp = buildTestCalendarTimestamp(testCalendarCommitment(CP_ROOT, SUBMIT_SUFFIX), {
        confirmed: true,
        height,
        suffix: new Uint8Array([0x01, 0x02]),
      });
      return { ok: true, timestamp };
    },
  };
}

describe('submitCheckpoint — happy path (pending)', () => {
  it('submits a checkpoint root and returns a PENDING proof committing that root', async () => {
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar());
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.proof.type).toBe('ots');
      expect(r.proof.checkpoint_root).toBe(CP_ROOT_HEX);
      expect(r.proof.pending).toBe(true);
      // The stored proof verifies offline as pending against the same root.
      const read = verifyOtsAnchor(r.proof);
      expect(read.ok).toBe(true);
      if (read.ok) expect(read.confirmed).toBe(false);
    }
  });

  it('accepts first success under one-of-N even if a later calendar fails', async () => {
    const cals = ['https://a.example', 'https://b.example'];
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar({ failCalendars: ['https://b.example'] }), {
      calendars: cals,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.submissions.filter((s) => s.ok).length).toBe(1);
      expect(r.submissions.find((s) => s.calendar === 'https://b.example')?.ok).toBe(false);
    }
  });

  it('records a per-calendar submission for each calendar tried', async () => {
    const cals = ['https://a.example', 'https://b.example', 'https://c.example'];
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar(), { calendars: cals });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.submissions.length).toBe(3);
  });
});

describe('submitCheckpoint — failure & policy paths (fail-closed)', () => {
  it('FAILS when every calendar rejects the submission', async () => {
    const cals = ['https://a.example', 'https://b.example'];
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar({ failCalendars: cals }), { calendars: cals });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/all .* failed/);
  });

  it('FAILS under requireAll when only some calendars succeed', async () => {
    const cals = ['https://a.example', 'https://b.example'];
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar({ failCalendars: ['https://b.example'] }), {
      calendars: cals,
      requireAll: true,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/requireAll/);
  });

  it('FAILS (per-checkpoint guard) when handed something that is not a 32-byte root', async () => {
    // A 20-byte value (e.g. a record id digest) is rejected — anchor per checkpoint.
    const notARoot = new Uint8Array(20).fill(7);
    const r = await submitCheckpoint({ root: notARoot }, mockCalendar());
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/32-byte|per checkpoint/);
  });
});

describe('upgradeProof — pending → confirmed (mocked, never fabricated)', () => {
  it('upgrades a pending proof to a Bitcoin-confirmed one when a calendar serves the block', async () => {
    const http = mockCalendar({ confirmCalendars: ['https://alice.btc.calendar.opentimestamps.org'] });
    // Submit against the public default calendar so the pending proof's URI matches.
    const sub = await submitCheckpoint({ root: CP_ROOT }, http, {
      calendars: ['https://alice.btc.calendar.opentimestamps.org'],
    });
    expect(sub.ok).toBe(true);
    if (!sub.ok) return;

    const up = await upgradeProof(sub.proof, http);
    expect(up.status).toBe('confirmed');
    if (up.status === 'confirmed') {
      expect(up.proof.pending).toBe(false);
      expect(up.read.ok).toBe(true);
      if (up.read.ok) {
        expect(up.read.confirmed).toBe(true);
        expect(up.read.block_heights).toContain(842000);
      }
      // The confirmed proof re-verifies offline against the same root.
      const reread = verifyOtsAnchor(up.proof);
      expect(reread.ok).toBe(true);
      if (reread.ok) expect(reread.confirmed).toBe(true);
    }
  });

  it('reports STILL-PENDING honestly when no calendar can serve a block yet (no fabrication)', async () => {
    const cal = 'https://alice.btc.calendar.opentimestamps.org';
    // confirm set empty ⇒ getTimestamp always 404.
    const http = mockCalendar({ confirmCalendars: [] });
    const sub = await submitCheckpoint({ root: CP_ROOT }, http, { calendars: [cal] });
    expect(sub.ok).toBe(true);
    if (!sub.ok) return;
    const up = await upgradeProof(sub.proof, http);
    expect(up.status).toBe('still-pending');
    if (up.status === 'still-pending') {
      // The proof is returned UNCHANGED and still pending.
      expect(up.proof.pending).toBe(true);
      expect(up.proof.ots_proof_b64).toBe(sub.proof.ots_proof_b64);
    }
  });

  it('reports a confirmed proof as already-confirmed and does not re-upgrade', async () => {
    const cal = 'https://alice.btc.calendar.opentimestamps.org';
    const http = mockCalendar({ confirmCalendars: [cal] });
    const sub = await submitCheckpoint({ root: CP_ROOT }, http, { calendars: [cal] });
    if (!sub.ok) throw new Error('submit failed');
    const up1 = await upgradeProof(sub.proof, http);
    if (up1.status !== 'confirmed') throw new Error('expected confirmed');
    const up2 = await upgradeProof(up1.proof, http);
    expect(up2.status).toBe('confirmed');
    if (up2.status === 'confirmed') expect(up2.reason).toMatch(/already/);
  });

  it('returns an error (not a confirmation) when the pending proof bytes are malformed', async () => {
    const http = mockCalendar();
    const bogus = { type: 'ots' as const, checkpoint_root: CP_ROOT_HEX, ots_proof_b64: 'not-base64-$$$', pending: true };
    const up = await upgradeProof(bogus, http);
    expect(up.status === 'error' || up.status === 'still-pending').toBe(true);
    expect(up.status).not.toBe('confirmed');
  });
});

describe('submitted + upgraded proofs verify through the SAME offline reader', () => {
  it('the assembled pending proof parses as a real .ots structure', async () => {
    const sub = await submitCheckpoint({ root: CP_ROOT }, mockCalendar(), {
      calendars: ['https://alice.btc.calendar.opentimestamps.org'],
    });
    if (!sub.ok) throw new Error('submit failed');
    const bytes = Buffer.from(sub.proof.ots_proof_b64, 'base64');
    const read = readOtsProof(bytes, CP_ROOT_HEX);
    expect(read.ok).toBe(true);
    if (read.ok) expect(read.calendars.length).toBeGreaterThan(0);
  });
});

describe('submitCheckpoint — defaults & defensive paths', () => {
  it('uses the DEFAULT public calendars when none are supplied', async () => {
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar());
    expect(r.ok).toBe(true);
    if (r.ok) {
      // Every default calendar was attempted.
      expect(r.submissions.map((s) => s.calendar)).toEqual([...DEFAULT_OTS_CALENDARS]);
    }
  });

  it('FAILS with an empty calendar list', async () => {
    const r = await submitCheckpoint({ root: CP_ROOT }, mockCalendar(), { calendars: [] });
    expect(r.ok).toBe(false);
  });

  it('skips a calendar that returns an UNPARSEABLE timestamp (never stores opaque bytes)', async () => {
    const badHttp: OtsHttp = {
      async postDigest() {
        return { ok: true, timestamp: new Uint8Array([0xff, 0xff, 0xff]) }; // not a valid timestamp
      },
      async getTimestamp() {
        return { ok: false, status: 404, reason: 'n/a' };
      },
    };
    const r = await submitCheckpoint({ root: CP_ROOT }, badHttp, { calendars: ['https://x.example'] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.submissions[0]?.reason).toMatch(/unparseable/);
  });

  it('treats a transport throw as a failed calendar (caught, not propagated)', async () => {
    const throwingHttp: OtsHttp = {
      async postDigest() {
        throw new Error('socket hang up');
      },
      async getTimestamp() {
        return { ok: false, reason: 'n/a' };
      },
    };
    const r = await submitCheckpoint({ root: CP_ROOT }, throwingHttp, { calendars: ['https://x.example'] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.submissions[0]?.reason).toMatch(/transport error/);
  });
});

describe('upgradeProof — defensive paths', () => {
  it('returns error when the pending proof commits a different root than it claims', async () => {
    // Build a valid pending proof for CP_ROOT, then claim a different checkpoint_root.
    const sub = await submitCheckpoint({ root: CP_ROOT }, mockCalendar(), { calendars: ['https://a.example'] });
    if (!sub.ok) throw new Error('submit failed');
    const tampered = { ...sub.proof, checkpoint_root: rootHexOf('different') };
    const up = await upgradeProof(tampered, mockCalendar());
    expect(up.status).toBe('error');
  });

  it('reports still-pending when the calendar serves only a 404 (transport returns not-ok)', async () => {
    const sub = await submitCheckpoint({ root: CP_ROOT }, mockCalendar({ confirmCalendars: [] }), {
      calendars: ['https://alice.btc.calendar.opentimestamps.org'],
    });
    if (!sub.ok) throw new Error('submit failed');
    const up = await upgradeProof(sub.proof, mockCalendar({ confirmCalendars: [] }), {
      calendars: ['https://alice.btc.calendar.opentimestamps.org'],
    });
    expect(up.status).toBe('still-pending');
  });

  it('ignores a calendar whose upgrade timestamp does not actually reach a Bitcoin attestation', async () => {
    // getTimestamp returns ok with a STILL-PENDING timestamp (no Bitcoin tag).
    const cal = 'https://alice.btc.calendar.opentimestamps.org';
    const half: OtsHttp = {
      async postDigest(calendarUrl, digest) {
        return {
          ok: true,
          timestamp: buildTestCalendarTimestamp(digest, { confirmed: false, calendar: calendarUrl, suffix: SUBMIT_SUFFIX }),
        };
      },
      async getTimestamp() {
        // A timestamp that parses but is still pending — must NOT be reported confirmed.
        return {
          ok: true,
          timestamp: buildTestCalendarTimestamp(testCalendarCommitment(CP_ROOT, SUBMIT_SUFFIX), {
            confirmed: false,
            suffix: new Uint8Array([0x09]),
          }),
        };
      },
    };
    const sub = await submitCheckpoint({ root: CP_ROOT }, half, { calendars: [cal] });
    if (!sub.ok) throw new Error('submit failed');
    const up = await upgradeProof(sub.proof, half, { calendars: [cal] });
    expect(up.status).toBe('still-pending');
  });
});

function rootHexOf(s: string): string {
  return Buffer.from(rootBytes(s)).toString('hex');
}
