/**
 * Structural validator tests for `validateWitnessRecord` / `isWitnessRecord`.
 *
 * Covers: happy path (a full record parses), error paths (missing required
 * blocks, malformed digests, unknown keys rejected by `.strict()`), and edge
 * cases (optional blocks absent, the PII/hmac digest rule — AC4). Each exported
 * function has ≥3 tests across happy/error/edge per the Quality Foundation.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  validateWitnessRecord,
  isWitnessRecord,
  WitnessRecordSchema,
  type WitnessRecord,
  type ArtifactDigest,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));

/** Deep clone of the canonical `pay` vector, mutable per test. */
function payRecord(): WitnessRecord {
  const raw = readFileSync(join(here, 'vectors', 'valid-pay.json'), 'utf8');
  return JSON.parse(raw) as WitnessRecord;
}

/** Deep clone of the canonical `doc` vector (has artifacts). */
function docRecord(): WitnessRecord {
  const raw = readFileSync(join(here, 'vectors', 'valid-doc.json'), 'utf8');
  return JSON.parse(raw) as WitnessRecord;
}

describe('[UNIT] validateWitnessRecord — should accept a well-formed record', () => {
  it('returns ok:true with the typed record for a valid pay record (happy)', () => {
    const result = validateWitnessRecord(payRecord());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.record.profile).toBe('pay');
      expect(result.record.intent.action).toBe('payment.refund');
    }
  });

  it('accepts a record with only the required blocks (edge — optionals absent)', () => {
    const minimal = payRecord();
    delete (minimal as Partial<WitnessRecord>).authorization;
    delete (minimal as Partial<WitnessRecord>).verifications;
    // Structurally valid even though it would fail the `pay` PROFILE — the
    // structural validator does not enforce profile minimums.
    const result = validateWitnessRecord(minimal);
    expect(result.ok).toBe(true);
  });

  it('accepts a record carrying an optional erasure_events block (edge)', () => {
    const rec = docRecord() as WitnessRecord & { erasure_events: unknown };
    rec.erasure_events = [
      {
        artifact_ref: 'artifact:0',
        key_ref: 'key:cust-1',
        destroyed_at: '2026-06-12T09:00:00Z',
        requested_by_ref: 'dpo:opaque-1',
      },
    ];
    expect(validateWitnessRecord(rec).ok).toBe(true);
  });
});

describe('[UNIT] validateWitnessRecord — should reject malformed records', () => {
  it('rejects a non-object input (error)', () => {
    const result = validateWitnessRecord('not-a-record');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.length).toBeGreaterThan(0);
  });

  it('rejects a record missing the required chain block (error)', () => {
    const rec = payRecord();
    delete (rec as Partial<WitnessRecord>).chain;
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('chain'))).toBe(true);
    }
  });

  it('rejects a record missing the required intent block (error)', () => {
    const rec = payRecord();
    delete (rec as Partial<WitnessRecord>).intent;
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });

  it('rejects an unknown top-level key via strict mode (error)', () => {
    const rec = payRecord() as Record<string, unknown>;
    rec.extra_field = 'smuggled';
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
  });

  it('rejects a non-hex params_hash (error — digest discipline)', () => {
    const rec = payRecord();
    rec.intent.params_hash = 'NOT_HEX';
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('params_hash'))).toBe(true);
    }
  });

  it('rejects an artifact digest value that is not 64 hex chars (error)', () => {
    const rec = docRecord();
    rec.artifacts![0]!.digest.value = 'abc123';
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('digest.value'))).toBe(true);
    }
  });

  it('rejects an unknown profile value (error)', () => {
    const rec = payRecord() as Record<string, unknown>;
    rec.profile = 'super-pay';
    expect(validateWitnessRecord(rec).ok).toBe(false);
  });
});

describe('[UNIT] validateWitnessRecord — PII/hmac digest rule (AC4)', () => {
  it('rejects a PII-bearing artifact that uses plain sha256 (error)', () => {
    const rec = docRecord();
    rec.artifacts![0]!.pii_bearing = true;
    // digest.alg is still sha256 from the vector → must fail.
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('hmac-sha256'))).toBe(true);
    }
  });

  it('accepts a PII-bearing artifact with hmac-sha256 + key_ref (happy)', () => {
    const rec = docRecord();
    rec.artifacts![0]!.pii_bearing = true;
    rec.artifacts![0]!.digest = {
      alg: 'hmac-sha256',
      value: '3333333333333333333333333333333333333333333333333333333333333333',
      key_ref: 'key:cust-pii-1',
    };
    expect(validateWitnessRecord(rec).ok).toBe(true);
  });

  it('rejects an hmac-sha256 digest that omits key_ref (edge)', () => {
    const rec = docRecord();
    rec.artifacts![0]!.digest = {
      alg: 'hmac-sha256',
      value: '3333333333333333333333333333333333333333333333333333333333333333',
    } as ArtifactDigest;
    const result = validateWitnessRecord(rec);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((e) => e.includes('key_ref'))).toBe(true);
    }
  });
});

describe('[UNIT] isWitnessRecord — should narrow valid records only', () => {
  it('returns true for a valid record (happy)', () => {
    expect(isWitnessRecord(payRecord())).toBe(true);
  });

  it('returns false for a malformed record (error)', () => {
    expect(isWitnessRecord({ profile: 'pay' })).toBe(false);
  });

  it('returns false for null (edge)', () => {
    expect(isWitnessRecord(null)).toBe(false);
  });
});

describe('[UNIT] WitnessRecordSchema — exported for direct composition', () => {
  it('is a usable zod schema that safeParses valid input (happy)', () => {
    expect(WitnessRecordSchema.safeParse(payRecord()).success).toBe(true);
  });

  it('safeParse fails on invalid input without throwing (error)', () => {
    expect(WitnessRecordSchema.safeParse(42).success).toBe(false);
  });

  it('applies the pii_bearing default of false when omitted (edge)', () => {
    const parsed = WitnessRecordSchema.safeParse(docRecord());
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.artifacts![0]!.pii_bearing).toBe(false);
    }
  });
});
