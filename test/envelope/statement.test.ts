/**
 * Tests for the in-toto Statement v1 wrapper (AW-2 statement.ts).
 *
 * Covers buildStatement, buildValidatedStatement, checkStatementShape, and
 * statementAsJson across happy / error / edge, plus AC5 (subject binds
 * target_ref + params_hash). ≥3 tests per exported function.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  buildStatement,
  buildValidatedStatement,
  checkStatementShape,
  statementAsJson,
} from '../../src/envelope/statement.js';
import {
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  type WitnessRecord,
} from '../../src/schema/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemaVectors = join(here, '..', 'schema', 'vectors');

function payRecord(): WitnessRecord {
  return JSON.parse(readFileSync(join(schemaVectors, 'valid-pay.json'), 'utf8')) as WitnessRecord;
}

describe('[UNIT] buildStatement — AC5 subject binding', () => {
  it('binds subject[0].name to intent.target_ref and digest to params_hash (happy / AC5)', () => {
    const record = payRecord();
    const stmt = buildStatement(record);
    expect(stmt._type).toBe(STATEMENT_TYPE);
    expect(stmt.predicateType).toBe(PREDICATE_TYPE);
    expect(stmt.subject).toHaveLength(1);
    expect(stmt.subject[0].name).toBe(record.intent.target_ref);
    expect(stmt.subject[0].digest.sha256).toBe(record.intent.params_hash);
  });

  it('carries the record verbatim as the predicate (happy)', () => {
    const record = payRecord();
    const stmt = buildStatement(record);
    expect(stmt.predicate).toEqual(record);
  });

  it('reflects a different target_ref/params_hash in the subject (edge)', () => {
    const record = payRecord();
    record.intent.target_ref = 'order:changed';
    record.intent.params_hash = 'f'.repeat(64);
    const stmt = buildStatement(record);
    expect(stmt.subject[0].name).toBe('order:changed');
    expect(stmt.subject[0].digest.sha256).toBe('f'.repeat(64));
  });
});

describe('[UNIT] buildValidatedStatement', () => {
  it('validates then builds for a valid record (happy)', () => {
    const result = buildValidatedStatement(payRecord());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.statement.predicate.profile).toBe('pay');
    }
  });

  it('fails closed for an invalid record, returning errors not a partial statement (error)', () => {
    const bad = payRecord() as Partial<WitnessRecord>;
    delete bad.chain;
    const result = buildValidatedStatement(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.join(' ')).toMatch(/chain/);
    }
  });

  it('fails closed for a non-object input (edge)', () => {
    expect(buildValidatedStatement(null).ok).toBe(false);
    expect(buildValidatedStatement('nope').ok).toBe(false);
  });
});

describe('[UNIT] checkStatementShape', () => {
  function validStatementJson(): unknown {
    return JSON.parse(JSON.stringify(buildStatement(payRecord())));
  }

  it('accepts a well-formed statement with matching subject binding (happy)', () => {
    const result = checkStatementShape(validStatementJson());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.statement.predicate.intent.action).toBe('payment.refund');
    }
  });

  it('rejects a wrong _type by name (error)', () => {
    const s = validStatementJson() as Record<string, unknown>;
    s['_type'] = 'https://in-toto.io/Statement/v0';
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/_type/);
  });

  it('rejects a wrong predicateType by name (error)', () => {
    const s = validStatementJson() as Record<string, unknown>;
    s['predicateType'] = 'https://evil.example/other/v1';
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/predicateType/);
  });

  it('rejects a subject array of length != 1 (error)', () => {
    const s = validStatementJson() as Record<string, unknown>;
    s['subject'] = [];
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/exactly one/);
  });

  it('rejects a subject name that does not bind intent.target_ref (error / AC5 guard)', () => {
    const s = validStatementJson() as { subject: { name: string; digest: { sha256: string } }[] };
    s.subject[0]!.name = 'order:does-not-match';
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/target_ref/);
  });

  it('rejects a subject digest that does not bind intent.params_hash (error / AC5 guard)', () => {
    const s = validStatementJson() as { subject: { name: string; digest: { sha256: string } }[] };
    s.subject[0]!.digest.sha256 = 'e'.repeat(64);
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/params_hash/);
  });

  it('rejects an invalid predicate (not a WitnessRecord) by name (error)', () => {
    const s = validStatementJson() as Record<string, unknown>;
    s['predicate'] = { not: 'a record' };
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/predicate is not a valid WitnessRecord/);
  });

  it('rejects a subject entry missing its digest (error)', () => {
    const s = validStatementJson() as { subject: { name: string; digest?: unknown }[] };
    delete s.subject[0]!.digest;
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/name and digest\.sha256/);
  });

  it('rejects a subject entry whose name is not a string (error)', () => {
    const s = validStatementJson() as { subject: { name: unknown; digest: { sha256: string } }[] };
    s.subject[0]!.name = 42;
    const result = checkStatementShape(s);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/name and digest\.sha256/);
  });

  it('rejects a non-object input (edge)', () => {
    expect(checkStatementShape(null).ok).toBe(false);
    expect(checkStatementShape([1, 2]).ok).toBe(false);
    expect(checkStatementShape('x').ok).toBe(false);
  });
});

describe('[UNIT] statementAsJson', () => {
  it('returns the same fields as a JsonValue (happy)', () => {
    const stmt = buildStatement(payRecord());
    const json = statementAsJson(stmt) as Record<string, unknown>;
    expect(json['_type']).toBe(STATEMENT_TYPE);
    expect(json['predicateType']).toBe(PREDICATE_TYPE);
  });

  it('serializes to JSON identically to the statement (happy)', () => {
    const stmt = buildStatement(payRecord());
    expect(JSON.stringify(statementAsJson(stmt))).toBe(JSON.stringify(stmt));
  });

  it('preserves the subject array (edge)', () => {
    const stmt = buildStatement(payRecord());
    const json = statementAsJson(stmt) as { subject: unknown[] };
    expect(Array.isArray(json.subject)).toBe(true);
    expect(json.subject).toHaveLength(1);
  });
});
