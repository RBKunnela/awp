/**
 * Committed-vector tests (AW-2 Tests & docs): a valid signed envelope, a
 * tampered envelope, and a wrong-key case are pinned on disk so any future
 * change to the envelope/PAE/canonicalization that breaks compatibility is
 * caught, and so an auditor can reproduce verification from the committed bytes
 * alone. Each vector carries its own `_comment` describing what it must prove.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyEnvelope } from '../../src/envelope/dsse.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = join(here, 'vectors');

function load(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(vectors, name), 'utf8')) as Record<string, unknown>;
}

describe('[INTEGRATION] committed envelope vectors', () => {
  it('signed-envelope.json verifies against its committed public key (happy)', () => {
    const v = load('signed-envelope.json');
    const result = verifyEnvelope(v['envelope'], v['public_key_pem'] as string);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.record.profile).toBe('pay');
      expect(result.checks.every((c) => c.ok)).toBe(true);
    }
  });

  it('signed-envelope.json also verifies against the committed raw 32-byte key (edge)', () => {
    const v = load('signed-envelope.json');
    const raw = new Uint8Array(Buffer.from(v['public_key_raw_base64'] as string, 'base64'));
    const result = verifyEnvelope(v['envelope'], raw);
    expect(result.ok).toBe(true);
  });

  it('tampered-envelope.json fails the signature check (AC3)', () => {
    const v = load('tampered-envelope.json');
    const result = verifyEnvelope(v['envelope'], v['public_key_pem'] as string);
    expect(result.ok).toBe(false);
    expect(result.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });

  it('wrong-key.json fails when verified against a different key (AC4)', () => {
    const v = load('wrong-key.json');
    const result = verifyEnvelope(v['envelope'], v['wrong_public_key_pem'] as string);
    expect(result.ok).toBe(false);
    expect(result.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });
});
