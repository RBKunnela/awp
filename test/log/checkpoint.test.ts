/**
 * Tests for C2SP tlog-checkpoint + signed-note encode / parse / verify.
 *
 * Includes the AW-4 acceptance test c2sp-checkpoint-signed-note-verify: a valid
 * signed note over (origin, size, root) PASSES, and a tampered size or root
 * FAILS. Covers keyId derivation, note splitting, multi-signature notes, and the
 * malformed-input error paths (≥3 per function).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  merkleTreeHash,
  encodeCheckpoint,
  parseCheckpoint,
  keyId,
  signNote,
  addSignature,
  splitNote,
  verifyNote,
  createTestNoteSigner,
} from '../../src/log/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vec = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(here, 'vectors', name), 'utf8'));

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const leaves = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => enc(`leaf-${i}`));
const sampleRoot = (): Uint8Array => merkleTreeHash(leaves(7));
const ORIGIN = 'awp.example/log';

describe('encodeCheckpoint', () => {
  it('emits origin / decimal size / base64 root, newline-terminated (happy)', () => {
    const body = encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() });
    const lines = body.split('\n');
    expect(lines[0]).toBe(ORIGIN);
    expect(lines[1]).toBe('7');
    expect(lines[2]).toBe(Buffer.from(sampleRoot()).toString('base64'));
    expect(body.endsWith('\n')).toBe(true);
  });

  it('appends optional extension lines (edge)', () => {
    const body = encodeCheckpoint({ origin: ORIGIN, size: 0, root: sampleRoot(), extensions: ['ext one'] });
    expect(body.split('\n')[3]).toBe('ext one');
  });

  it('throws for a non-32-byte root, negative size, or bad origin/ext (error)', () => {
    expect(() => encodeCheckpoint({ origin: ORIGIN, size: 1, root: new Uint8Array(31) })).toThrow(RangeError);
    expect(() => encodeCheckpoint({ origin: ORIGIN, size: -1, root: sampleRoot() })).toThrow(RangeError);
    expect(() => encodeCheckpoint({ origin: '', size: 1, root: sampleRoot() })).toThrow(RangeError);
    expect(() => encodeCheckpoint({ origin: ORIGIN, size: 1, root: sampleRoot(), extensions: [''] })).toThrow(RangeError);
  });
});

describe('parseCheckpoint', () => {
  it('round-trips with encodeCheckpoint (happy)', () => {
    const root = sampleRoot();
    const body = encodeCheckpoint({ origin: ORIGIN, size: 7, root });
    const r = parseCheckpoint(body);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.checkpoint.origin).toBe(ORIGIN);
      expect(r.checkpoint.size).toBe(7);
      expect(Buffer.from(r.checkpoint.root).toString('hex')).toBe(Buffer.from(root).toString('hex'));
    }
  });

  it('captures extension lines (edge)', () => {
    const body = encodeCheckpoint({ origin: ORIGIN, size: 2, root: sampleRoot(), extensions: ['a', 'b'] });
    const r = parseCheckpoint(body);
    expect(r.ok && r.checkpoint.extensions).toEqual(['a', 'b']);
  });

  it('rejects too-few lines, leading-zero size, and a non-32-byte root (error)', () => {
    expect(parseCheckpoint('origin\n7\n').ok).toBe(false);
    expect(parseCheckpoint(`${ORIGIN}\n07\n${Buffer.from(sampleRoot()).toString('base64')}\n`).ok).toBe(false);
    expect(parseCheckpoint(`${ORIGIN}\n7\n${Buffer.from(new Uint8Array(16)).toString('base64')}\n`).ok).toBe(false);
  });
});

describe('keyId', () => {
  it('derives SHA-256(name || 0x0A || 0x01 || pub)[:4] (happy, vector)', () => {
    const v = vec('checkpoint-signed-note.json');
    const pub = Buffer.from(v.publicKeyHex as string, 'hex');
    expect(Buffer.from(keyId(v.origin as string, new Uint8Array(pub))).toString('hex')).toBe(v.keyIdHex);
  });

  it('is 4 bytes (edge)', () => {
    const { publicKey } = createTestNoteSigner(ORIGIN);
    expect(keyId(ORIGIN, publicKey).length).toBe(4);
  });

  it('throws for a non-32-byte key (error)', () => {
    expect(() => keyId(ORIGIN, new Uint8Array(16))).toThrow(RangeError);
  });
});

describe('signNote / splitNote', () => {
  it('produces a note that splits back to the original text + one signature (happy)', () => {
    const { signer } = createTestNoteSigner(ORIGIN);
    const body = encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() });
    const note = signNote(body, signer);
    const split = splitNote(note);
    expect(split.ok).toBe(true);
    if (split.ok) {
      expect(split.text).toBe(body);
      expect(split.signatures.length).toBe(1);
      expect(split.signatures[0]!.name).toBe(ORIGIN);
    }
  });

  it('signNote throws if the text does not end in a newline (error)', () => {
    const { signer } = createTestNoteSigner(ORIGIN);
    expect(() => signNote('no newline', signer)).toThrow(/newline/);
  });

  it('splitNote rejects a note with no blank separator or no signatures (error)', () => {
    expect(splitNote('just text\n').ok).toBe(false);
    expect(splitNote('text\n\n').ok).toBe(false);
  });

  it('addSignature yields a two-signature note (edge)', () => {
    const a = createTestNoteSigner(ORIGIN);
    const b = createTestNoteSigner('witness.example/w1');
    const body = encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() });
    const note = addSignature(signNote(body, a.signer), b.signer);
    const split = splitNote(note);
    expect(split.ok && split.signatures.length).toBe(2);
  });
});

describe('verifyNote — c2sp-checkpoint-signed-note-verify', () => {
  it('verifies a valid signed note and reports all checks ok (happy)', () => {
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const body = encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() });
    const note = signNote(body, signer);
    const r = verifyNote(note, verifier);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.checks.every((c) => c.ok)).toBe(true);
      expect(r.checks.map((c) => c.name)).toEqual(['note-shape', 'key-id', 'signature']);
      expect(r.text).toBe(body);
    }
  });

  it('verifies the committed fixed-key vector note', () => {
    const v = vec('checkpoint-signed-note.json');
    const verifier = { name: v.origin as string, publicKey: new Uint8Array(Buffer.from(v.publicKeyHex as string, 'hex')) };
    const r = verifyNote(v.signedNote as string, verifier);
    expect(r.ok).toBe(true);
    if (r.ok) {
      const cp = parseCheckpoint(r.text);
      expect(cp.ok && cp.checkpoint.size).toBe(7);
    }
  });

  it('FAILS when the checkpoint size is tampered (error)', () => {
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const root = sampleRoot();
    const note = signNote(encodeCheckpoint({ origin: ORIGIN, size: 7, root }), signer);
    const tampered = note.replace('\n7\n', '\n8\n');
    const r = verifyNote(tampered, verifier);
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });

  it('FAILS when the root is tampered (error)', () => {
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const goodRoot = sampleRoot();
    const badRoot = merkleTreeHash(leaves(8));
    const note = signNote(encodeCheckpoint({ origin: ORIGIN, size: 7, root: goodRoot }), signer);
    const tampered = note.replace(
      Buffer.from(goodRoot).toString('base64'),
      Buffer.from(badRoot).toString('base64'),
    );
    const r = verifyNote(tampered, verifier);
    expect(r.ok).toBe(false);
  });

  it('FAILS against the wrong public key (error)', () => {
    const { signer } = createTestNoteSigner(ORIGIN);
    const other = createTestNoteSigner(ORIGIN);
    const note = signNote(encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() }), signer);
    const r = verifyNote(note, other.verifier);
    expect(r.ok).toBe(false);
    // Wrong key ⇒ no matching key-id line.
    expect(r.checks.find((c) => c.name === 'key-id')?.ok).toBe(false);
  });

  it('FAILS a malformed note at note-shape (edge)', () => {
    const { verifier } = createTestNoteSigner(ORIGIN);
    const r = verifyNote('garbage with no structure', verifier);
    expect(r.ok).toBe(false);
    expect(r.checks[0]!.name).toBe('note-shape');
  });

  it('FAILS at key-id when the verifier public key is not 32 bytes (error)', () => {
    const { signer } = createTestNoteSigner(ORIGIN);
    const note = signNote(encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() }), signer);
    const r = verifyNote(note, { name: ORIGIN, publicKey: new Uint8Array(16) });
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'key-id')?.ok).toBe(false);
  });

  it('FAILS at signature when the matching line carries a corrupt signature (error)', () => {
    const { signer, verifier } = createTestNoteSigner(ORIGIN);
    const note = signNote(encodeCheckpoint({ origin: ORIGIN, size: 7, root: sampleRoot() }), signer);
    const split = splitNote(note);
    expect(split.ok).toBe(true);
    if (!split.ok) return;
    // Keep the key-id intact but flip a byte of the raw signature, then re-encode
    // the signature line so key-id still matches but the Ed25519 check fails.
    const sig = split.signatures[0]!;
    const corrupt = new Uint8Array(sig.signature);
    corrupt[0] = (corrupt[0]! ^ 0xff) & 0xff;
    const blob = Buffer.concat([Buffer.from(sig.keyId), Buffer.from(corrupt)]);
    const corruptNote = split.text + '\n' + `— ${sig.name} ${blob.toString('base64')}` + '\n';
    const r = verifyNote(corruptNote, verifier);
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'key-id')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === 'signature')?.ok).toBe(false);
  });
});
