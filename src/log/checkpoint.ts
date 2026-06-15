/**
 * @module log/checkpoint
 *
 * C2SP `tlog-checkpoint` + `signed-note` encode / parse / verify for the OPEN
 * AWP transparency log (AW-4). A checkpoint is the log's signed commitment to
 * "at tree size N, the Merkle root is R" — the artifact external monitors and
 * witnesses cosign, and the artifact AW-5 anchors (qualified TSA + OpenTimestamps).
 *
 * This is the SAME checkpoint/signed-note format Go sumdb, Sigsum, and Sigstore
 * Rekor v2 use, so an independent verifier interoperates with no special casing.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * tlog-checkpoint body (C2SP `tlog-checkpoint`), lines separated by `\n`:
 *
 *   <origin>\n            line 1: unique log identity string (schema-less)
 *   <size>\n              line 2: ASCII decimal leaf count, no leading zeros
 *   <base64(root)>\n      line 3: standard base64 (RFC 4648 §4) of the 32-byte root
 *   [<extension>\n ...]    optional opaque non-empty extension lines
 *
 * signed-note (C2SP `signed-note`):
 *
 *   <note text>           the checkpoint body above (ends in `\n`)
 *   \n                    one blank line
 *   — <key name> <base64(keyID || sig)>\n   one or more signature lines
 *
 *   - The leading rune on each signature line is EM DASH U+2014, then a space.
 *   - `base64(keyID || sig)` is standard base64 of (4-byte big-endian key ID ||
 *     the raw signature bytes). For Ed25519 the signature is 64 bytes → 68 bytes
 *     total → 92 base64 chars.
 *   - The signature is computed over the NOTE TEXT (the checkpoint body, ending
 *     in `\n`) — NOT over the blank line or the signature lines.
 *
 * Ed25519 key ID (C2SP `signed-note`):
 *
 *   keyID = SHA-256( <key name> || 0x0A || 0x01 || <32-byte Ed25519 pubkey> )[:4]
 *
 *   The `0x0A` is a literal newline byte; `0x01` is the Ed25519 signature-type
 *   algorithm byte. The first 4 bytes of that SHA-256 are the big-endian key ID.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Key custody: signing goes through a caller-supplied closure (the log holds its
 * own Ed25519 key); this OPEN package never generates or holds production keys.
 * A test signer is provided for vectors/tests ONLY. Verification takes a raw
 * 32-byte Ed25519 public key plus the expected key name.
 *
 * Dependencies: Node `crypto` (stdlib Ed25519 + SHA-256), `./merkle-rfc9162`
 * (root hex/bytes helpers).
 * Used by: `./index`, AW-5 (anchors the checkpoint root), AW-6 (binds a receipt's
 * inclusion proof to a verified checkpoint).
 *
 * @example
 * import { encodeCheckpoint, signNote, verifyNote, parseCheckpoint } from './log/index.js';
 * const body = encodeCheckpoint({ origin: 'awp.example/log', size: 4, root });
 * const note = signNote(body, signer);
 * const v = verifyNote(note, { name: 'awp.example/log', publicKey });
 * if (v.ok) console.log(parseCheckpoint(v.text));
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  createHash,
  type KeyObject,
} from 'node:crypto';
import { HASH_SIZE } from './merkle-rfc9162.js';

/** EM DASH (U+2014) — the leading rune of every signed-note signature line. */
const EM_DASH = '—';
/** Ed25519 signature-type / algorithm byte in the C2SP key-ID hash. */
const ED25519_ALG_BYTE = 0x01;
/** Raw Ed25519 signature length in bytes (RFC 8032). */
const ED25519_SIG_LEN = 64;

/** A parsed C2SP tlog-checkpoint. */
export interface Checkpoint {
  /** Unique log identity string (line 1). */
  origin: string;
  /** Tree size — leaf count (line 2). */
  size: number;
  /** The 32-byte Merkle root (decoded from the base64 of line 3). */
  root: Uint8Array;
  /** Any opaque extension lines after line 3 (verbatim, no trailing newline). */
  extensions: string[];
}

/**
 * Encode a {@link Checkpoint} into its C2SP `tlog-checkpoint` body text (the
 * note text that gets signed). The body ends with a trailing newline, as a
 * signed-note's text MUST.
 *
 * @param cp - The checkpoint fields. `root` must be 32 bytes.
 * @returns The checkpoint body string (UTF-8 text, ends in `\n`).
 * @throws {RangeError} If `root` is not 32 bytes or `size` is not a non-negative
 *   integer, or an extension line is empty / contains a newline.
 *
 * @example
 * encodeCheckpoint({ origin: 'awp.example/log', size: 4, root });
 * // 'awp.example/log\n4\n<base64root>\n'
 */
export function encodeCheckpoint(cp: {
  origin: string;
  size: number;
  root: Uint8Array;
  extensions?: string[];
}): string {
  if (cp.root.length !== HASH_SIZE) {
    throw new RangeError(`checkpoint root must be ${HASH_SIZE} bytes (got ${cp.root.length})`);
  }
  if (!Number.isInteger(cp.size) || cp.size < 0) {
    throw new RangeError(`checkpoint size must be a non-negative integer (got ${cp.size})`);
  }
  if (cp.origin.length === 0 || cp.origin.includes('\n')) {
    throw new RangeError('checkpoint origin must be a non-empty single line');
  }
  const lines = [cp.origin, String(cp.size), Buffer.from(cp.root).toString('base64')];
  for (const ext of cp.extensions ?? []) {
    if (ext.length === 0 || ext.includes('\n')) {
      throw new RangeError('checkpoint extension lines must be non-empty and contain no newline');
    }
    lines.push(ext);
  }
  return lines.join('\n') + '\n';
}

/** Result of {@link parseCheckpoint}. */
export type ParseCheckpointResult =
  | { ok: true; checkpoint: Checkpoint }
  | { ok: false; reason: string };

/**
 * Parse a C2SP `tlog-checkpoint` body (the note text) into a {@link Checkpoint}.
 * Validates the three required lines, the decimal size (no leading zeros), and
 * that the root decodes to exactly 32 bytes. Extra lines become `extensions`.
 *
 * @param text - The checkpoint body text (as returned by {@link encodeCheckpoint}
 *   or extracted from a verified note).
 * @returns `{ ok: true, checkpoint }` or `{ ok: false, reason }`.
 *
 * @example
 * const r = parseCheckpoint('awp.example/log\n4\n<base64root>\n');
 * if (r.ok) console.log(r.checkpoint.size); // 4
 */
export function parseCheckpoint(text: string): ParseCheckpointResult {
  // Split on '\n'; a well-formed body ends with '\n', yielding a trailing ''.
  const rawLines = text.split('\n');
  // Drop exactly one trailing '' produced by the final newline, if present.
  if (rawLines.length > 0 && rawLines[rawLines.length - 1] === '') rawLines.pop();
  if (rawLines.length < 3) {
    return { ok: false, reason: 'checkpoint must have at least 3 lines (origin, size, root)' };
  }
  const [origin, sizeLine, rootLine, ...extensions] = rawLines as [string, string, string, ...string[]];
  if (origin.length === 0) {
    return { ok: false, reason: 'checkpoint origin (line 1) is empty' };
  }
  if (!/^(0|[1-9][0-9]*)$/.test(sizeLine)) {
    return { ok: false, reason: `checkpoint size (line 2) must be decimal with no leading zeros, got ${JSON.stringify(sizeLine)}` };
  }
  const size = Number(sizeLine);
  if (!Number.isSafeInteger(size)) {
    return { ok: false, reason: `checkpoint size ${sizeLine} is too large` };
  }
  let root: Buffer;
  try {
    root = Buffer.from(rootLine, 'base64');
  } catch (err) {
    return { ok: false, reason: `checkpoint root (line 3) is not valid base64: ${(err as Error).message}` };
  }
  // Buffer.from is lenient; re-encode to confirm the input was real base64 of 32 bytes.
  if (root.length !== HASH_SIZE || root.toString('base64') !== rootLine) {
    return { ok: false, reason: `checkpoint root must be base64 of exactly ${HASH_SIZE} bytes` };
  }
  for (const ext of extensions) {
    if (ext.length === 0) {
      return { ok: false, reason: 'checkpoint extension lines must be non-empty' };
    }
  }
  return {
    ok: true,
    checkpoint: { origin, size, root: new Uint8Array(root), extensions },
  };
}

/**
 * A signing function injected by the log's key holder: given the exact note text
 * BYTES, return the raw 64-byte Ed25519 signature. The OPEN package never sees
 * the private key.
 */
export type NoteSignFn = (noteTextBytes: Uint8Array) => Uint8Array;

/** A note signer: the log's key name, its public key (for key-ID derivation), and how to sign. */
export interface NoteSigner {
  /** The log's signed-note key name (typically equal to, or tied to, the origin). */
  name: string;
  /** The log's 32-byte Ed25519 public key (used to derive the 4-byte key ID). */
  publicKey: Uint8Array;
  /** Produce a raw Ed25519 signature over the note text bytes. */
  sign: NoteSignFn;
}

/**
 * Compute the C2SP signed-note 4-byte Ed25519 key ID:
 * `SHA-256(name || 0x0A || 0x01 || pubkey)[:4]`, big-endian.
 *
 * @param name - The signed-note key name.
 * @param publicKey - The 32-byte Ed25519 public key.
 * @returns The 4-byte key ID.
 * @throws {RangeError} If `publicKey` is not 32 bytes.
 *
 * @example
 * keyId('awp.example/log', pub); // Uint8Array(4)
 */
export function keyId(name: string, publicKey: Uint8Array): Uint8Array {
  if (publicKey.length !== 32) {
    throw new RangeError(`Ed25519 public key must be 32 bytes (got ${publicKey.length})`);
  }
  const h = createHash('sha256');
  h.update(Buffer.from(name, 'utf8'));
  h.update(Uint8Array.of(0x0a)); // literal newline byte
  h.update(Uint8Array.of(ED25519_ALG_BYTE)); // Ed25519 algorithm byte
  h.update(publicKey);
  return new Uint8Array(h.digest()).slice(0, 4);
}

/**
 * Sign a note text with one Ed25519 signer, producing the C2SP signed-note wire
 * text: the note text, a blank line, then a single signature line. Append more
 * signatures (e.g. witness cosignatures) with {@link addSignature}.
 *
 * @param noteText - The note text (e.g. a checkpoint body ending in `\n`).
 * @param signer - The log's note signer.
 * @returns The signed-note text.
 * @throws {Error} If `noteText` does not end in a newline (signed-note requires it).
 *
 * @example
 * const note = signNote(encodeCheckpoint(cp), signer);
 */
export function signNote(noteText: string, signer: NoteSigner): string {
  if (!noteText.endsWith('\n')) {
    throw new Error('signed-note text must end with a newline (U+000A)');
  }
  const sigLine = signatureLine(noteText, signer);
  return noteText + '\n' + sigLine + '\n';
}

/**
 * Append an additional signature line (e.g. a witness cosignature) to an
 * existing signed note, over the same note text.
 *
 * @param note - An existing signed-note text.
 * @param signer - Another note signer.
 * @returns The signed note with one more signature line.
 * @throws {Error} If `note` is not a parseable signed note.
 *
 * @example
 * const cosigned = addSignature(note, witnessSigner);
 */
export function addSignature(note: string, signer: NoteSigner): string {
  const split = splitNote(note);
  if (!split.ok) throw new Error(`cannot add signature: ${split.reason}`);
  const sigLine = signatureLine(split.text, signer);
  return note.endsWith('\n') ? note + sigLine + '\n' : note + '\n' + sigLine + '\n';
}

/**
 * Build a single signature line `— <name> <base64(keyID || sig)>` for `noteText`.
 *
 * @param noteText - The note text the signature covers.
 * @param signer - The note signer.
 * @returns The signature line (without trailing newline).
 */
function signatureLine(noteText: string, signer: NoteSigner): string {
  const id = keyId(signer.name, signer.publicKey);
  const sig = signer.sign(new TextEncoder().encode(noteText));
  if (sig.length !== ED25519_SIG_LEN) {
    throw new Error(`Ed25519 signature must be ${ED25519_SIG_LEN} bytes (got ${sig.length})`);
  }
  const blob = Buffer.concat([Buffer.from(id), Buffer.from(sig)]);
  return `${EM_DASH} ${signer.name} ${blob.toString('base64')}`;
}

/** A parsed signature line from a signed note. */
export interface NoteSignature {
  /** The key name on the signature line. */
  name: string;
  /** The 4-byte key ID (first 4 bytes of the decoded blob). */
  keyId: Uint8Array;
  /** The raw signature bytes (the rest of the decoded blob). */
  signature: Uint8Array;
}

/** Result of {@link splitNote}: the note text plus its parsed signature lines. */
export type SplitNoteResult =
  | { ok: true; text: string; signatures: NoteSignature[] }
  | { ok: false; reason: string };

/**
 * Split a signed note into its note text and its signature lines WITHOUT
 * verifying any signature. Validates the structural shape: text, a blank line,
 * then one or more `— name base64` lines.
 *
 * @param note - The signed-note text.
 * @returns `{ ok: true, text, signatures }` or `{ ok: false, reason }`.
 */
export function splitNote(note: string): SplitNoteResult {
  // The note text is everything up to and including the newline that precedes
  // the blank separator line. Signed-note: text, blank line, signature lines.
  const sep = note.indexOf('\n\n');
  if (sep === -1) {
    return { ok: false, reason: 'signed note has no blank line separating text from signatures' };
  }
  const text = note.slice(0, sep + 1); // include the text's terminating newline
  const sigBlock = note.slice(sep + 2); // after the blank line
  const sigLines = sigBlock.split('\n').filter((l) => l.length > 0);
  if (sigLines.length === 0) {
    return { ok: false, reason: 'signed note has no signature lines' };
  }
  const signatures: NoteSignature[] = [];
  for (const line of sigLines) {
    const parsed = parseSignatureLine(line);
    if (!parsed.ok) return { ok: false, reason: parsed.reason };
    signatures.push(parsed.signature);
  }
  return { ok: true, text, signatures };
}

/** Parse one `— name base64(keyID||sig)` signature line. */
function parseSignatureLine(
  line: string,
): { ok: true; signature: NoteSignature } | { ok: false; reason: string } {
  if (!line.startsWith(EM_DASH + ' ')) {
    return { ok: false, reason: `signature line must start with "${EM_DASH} ", got ${JSON.stringify(line.slice(0, 4))}` };
  }
  const rest = line.slice(2); // drop em dash + space
  const lastSpace = rest.lastIndexOf(' ');
  if (lastSpace === -1) {
    return { ok: false, reason: 'signature line missing the base64 field' };
  }
  const name = rest.slice(0, lastSpace);
  const b64 = rest.slice(lastSpace + 1);
  if (name.length === 0) {
    return { ok: false, reason: 'signature line has an empty key name' };
  }
  let blob: Buffer;
  try {
    blob = Buffer.from(b64, 'base64');
  } catch (err) {
    return { ok: false, reason: `signature base64 invalid: ${(err as Error).message}` };
  }
  if (blob.toString('base64') !== b64 || blob.length < 4) {
    return { ok: false, reason: 'signature blob must be base64 of at least 4 bytes (keyID || sig)' };
  }
  return {
    ok: true,
    signature: {
      name,
      keyId: new Uint8Array(blob.subarray(0, 4)),
      signature: new Uint8Array(blob.subarray(4)),
    },
  };
}

/** A public key + its expected name, for {@link verifyNote}. */
export interface NoteVerifier {
  /** The expected signed-note key name. */
  name: string;
  /** The log's 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
}

/** A single named check result, mirroring the AW-2/AW-3 per-check report contract. */
export interface NoteCheck {
  /** Check name, e.g. `"note-shape"`, `"key-id"`, `"signature"`. */
  name: string;
  /** Whether the check passed. */
  ok: boolean;
  /** One-line human reason (always present). */
  reason: string;
}

/** Result of {@link verifyNote}. */
export type VerifyNoteResult =
  | { ok: true; checks: NoteCheck[]; text: string }
  | { ok: false; checks: NoteCheck[] };

/**
 * Verify a C2SP signed note FAIL-CLOSED against one Ed25519 verifier (name +
 * public key). Reports each check by name:
 *
 *  1. `note-shape` — the note splits into text + ≥1 well-formed signature line;
 *  2. `key-id`     — at least one signature line matches the expected name AND
 *                    its 4-byte key ID equals `keyId(name, publicKey)`;
 *  3. `signature`  — that signature verifies (Ed25519) over the note TEXT bytes.
 *
 * A tampered checkpoint body (changed size or root) changes the note text, so
 * the Ed25519 signature fails `signature`. A wrong key fails `key-id`/`signature`.
 *
 * @param note - The signed-note text.
 * @param verifier - The expected name + 32-byte Ed25519 public key.
 * @returns Per-check list, plus the verified note text on success.
 *
 * @example
 * const r = verifyNote(note, { name: 'awp.example/log', publicKey });
 * if (r.ok) console.log(parseCheckpoint(r.text));
 */
export function verifyNote(note: string, verifier: NoteVerifier): VerifyNoteResult {
  const checks: NoteCheck[] = [];

  const split = splitNote(note);
  if (!split.ok) {
    checks.push({ name: 'note-shape', ok: false, reason: split.reason });
    return { ok: false, checks };
  }
  checks.push({ name: 'note-shape', ok: true, reason: `well-formed signed note with ${split.signatures.length} signature(s)` });

  let expectedId: Uint8Array;
  try {
    expectedId = keyId(verifier.name, verifier.publicKey);
  } catch (err) {
    checks.push({ name: 'key-id', ok: false, reason: `invalid verifier key: ${(err as Error).message}` });
    return { ok: false, checks };
  }

  const candidate = split.signatures.find(
    (s) => s.name === verifier.name && bytesEqual(s.keyId, expectedId),
  );
  if (candidate === undefined) {
    checks.push({
      name: 'key-id',
      ok: false,
      reason: `no signature line matches name "${verifier.name}" with the expected key ID`,
    });
    return { ok: false, checks };
  }
  checks.push({ name: 'key-id', ok: true, reason: `signature line for "${verifier.name}" matches the expected key ID` });

  let keyObject: KeyObject;
  try {
    keyObject = ed25519PublicKeyObject(verifier.publicKey);
  } catch (err) {
    checks.push({ name: 'signature', ok: false, reason: `invalid public key: ${(err as Error).message}` });
    return { ok: false, checks };
  }

  let sigOk = false;
  try {
    sigOk = nodeVerify(
      null,
      new TextEncoder().encode(split.text),
      keyObject,
      Buffer.from(candidate.signature),
    );
  } catch {
    sigOk = false;
  }
  if (!sigOk) {
    checks.push({
      name: 'signature',
      ok: false,
      reason: 'Ed25519 signature did not verify over the note text (tampered checkpoint or wrong key)',
    });
    return { ok: false, checks };
  }
  checks.push({ name: 'signature', ok: true, reason: 'Ed25519 signature verified over the note text' });

  return { ok: true, checks, text: split.text };
}

// ---------------------------------------------------------------------------
// Internal helpers + test-only signer.
// ---------------------------------------------------------------------------

/** The fixed 12-byte DER prefix for an Ed25519 SubjectPublicKeyInfo. */
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Wrap a raw 32-byte Ed25519 public key as a Node `KeyObject` via DER SPKI.
 *
 * @param raw - The raw 32-byte Ed25519 public key.
 * @returns A Node public `KeyObject`.
 */
function ed25519PublicKeyObject(raw: Uint8Array): KeyObject {
  if (raw.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes (got ${raw.length})`);
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/** Length-checked byte equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Create an in-process Ed25519 {@link NoteSigner} + a matching {@link NoteVerifier}
 * for tests and committed vectors ONLY. Real logs inject their own signer; the
 * OPEN package never generates or holds production keys.
 *
 * @param name - The signed-note key name to use.
 * @returns `{ signer, verifier, publicKey, privateKey }`.
 *
 * @example
 * const { signer, verifier } = createTestNoteSigner('awp.example/log');
 * const note = signNote(encodeCheckpoint(cp), signer);
 * verifyNote(note, verifier).ok; // true
 */
export function createTestNoteSigner(name: string): {
  signer: NoteSigner;
  verifier: NoteVerifier;
  publicKey: Uint8Array;
  privateKey: KeyObject;
} {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  // Extract the raw 32-byte public key from the DER SPKI (last 32 bytes).
  const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const rawPub = new Uint8Array(spki.subarray(spki.length - 32));
  const signer: NoteSigner = {
    name,
    publicKey: rawPub,
    sign: (bytes: Uint8Array): Uint8Array => new Uint8Array(nodeSign(null, bytes, privateKey)),
  };
  return {
    signer,
    verifier: { name, publicKey: rawPub },
    publicKey: rawPub,
    privateKey,
  };
}
