/**
 * @module cli/awp
 *
 * The `awp verify` command, as a TESTABLE pure-ish function: `runVerify(args,
 * io)` reads exactly one file, parses it, runs {@link verify}, formats the
 * per-check report, and returns an exit code (0 = PASS, non-zero = FAIL) without
 * calling `process.exit` itself. `../cli/index` is the thin executable that
 * wires real stdio and the real exit.
 *
 * This keeps the CLI a thin formatter over the library contract (AW-3
 * CLI-First) and keeps the integration tests free of process control.
 *
 * Offline (AC3): the ONLY I/O the command performs is reading the input file
 * (and, if `--pubkey` is a path, reading that file). The verifier itself does
 * no I/O. A test asserts no outbound network.
 *
 * Usage:
 * ```
 *   awp verify <receipt-or-envelope.json> --pubkey <key.pem|key.b64|inline>
 *              [--prev <prev_record_hash>] [--json]
 * ```
 * When `--pubkey` is omitted, the command looks for a `public_key_pem` or
 * `public_key_raw_base64` field inside the receipt/envelope file (the shape the
 * AW-2 vectors and the AW-3 fixtures use) so the 10-minute walkthrough is a
 * single `awp verify receipt.json`.
 *
 * Dependencies: Node `fs`, `../verify`. Used by: `../cli/index`, CLI tests.
 */

import { readFileSync } from 'node:fs';
import { verify, type VerifyReport } from '../verify/index.js';
import type { PublicKeyInput } from '../envelope/index.js';
import type { Rfc3161TrustAnchor } from '../anchor/index.js';

/** Injectable IO so tests capture output without touching real stdio. */
export interface CliIo {
  /** Read a UTF-8 file (defaults to `fs.readFileSync`). */
  readFile: (path: string) => string;
  /** Write a line to stdout. */
  out: (line: string) => void;
  /** Write a line to stderr. */
  err: (line: string) => void;
}

/** The default IO: real filesystem + console. */
export const defaultIo: CliIo = {
  readFile: (path) => readFileSync(path, 'utf8'),
  out: (line) => process.stdout.write(line + '\n'),
  err: (line) => process.stderr.write(line + '\n'),
};

/** Parsed `awp verify` arguments. */
interface ParsedArgs {
  file?: string;
  pubkey?: string;
  prev?: string;
  tsaPubkey?: string;
  tsaQualified: boolean;
  json: boolean;
  help: boolean;
}

/** The `--help` / usage text. */
export const USAGE = `awp verify — offline, zero-network verification of an AWP witness receipt.

USAGE:
  awp verify <receipt-or-envelope.json> [options]

OPTIONS:
  --pubkey <value>   Ed25519 public key: a PEM string, a 32-byte raw key in
                     base64, or a path to a file containing either. If omitted,
                     a "public_key_pem" or "public_key_raw_base64" field in the
                     input file is used.
  --prev <hash>      Expected predecessor record hash (lowercase 64-char hex
                     SHA-256) for the chain-link check.
  --tsa-pubkey <v>   RFC 3161 TSA trust anchor: a PEM/base64 SubjectPublicKeyInfo
                     or a path to one. Required to verify an RFC 3161 anchor
                     unless the receipt embeds "rfc3161_trust_anchor". Never
                     inferred — the verifier trusts no TSA implicitly.
  --tsa-qualified    Treat the supplied TSA anchor as a qualified eIDAS TSA. ONLY
                     this flag lets the report claim qualified time weight.
  --json             Emit the report as JSON instead of the human table.
  -h, --help         Show this help.

EXIT CODES:
  0   PASS — every applicable check passed.
  1   FAIL — at least one check failed (the failing check is named).
  2   USAGE — bad arguments or unreadable/unparseable input.

WHAT IT PROVES:
  Integrity-since-witness only — signature, statement binding, schema, profile,
  the claim-class honesty boundary, the hash-chain link, and (when present) the
  signed checkpoint, the RFC 9162 inclusion proof of the record's leaf under that
  checkpoint's root, and an external time anchor over that root (reported as an
  honest time BOUND, with the anchor's evidentiary weight). It does NOT prove
  completeness, authenticity-at-origin, or the identity of any person.`;

/**
 * Parse `awp verify` argv (everything AFTER the `verify` subcommand).
 *
 * @param args - The argument list after `verify`.
 * @returns The parsed arguments.
 */
export function parseArgs(args: string[]): ParsedArgs {
  const parsed: ParsedArgs = { json: false, help: false, tsaQualified: false };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--json') parsed.json = true;
    else if (a === '-h' || a === '--help') parsed.help = true;
    else if (a === '--tsa-qualified') parsed.tsaQualified = true;
    else if (a === '--pubkey') {
      const v = args[(i += 1)];
      if (v !== undefined) parsed.pubkey = v;
    } else if (a === '--prev') {
      const v = args[(i += 1)];
      if (v !== undefined) parsed.prev = v;
    } else if (a === '--tsa-pubkey') {
      const v = args[(i += 1)];
      if (v !== undefined) parsed.tsaPubkey = v;
    } else if (a !== undefined && !a.startsWith('-') && parsed.file === undefined) parsed.file = a;
  }
  return parsed;
}

/**
 * Resolve an RFC 3161 trust anchor from the `--tsa-pubkey` flag (a PEM/base64
 * key or a path to one) plus `--tsa-qualified`. Returns `undefined` when no TSA
 * key was supplied (an embedded `rfc3161_trust_anchor`, if present, is used by
 * the verifier instead). The `qualified` flag is the operator's assertion — the
 * SOLE thing that lets the report claim qualified weight.
 *
 * @param tsaPubkeyArg - The `--tsa-pubkey` value, if any.
 * @param qualified - Whether `--tsa-qualified` was passed.
 * @param io - IO for reading a key file.
 * @returns The trust anchor, or undefined.
 */
export function resolveTrustAnchor(
  tsaPubkeyArg: string | undefined,
  qualified: boolean,
  io: CliIo,
): Rfc3161TrustAnchor | undefined {
  if (tsaPubkeyArg === undefined) return undefined;
  let value = tsaPubkeyArg;
  try {
    value = io.readFile(tsaPubkeyArg);
  } catch {
    value = tsaPubkeyArg;
  }
  const trimmed = value.trim();
  const publicKey: string | Uint8Array = trimmed.includes('BEGIN')
    ? trimmed
    : new Uint8Array(Buffer.from(trimmed, 'base64'));
  return { publicKey, qualified };
}

/**
 * Resolve the public key from the `--pubkey` flag or from a field inside the
 * already-parsed input file. A `--pubkey` value that names an existing file is
 * read; otherwise it is used inline (PEM or base64). Returns `undefined` when no
 * key can be found (the caller reports a usage error).
 *
 * @param pubkeyArg - The `--pubkey` value, if any.
 * @param fileJson - The parsed input JSON (may carry an embedded key).
 * @param io - IO for reading a key file.
 * @returns The public key input, or undefined.
 */
export function resolvePublicKey(
  pubkeyArg: string | undefined,
  fileJson: unknown,
  io: CliIo,
): PublicKeyInput | undefined {
  if (pubkeyArg !== undefined) {
    // Try to read it as a file path; fall back to treating it as an inline value.
    let value = pubkeyArg;
    try {
      value = io.readFile(pubkeyArg);
    } catch {
      value = pubkeyArg;
    }
    return inlineKeyToInput(value);
  }
  if (fileJson !== null && typeof fileJson === 'object') {
    const obj = fileJson as Record<string, unknown>;
    if (typeof obj['public_key_pem'] === 'string') return obj['public_key_pem'];
    if (typeof obj['public_key_raw_base64'] === 'string') {
      return new Uint8Array(Buffer.from(obj['public_key_raw_base64'], 'base64'));
    }
  }
  return undefined;
}

/** Coerce an inline key string to a PublicKeyInput (PEM passthrough or b64→raw). */
function inlineKeyToInput(value: string): PublicKeyInput {
  const trimmed = value.trim();
  if (trimmed.includes('BEGIN PUBLIC KEY')) return trimmed;
  // Assume base64 of a 32-byte raw Ed25519 key.
  return new Uint8Array(Buffer.from(trimmed, 'base64'));
}

/** Format a {@link VerifyReport} as the human-readable per-check table. */
export function formatHuman(report: VerifyReport): string[] {
  const lines: string[] = [];
  for (const c of report.checks) {
    lines.push(`  [${c.ok ? 'PASS' : 'FAIL'}] ${c.name.padEnd(12)} ${c.reason}`);
  }
  lines.push('');
  lines.push(report.ok ? 'RESULT: PASS' : 'RESULT: FAIL');
  if (!report.ok) {
    const failed = report.checks.filter((c) => !c.ok).map((c) => c.name);
    lines.push(`  failed checks: ${failed.join(', ')}`);
  }
  lines.push('');
  lines.push(report.boundary);
  return lines;
}

/**
 * Run `awp verify`. Reads the input file, resolves the key, verifies, prints the
 * report (human table or `--json`), and RETURNS the exit code (does not call
 * `process.exit`). Exit 0 = PASS, 1 = FAIL, 2 = usage/IO error.
 *
 * @param args - argv after the `verify` subcommand.
 * @param io - Injectable IO (defaults to {@link defaultIo}).
 * @returns The process exit code.
 */
export function runVerify(args: string[], io: CliIo = defaultIo): number {
  const parsed = parseArgs(args);
  if (parsed.help) {
    io.out(USAGE);
    return 0;
  }
  if (parsed.file === undefined) {
    io.err('error: missing input file\n');
    io.err(USAGE);
    return 2;
  }

  let raw: string;
  try {
    raw = io.readFile(parsed.file);
  } catch (e) {
    io.err(`error: cannot read ${parsed.file}: ${(e as Error).message}`);
    return 2;
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (e) {
    io.err(`error: ${parsed.file} is not valid JSON: ${(e as Error).message}`);
    return 2;
  }

  const publicKey = resolvePublicKey(parsed.pubkey, json, io);
  if (publicKey === undefined) {
    io.err(
      'error: no public key. Pass --pubkey <pem|base64|path> or embed "public_key_pem"/"public_key_raw_base64" in the file.',
    );
    return 2;
  }

  const trustAnchor = resolveTrustAnchor(parsed.tsaPubkey, parsed.tsaQualified, io);
  const report = verify(json, {
    publicKey,
    ...(parsed.prev !== undefined ? { expectedPrevRecordHash: parsed.prev } : {}),
    ...(trustAnchor !== undefined ? { rfc3161TrustAnchor: trustAnchor } : {}),
  });

  if (parsed.json) {
    io.out(JSON.stringify(report, null, 2));
  } else {
    io.out(`awp verify ${parsed.file}`);
    io.out('');
    for (const line of formatHuman(report)) io.out(line);
  }

  return report.ok ? 0 : 1;
}

/**
 * Top-level CLI dispatch over the full argv (after `node awp`). Routes the
 * `verify` subcommand; `--help`/`-h`/no-args print usage. Returns the exit code.
 *
 * @param argv - The args after the program name (e.g. `process.argv.slice(2)`).
 * @param io - Injectable IO (defaults to {@link defaultIo}).
 * @returns The process exit code.
 */
export function run(argv: string[], io: CliIo = defaultIo): number {
  const [command, ...rest] = argv;
  if (command === undefined || command === '-h' || command === '--help') {
    io.out(USAGE);
    return command === undefined ? 2 : 0;
  }
  if (command === 'verify') {
    return runVerify(rest, io);
  }
  io.err(`error: unknown command "${command}"\n`);
  io.err(USAGE);
  return 2;
}
