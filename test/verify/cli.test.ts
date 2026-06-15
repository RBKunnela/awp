/**
 * CLI integration tests for `awp verify` (AW-3 cli/awp.ts). Uses an injectable
 * IO so no process control is needed, and the committed fixtures so the exact
 * 10-minute auditor walkthrough (byte-flip → FAIL) is asserted end-to-end.
 *
 * Acceptance: cli-verify-pass-exit-0, cli-verify-tamper-exit-nonzero-names-check,
 * verify-prints-per-check-list (with the honesty boundary line), plus flag and
 * usage-error coverage.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { run, runVerify, parseArgs, formatHuman, resolvePublicKey, resolveTrustAnchor, USAGE, type CliIo } from '../../src/cli/awp.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, 'fixtures');
const VALID = join(fixtures, 'valid-receipt.json');
const TAMPERED = join(fixtures, 'tampered-receipt.json');
const FULL = join(fixtures, 'full-receipt.json');
const FULL_TAMPERED = join(fixtures, 'full-receipt-tampered.json');
const SAMPLE = join(here, '..', '..', 'samples', 'receipt.json');

/** A capturing IO that reads real files but buffers stdout/stderr. */
function capturingIo(): CliIo & { stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    readFile: (p: string) => readFileSync(p, 'utf8'),
    out: (l: string) => stdout.push(l),
    err: (l: string) => stderr.push(l),
    stdout,
    stderr,
  };
}

describe('parseArgs', () => {
  it('parses file + flags', () => {
    const p = parseArgs(['r.json', '--pubkey', 'k.pem', '--prev', 'abc', '--json']);
    expect(p.file).toBe('r.json');
    expect(p.pubkey).toBe('k.pem');
    expect(p.prev).toBe('abc');
    expect(p.json).toBe(true);
  });
  it('sets help on -h/--help', () => {
    expect(parseArgs(['--help']).help).toBe(true);
    expect(parseArgs(['-h']).help).toBe(true);
  });
  it('takes the first positional as the file', () => {
    expect(parseArgs(['a.json', 'b.json']).file).toBe('a.json');
  });
});

describe('cli verify — PASS path (cli-verify-pass-exit-0)', () => {
  it('prints PASS and exits 0 for the valid fixture', () => {
    const io = capturingIo();
    const code = run(['verify', VALID], io);
    expect(code).toBe(0);
    const text = io.stdout.join('\n');
    expect(text).toMatch(/RESULT: PASS/);
    expect(text).toMatch(/\[PASS\] signature/);
    expect(text).toMatch(/\[PASS\] anchor/);
  });

  it('binds and prints the record hashes (subject/intent) via the check list', () => {
    const io = capturingIo();
    run(['verify', VALID], io);
    const text = io.stdout.join('\n');
    expect(text).toMatch(/subject binds intent/);
    expect(text).toMatch(/Bitcoin-confirmed|trust-minimized/);
  });
});

describe('cli verify — TAMPER path (cli-verify-tamper-exit-nonzero-names-check)', () => {
  it('prints FAIL, names the signature check, and exits non-zero for the byte-flipped fixture', () => {
    const io = capturingIo();
    const code = run(['verify', TAMPERED], io);
    expect(code).not.toBe(0);
    const text = io.stdout.join('\n');
    expect(text).toMatch(/RESULT: FAIL/);
    expect(text).toMatch(/\[FAIL\] signature/);
    expect(text).toMatch(/failed checks: .*signature/);
  });
});

describe('cli verify — per-check list + honesty boundary (verify-prints-per-check-list)', () => {
  it('prints every check and the verbatim honesty-boundary line', () => {
    const io = capturingIo();
    run(['verify', VALID], io);
    const text = io.stdout.join('\n');
    for (const name of ['envelope-shape', 'signature', 'schema', 'profile', 'claim-class', 'chain-link', 'anchor']) {
      expect(text).toContain(name);
    }
    expect(text).toMatch(/integrity-since-witness only/);
  });

  it('--json emits a structured report with ok + checks + boundary', () => {
    const io = capturingIo();
    const code = run(['verify', VALID, '--json'], io);
    expect(code).toBe(0);
    // In --json mode the entire (pretty-printed) JSON report is written via a
    // single io.out call, so the whole buffer is the JSON document.
    const parsed = JSON.parse(io.stdout.join('\n'));
    expect(parsed.ok).toBe(true);
    expect(Array.isArray(parsed.checks)).toBe(true);
    expect(parsed.boundary).toMatch(/integrity-since-witness/);
  });
});

describe('cli verify — chain-link via --prev', () => {
  it('FAILS chain-link and exits non-zero when --prev does not match', () => {
    const io = capturingIo();
    const code = run(['verify', VALID, '--prev', 'd'.repeat(64)], io);
    expect(code).toBe(1);
    expect(io.stdout.join('\n')).toMatch(/\[FAIL\] chain-link/);
  });

  it('PASSES when --prev matches the record predecessor', () => {
    // valid-pay's prev_record_hash is all-zero genesis.
    const io = capturingIo();
    const code = run(['verify', VALID, '--prev', '0'.repeat(64)], io);
    expect(code).toBe(0);
  });
});

describe('cli verify — key resolution', () => {
  it('uses an embedded public_key_pem when --pubkey is omitted', () => {
    const io = capturingIo();
    const code = run(['verify', VALID], io);
    expect(code).toBe(0);
  });

  it('resolvePublicKey reads an inline base64 raw key', () => {
    const fixture = JSON.parse(readFileSync(VALID, 'utf8'));
    const io = capturingIo();
    const key = resolvePublicKey(fixture.public_key_raw_base64, null, io);
    expect(key).toBeInstanceOf(Uint8Array);
  });

  it('resolvePublicKey returns undefined when no key anywhere', () => {
    const io = capturingIo();
    expect(resolvePublicKey(undefined, { envelope: {} }, io)).toBeUndefined();
  });
});

describe('cli — usage and error exits', () => {
  it('exits 2 and prints usage when the file is missing', () => {
    const io = capturingIo();
    const code = run(['verify'], io);
    expect(code).toBe(2);
    expect(io.stderr.join('\n')).toMatch(/missing input file/);
  });

  it('exits 2 when the file is not valid JSON', () => {
    const io: CliIo = { readFile: () => 'not json{', out: () => {}, err: () => {} };
    expect(runVerify(['bad.json'], io)).toBe(2);
  });

  it('exits 2 when the file is unreadable', () => {
    const io: CliIo = {
      readFile: () => {
        throw new Error('ENOENT');
      },
      out: () => {},
      err: () => {},
    };
    expect(runVerify(['missing.json'], io)).toBe(2);
  });

  it('exits 2 with no key resolvable', () => {
    const io: CliIo = {
      readFile: () => JSON.stringify({ envelope: { payload: 'x', payloadType: 'y', signatures: [{ sig: 'z' }] } }),
      out: () => {},
      err: () => {},
    };
    expect(runVerify(['r.json'], io)).toBe(2);
  });

  it('--help exits 0 and prints usage; unknown command exits 2', () => {
    const io = capturingIo();
    expect(run(['--help'], io)).toBe(0);
    expect(io.stdout.join('\n')).toContain('awp verify');
    const io2 = capturingIo();
    expect(run(['bogus'], io2)).toBe(2);
  });

  it('no command at all prints usage and exits 2', () => {
    const io = capturingIo();
    expect(run([], io)).toBe(2);
  });
});

describe('cli verify — FULL receipt (AW-6): the Phase-2 walkthrough', () => {
  it('prints PASS for the full receipt, listing the checkpoint + inclusion layers, exit 0', () => {
    const io = capturingIo();
    const code = run(['verify', FULL], io);
    expect(code).toBe(0);
    const text = io.stdout.join('\n');
    expect(text).toMatch(/RESULT: PASS/);
    expect(text).toMatch(/\[PASS\] checkpoint/);
    expect(text).toMatch(/\[PASS\] inclusion/);
    expect(text).toMatch(/RFC 9162 inclusion proof verified/);
    // The honest time-bounding line, with the anchor weight.
    expect(text).toMatch(/existed no later than the checkpoint/);
    expect(text).toMatch(/trust-minimized/);
  });

  it('prints PASS for the committed samples/receipt.json (the auditor guide file)', () => {
    const io = capturingIo();
    const code = run(['verify', SAMPLE], io);
    expect(code).toBe(0);
    expect(io.stdout.join('\n')).toMatch(/RESULT: PASS/);
  });

  it('FAILS the byte-flipped full receipt, names "inclusion", exits non-zero', () => {
    const io = capturingIo();
    const code = run(['verify', FULL_TAMPERED], io);
    expect(code).not.toBe(0);
    const text = io.stdout.join('\n');
    expect(text).toMatch(/RESULT: FAIL/);
    expect(text).toMatch(/\[FAIL\] inclusion/);
    expect(text).toMatch(/failed checks: .*inclusion/);
    // The other layers stay PASS — the failure is isolated to the tampered layer.
    expect(text).toMatch(/\[PASS\] signature/);
    expect(text).toMatch(/\[PASS\] checkpoint/);
  });

  it('--json over the full receipt exposes the checkpoint + inclusion checks', () => {
    const io = capturingIo();
    const code = run(['verify', FULL, '--json'], io);
    expect(code).toBe(0);
    const parsed = JSON.parse(io.stdout.join('\n'));
    const names = parsed.checks.map((c: { name: string }) => c.name);
    expect(names).toContain('checkpoint');
    expect(names).toContain('inclusion');
  });
});

describe('parseArgs + resolveTrustAnchor — RFC 3161 flags', () => {
  it('parses --tsa-pubkey and --tsa-qualified', () => {
    const p = parseArgs(['r.json', '--tsa-pubkey', 'tsa.pem', '--tsa-qualified']);
    expect(p.tsaPubkey).toBe('tsa.pem');
    expect(p.tsaQualified).toBe(true);
  });

  it('resolveTrustAnchor returns undefined with no --tsa-pubkey', () => {
    const io: CliIo = { readFile: () => '', out: () => {}, err: () => {} };
    expect(resolveTrustAnchor(undefined, false, io)).toBeUndefined();
  });

  it('resolveTrustAnchor builds a PEM anchor and carries the qualified flag', () => {
    const pem = '-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----';
    const io: CliIo = {
      readFile: () => {
        throw new Error('not a file');
      },
      out: () => {},
      err: () => {},
    };
    const anchor = resolveTrustAnchor(pem, true, io);
    expect(anchor?.qualified).toBe(true);
    expect(typeof anchor?.publicKey).toBe('string');
  });
});

describe('formatHuman + USAGE', () => {
  it('formatHuman lists PASS/FAIL lines and a RESULT line', () => {
    const lines = formatHuman({
      ok: false,
      checks: [{ name: 'signature', ok: false, reason: 'bad' }],
      boundary: 'B',
    });
    expect(lines.some((l) => l.includes('[FAIL] signature'))).toBe(true);
    expect(lines.some((l) => l.includes('RESULT: FAIL'))).toBe(true);
  });

  it('USAGE documents the command, options, and exit codes', () => {
    expect(USAGE).toMatch(/awp verify/);
    expect(USAGE).toMatch(/--pubkey/);
    expect(USAGE).toMatch(/EXIT CODES/);
  });
});
