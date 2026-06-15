/**
 * Vitest configuration for the Agent Witness Protocol (AWP) open package.
 *
 * Coverage is collected with the v8 provider and gated at 80% on the shipped
 * source — the AW-1 schema, the AW-2 envelope, the AW-3 verifier (+ CLI), the
 * AW-4 transparency log (RFC 9162 Merkle + C2SP checkpoint), the AW-5 external
 * anchors (OTS verify + submit/upgrade, and the RFC 3161 verify slot), and the
 * AW-6 producer ops (proof / checkpoint) — to satisfy the Quality Foundation floor.
 * Barrels (`index.ts`) are pure re-exports and are excluded; so is the CLI
 * process-wiring entry (`src/cli/index.ts`, just `process.exit` plumbing).
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      include: [
        'src/schema/**/*.ts',
        'src/envelope/**/*.ts',
        'src/verify/**/*.ts',
        'src/anchor/**/*.ts',
        'src/log/**/*.ts',
        'src/ops/**/*.ts',
        'src/cli/**/*.ts',
      ],
      exclude: [
        'src/schema/index.ts',
        'src/envelope/index.ts',
        'src/verify/index.ts',
        'src/anchor/index.ts',
        'src/log/index.ts',
        'src/ops/index.ts',
        'src/cli/index.ts',
        '**/*.d.ts',
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
});
