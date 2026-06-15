/**
 * @module cli
 *
 * The executable entry for the `awp` CLI. It wires real stdio and the real
 * process exit around {@link run} (the testable dispatcher in `./awp`), so the
 * command logic stays free of `process.exit` and is unit-testable.
 *
 * The `bin/awp.js` shim imports this module's {@link main}.
 *
 * Dependencies: `./awp`. Used by: `bin/awp.js`.
 */

import { run, defaultIo } from './awp.js';

/**
 * Run the CLI against `process.argv` and exit with the returned code.
 * 0 = PASS, 1 = FAIL, 2 = usage/IO error.
 */
export function main(): void {
  const code = run(process.argv.slice(2), defaultIo);
  process.exit(code);
}

export { run, runVerify, USAGE } from './awp.js';
