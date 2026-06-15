#!/usr/bin/env node
/**
 * bin/awp — the `awp` executable shim.
 *
 * A 2-line launcher: import the compiled CLI entry and run it. The real logic
 * lives in `src/cli/awp.ts` (testable, no process control) and `src/cli/index.ts`
 * (wires stdio + exit). This file is intentionally trivial so the bin field is
 * stable and the command surface is the library, per the AW-3 CLI-First rule.
 *
 * Resolves the compiled module from `dist/`. Run `npm run build` first.
 */
import { main } from '../dist/cli/index.js';

main();
