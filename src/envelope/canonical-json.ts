/**
 * @module envelope/canonical-json
 *
 * Deterministic JSON serialization for the in-toto Statement before it is fed to
 * DSSE PAE and signed. AWP spec §4 and the build-decision ADR fix the rule:
 * **recursive key-sort** (the same rule the kernel's `sortObjectKeys` uses for
 * its hash-chain and Merkle tree). AW-1 declared this expectation; AW-2 is where
 * signing actually happens, so the implementation lives here.
 *
 * The rule, stated so an auditor can re-implement it in 2036 with no hidden
 * behaviour:
 *
 *  1. Object keys are emitted in ascending Unicode code-point order (the order
 *     `Array.prototype.sort()` gives for strings), recursively, at every depth.
 *  2. Array element ORDER is preserved exactly (arrays are ordered data).
 *  3. The output is `JSON.stringify` of the key-sorted structure: no extra
 *     whitespace, standard JSON string escaping, numbers as JS emits them.
 *  4. `undefined` object properties are dropped (JSON has no `undefined`); this
 *     never happens for a validated WitnessRecord/Statement, which carries only
 *     defined values.
 *
 * There is deliberately NO Unicode normalization, NO number reformatting beyond
 * what `JSON.stringify` does, and NO custom escaping. DSSE PAE then frames the
 * resulting UTF-8 bytes with explicit byte lengths, so the signature does not
 * depend on any canonicalization subtlety beyond key order — the whole point of
 * adopting DSSE (spec §2: "no canonicalization games").
 *
 * Dependencies: none (Node stdlib only — and not even that; pure JS).
 * Used by: `./statement` (to produce the signed payload bytes).
 */

/** A JSON value the canonicalizer accepts. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * Return a structurally-identical copy of `value` with every object's keys
 * sorted into ascending Unicode code-point order, recursively. Array order is
 * preserved. Primitives are returned unchanged.
 *
 * This is the in-package re-implementation of the kernel's `sortObjectKeys`
 * rule (build-decision ADR, decision (c) "Canonical JSON"). It is exported so
 * tests and auditors can inspect the intermediate sorted structure separately
 * from its serialization.
 *
 * @param value - Any JSON-compatible value.
 * @returns A new value with all nested object keys sorted; same shape otherwise.
 *
 * @example
 * sortObjectKeys({ b: 1, a: { d: 2, c: 3 } });
 * // => { a: { c: 3, d: 2 }, b: 1 }
 */
export function sortObjectKeys(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((element) => sortObjectKeys(element));
  }
  if (value !== null && typeof value === 'object') {
    const sorted: { [key: string]: JsonValue } = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      // Drop `undefined` (not representable in JSON). Defined values only.
      if (child !== undefined) {
        sorted[key] = sortObjectKeys(child);
      }
    }
    return sorted;
  }
  return value;
}

/**
 * Serialize `value` to its canonical JSON string: key-sorted (recursively),
 * minimal whitespace, standard `JSON.stringify` escaping. This is the exact
 * string whose UTF-8 bytes become the DSSE payload.
 *
 * @param value - Any JSON-compatible value.
 * @returns The canonical JSON string.
 *
 * @example
 * canonicalJSONStringify({ b: 1, a: 2 }); // => '{"a":2,"b":1}'
 */
export function canonicalJSONStringify(value: JsonValue): string {
  return JSON.stringify(sortObjectKeys(value));
}

/**
 * Serialize `value` to canonical JSON and return its UTF-8 bytes — the payload
 * that DSSE PAE frames and Ed25519 signs.
 *
 * @param value - Any JSON-compatible value.
 * @returns A `Uint8Array` of the canonical JSON UTF-8 bytes.
 */
export function canonicalJSONBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalJSONStringify(value));
}
