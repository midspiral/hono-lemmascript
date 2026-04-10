# LemmaScript TODO

Issues encountered while adding LemmaScript verification to hono's ip-restriction middleware.

## LemmaScript issues

1. **Unneeded types are extracted, causing Dafny errors.**
   When `//@ verify` selective mode is active, `lsc` still extracts all type/interface declarations in the file — even those not reachable from any verified function. In our case, `IPRestrictionRules` (which references the untranslatable union type `IPRestrictionRule = string | function`) was emitted, causing a Dafny resolution error.
   *Fix:* `lsc` should only emit types transitively referenced by `//@ verify` functions.

2. **Cross-file string literal union import silently drops the function.**
   `AddressType = 'IPv4' | 'IPv6' | undefined` is imported from `../../helper/conninfo` (re-exported from `conninfo/types.ts`). The spec says cross-file types are resolved via ts-morph and string literal unions are supported, but `lsc` silently skips the function entirely — no error, no output. Likely a resolution failure through re-export barrels.
   *Fix:* `lsc` should either resolve re-exported types or emit a diagnostic when a parameter type can't be resolved.

3. **Arrow functions with `//@ verify` are silently skipped.**
   `const f = (...) => { //@ verify ... }` produces no Dafny output and no error. Only `function` declarations are recognized for verification. The spec doesn't document this limitation.
   *Fix:* Either support `//@ verify` on arrow functions assigned to `const`, or emit a warning when `//@ verify` is found inside an arrow function.

4. ~~**Template literals not supported.**~~ **FIXED** — desugared to string concatenation during extraction.

5. ~~**Property shorthand in object literals drops the field.**~~ **FIXED** — `{ prefix }` now expands to `{ prefix: prefix }` during extraction.

6. ~~**`bigint` type and literals not supported.**~~ **FIXED** — `bigint` maps to `int`, literals strip the `n` suffix.

7. ~~**Bitwise operators not supported.**~~ **FIXED (Dafny only)** — `>>`, `<<` translate to division/multiplication by powers of 2. `&` translates to `%` when mask+1 is a power of 2.

8. ~~**Module-level `const` not extracted.**~~ **FIXED (Dafny only)** — `const` declarations are extracted and emitted as Dafny `const`. Literal types (e.g., TS inferring `281470681743360` instead of `number`) are widened to their base type.

9. ~~**Mutable collection parameters not shadowed.**~~ **FIXED** — `findReassignedNames` now detects mutating collection calls (`.add()`, `.set()`, `.delete()`, `.push()`) on parameters and shadows them as mutable locals.

## Workarounds applied

- Extracted verified functions to `src/middleware/ip-restriction/verified.ts` to isolate them from unverifiable types.
- Inlined `type AddressType = 'IPv4' | 'IPv6'` instead of importing.
- Converted arrow functions to `function` declarations.
- ~~Replaced template literal with string concatenation.~~ No longer needed.
- ~~Replaced property shorthand `prefix` with explicit `prefix: prefix`.~~ No longer needed.
