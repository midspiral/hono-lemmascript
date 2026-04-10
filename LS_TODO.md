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

4. **Template literals not supported.**
   `` `::ffff:${rule}` `` throws `Unsupported expression` at extract time. Must use `'::ffff:' + rule` instead.
   *Fix:* Desugar template literals to string concatenation during extraction.

5. **Property shorthand in object literals drops the field.**
   `{ isIPv4: true, prefix }` (where `prefix` is shorthand for `prefix: prefix`) generates `NormalizedMappedCIDRMeta(true)` in Dafny — missing the second argument. Must use `{ isIPv4: true, prefix: prefix }` explicitly.
   *Fix:* Expand property shorthand during extraction.

## Workarounds applied

- Extracted verified functions to `src/middleware/ip-restriction/verified.ts` to isolate them from unverifiable types.
- Inlined `type AddressType = 'IPv4' | 'IPv6'` instead of importing.
- Converted arrow functions to `function` declarations.
- Replaced template literal with string concatenation.
- Replaced property shorthand `prefix` with explicit `prefix: prefix`.
