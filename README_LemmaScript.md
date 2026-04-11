# Hono — Verified with LemmaScript

This is a fork of [honojs/hono](https://github.com/honojs/hono) with formal verification of security-critical middleware using [LemmaScript](https://github.com/midspiral/LemmaScript) (Dafny backend). 51 Dafny lemmas, 0 errors. Two CVEs verified. [View as diff](https://github.com/midspiral/hono-lemmascript/compare/main..lemmascript).

### [CVE-2026-39409](https://github.com/honojs/hono/security/advisories/GHSA-3mpf-rcc7-5347) — IP restriction bypass via IPv4-mapped IPv6

An attacker could send a request from `::ffff:192.168.1.1` and bypass an IPv4 restriction rule for `192.168.1.1`. We prove:

> **For any IPv4 CIDR rule, matching a direct IPv4 address through the matcher gives the same result as matching its `::ffff:` mapped form.**

Combined with `addIPv4StaticRule` (which proves both alias forms are in the static rule set), both data paths through the matcher are covered.

### [CVE-2026-39410](https://github.com/honojs/hono/security/advisories/GHSA-r5rp-j6wh-rvv4) — Cookie name bypass via non-breaking space

The old `.trim()` stripped Unicode whitespace including `\xA0` (non-breaking space), letting `\xA0sessionId=secret` bypass cookie name validation. The fix uses `trimCookieWhitespace` which only strips space and tab. We prove **in-place** in the production code:

> **Every character trimmed is space (0x20) or tab (0x09) — nothing else is removed.**

Annotated and verified directly in [`src/utils/cookie.ts`](https://github.com/midspiral/hono-lemmascript/blob/lemmascript/src/utils/cookie.ts#L79) — no separate verified file needed.

## Setup

**Prerequisites:** [Dafny](https://github.com/dafny-lang/dafny) >= 4.x, Node.js >= 18.

**Clone LemmaScript:**

```sh
git clone https://github.com/midspiral/LemmaScript.git ../LemmaScript
cd ../LemmaScript && npm install
```

**Run tests (verify the refactored code passes all existing tests):**

```sh
npm install
npx vitest --run --coverage.enabled=false src/middleware/ip-restriction/index.test.ts
```

All 6 existing tests pass with verified code wired in.

## What's Verified

### `normalizeMappedCIDRMeta` (`src/middleware/ip-restriction/verified.ts`)

Normalizes CIDR metadata for IPv4-mapped IPv6 addresses. Extracted from `buildMatcher`.

- **Preconditions:** prefix in `[0,32]` for IPv4, `[0,128]` for IPv6
- **Branch correctness:** IPv4 passthrough, mapped IPv6 → IPv4 conversion (prefix -= 96), plain IPv6 passthrough
- **Prefix bounds preservation:** output prefix in `[0,32]` when `isIPv4`, `[0,128]` otherwise — guarantees the downstream mask computation `1n << BigInt(prefix)` can't overflow

### `ipv4StaticRuleAliases` (`src/middleware/ip-restriction/verified.ts`)

Generates both forms of an IPv4 static rule for the deny/allow set.

- Returns exactly 2 elements: the original rule and its `::ffff:` mapped form

### `addIPv4StaticRule` (`src/middleware/ip-restriction/verified.ts`)

Adds both alias forms to a static rule set. Proves both are members after insertion.

- `rule in result` and `'::ffff:' + rule in result` — both the direct and mapped forms are in the set

### `isIPv4MappedIPv6` (`src/utils/ipaddr.verified.ts`)

Checks if a binary IPv6 address is IPv4-mapped (`::ffff:x.x.x.x`). Uses `bigint` with `>>`.

- Equivalence: result matches `ipv6binary / 2^32 === 0xffff`

### `convertIPv4MappedIPv6ToIPv4` (`src/utils/ipaddr.verified.ts`)

Extracts the IPv4 portion (lower 32 bits) from an IPv4-mapped IPv6 address. Uses `bigint` with `&`.

- Equivalence: result matches `ipv6binary % 2^32`
- **32-bit bounds:** result in `[0, 2^32 - 1]`

### `resolveIPv4Addr` (`src/utils/ipaddr.verified.ts`)

Resolves a remote address to its IPv4 form — direct IPv4 passes through, mapped IPv6 extracts the IPv4 portion. Extracted from `buildMatcher` and wired into the production matcher.

- **32-bit bounds:** result in `[0, 2^32 - 1]`

### Equivalence properties (`src/utils/ipaddr.verified.ts`)

Three properties that together prove the CVE fix's building blocks are correct:

- **`mappedIsDetected`**: `isIPv4MappedIPv6(0xffff00000000 + ipv4Addr) === true` — any embedded IPv4 address is detected as mapped
- **`mappedRoundTrip`**: `convertIPv4MappedIPv6ToIPv4(0xffff00000000 + ipv4Addr) === ipv4Addr` — embedding and extracting is the identity
- **`cveMappedEquivalence`**: `resolveIPv4Addr(ipv4Addr, true) === resolveIPv4Addr(0xffff00000000 + ipv4Addr, false)` — resolving an IPv4 address directly gives the same result as resolving its `::ffff:` mapped form

The pre-fix code didn't resolve mapped addresses at all — it treated `::ffff:192.168.1.1` as a plain IPv6 address, so IPv4 restriction rules didn't match it.

### Matcher CIDR check (`src/middleware/ip-restriction/matcher.verified.ts`)

`matchSingleCIDR` — the matcher's per-rule CIDR check, extracted from `buildMatcher` lines 127-142. Handles the `undefined` guard, bitwise mask comparison (`BitAnd`), and address family dispatch.

`matcherCIDREquivalence` — proves that for any IPv4 CIDR rule, `matchSingleCIDR` gives the same result for a direct IPv4 address and its `::ffff:` mapped form.

### CIDR mask computation (`src/utils/ipaddr.verified.ts`)

`cidrMask` — the `((1n << prefix) - 1n) << (bits - prefix)` expression. Proved non-negative (required a manual `Pow2Positive` helper lemma — the only non-automatic proof in the case study).

### Coverage summary

Both data paths through the matcher are verified for IPv4/mapped-IPv6 equivalence:
- **Static rules:** `addIPv4StaticRule` proves both `rule` and `::ffff:rule` are in the set
- **CIDR rules:** `matcherCIDREquivalence` proves `matchSingleCIDR` gives the same result for both forms

The remaining unverified part is the for loop and closure in `buildMatcher` itself — control flow, not data logic.

### `trimCookieWhitespace` (`src/utils/cookie.ts`) — [CVE-2026-39410](https://github.com/honojs/hono/security/advisories/GHSA-r5rp-j6wh-rvv4)

Verified **in-place** — annotations directly in the production source, no separate file.

- **Result is a contiguous slice** of the input
- **Only space (0x20) and tab (0x09) are stripped** — every character outside the result slice is one of these two. Non-breaking space (0xA0), the CVE attack vector, is provably never removed.

## File Structure

```
src/middleware/ip-restriction/
  index.ts                    ← Production middleware, imports from verified.ts
  verified.ts                 ← Rule building (normalizeMappedCIDRMeta, ipv4StaticRuleAliases, addIPv4StaticRule)
  verified.dfy                ← Dafny verification (5 verified, 0 errors)
  matcher.verified.ts         ← Matcher CIDR check (matchSingleCIDR, matcherCIDREquivalence)
  matcher.verified.dfy        ← Dafny verification (15 verified, 0 errors)

src/utils/
  ipaddr.ts                   ← Production IP utilities, imports from ipaddr.verified.ts
  ipaddr.verified.ts          ← IP functions + equivalence properties + cidrMask
  ipaddr.verified.dfy         ← Dafny verification (29 verified, 0 errors)
  cookie.ts                   ← Production cookie parsing, annotated in-place
  cookie.dfy                  ← Dafny verification (2 verified, 0 errors)
```

## How It Works

1. Add `//@ ` annotations to TypeScript:

   ```typescript
   export function normalizeMappedCIDRMeta(
     type: AddressType, prefix: number, isMappedIPv6: boolean
   ): NormalizedMappedCIDRMeta {
     //@ verify
     //@ requires type === 'IPv4' ==> prefix >= 0 && prefix <= 32
     //@ requires type === 'IPv6' ==> prefix >= 0 && prefix <= 128
     //@ ensures \result.isIPv4 ==> \result.prefix >= 0 && \result.prefix <= 32
     ...
   }
   ```

2. Generate and verify:

   ```sh
   npx tsx ../LemmaScript/tools/src/lsc.ts check --backend=dafny src/middleware/ip-restriction/verified.ts
   npx tsx ../LemmaScript/tools/src/lsc.ts check --backend=dafny src/utils/ipaddr.verified.ts
   ```

3. After changing annotations, regenerate:

   ```sh
   npx tsx ../LemmaScript/tools/src/lsc.ts regen --backend=dafny src/middleware/ip-restriction/verified.ts
   npx tsx ../LemmaScript/tools/src/lsc.ts regen --backend=dafny src/utils/ipaddr.verified.ts
   ```

The TypeScript is the source of truth. The `.dfy.gen` file is always regeneratable. The `.dfy` file is the verification target (may contain manual proof additions, though none were needed here — all proofs are automatic).

## LemmaScript Improvements

This case study drove several improvements to LemmaScript (Dafny backend):

- **`bigint` support:** `bigint` type maps to `int`, literals like `32n` strip the `n` suffix
- **Bitwise operators:** `>>` and `<<` translate to division/multiplication by powers of 2; `&` with power-of-2 masks translates to `%`
- **Module-level `const`:** extracted and emitted as Dafny `const`; literal types widened to base type

- **Hex literals in annotations:** `0xffffn` works in `//@ ensures` (spec parser supports hex and `n` suffix)
- **Template literals:** `` `::ffff:${rule}` `` desugared to string concatenation
- **Property shorthand:** `{ prefix }` expanded to `{ prefix: prefix }`
- **Mutable collection parameters:** `s.add(x)` on a parameter now correctly shadows it as mutable
- **`BitAnd` and `Pow2` helpers:** `x & y` with variable masks emits `BitAnd(x, y)` (recursive binary decomposition); `x << n` with variable shift emits `x * Pow2(n)`
- **`BigInt()` identity:** `BigInt(x)` emits `x` (both map to `int`)
- **Optional narrowing fixes:** ternary `Some`/`None` wrapping, `=== undefined` codegen, early-return narrowing, pure function narrowing, `T` to `Option<T>` parameter coercion
- **Arrow functions:** `const f = (...) => { //@ verify ... }` now extracted and verified
- **`charCodeAt`:** `s.charCodeAt(i)` emits `s[i] as int`
- **Multi-variable quantifiers:** nested `exists`/`forall` collapsed to `exists x, y ::` in Dafny
- **Brownfield const filtering:** only consts referenced by verified functions are extracted
- **Literal type widening:** `true`/`false` literal types map to `bool`

See `LS_TODO.md` for remaining issues (cross-file imports, unreachable type extraction).

## Roadmap

### Verify `buildMatcher`'s for loop

The CIDR loop iterates over rules and returns true on first match. Verifying the loop would close the gap between `matchSingleCIDR` (verified per-rule) and the full matcher. Blocked on LemmaScript's `return inside a loop` limitation.

### Wire `matchSingleCIDR` into production code

Currently a self-contained verification file. Could be wired into `buildMatcher` by extracting the loop body, similar to how `resolveIPv4Addr` was extracted and wired in.
