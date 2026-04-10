# Hono IP Restriction — Verified with LemmaScript

This is a fork of [honojs/hono](https://github.com/honojs/hono) with formal verification of the IP restriction middleware using [LemmaScript](https://github.com/midspiral/LemmaScript) (Dafny backend). All verified functions are wired into the production code (16 Dafny lemmas, 0 errors).

The IP restriction middleware recently had a fix for [CVE-2026-39409](https://github.com/honojs/hono/security/advisories/GHSA-3mpf-rcc7-5347) (incorrect IP matching for IPv4-mapped IPv6 addresses). An attacker could send a request from `::ffff:192.168.1.1` (an IPv4-mapped IPv6 address) and bypass an IPv4 restriction rule for `192.168.1.1`. The fix added detection and extraction of the IPv4 address from the mapped form. We formally verify the key property the fix depends on:

> **For all 2^32 IPv4 addresses, embedding as `::ffff:x.x.x.x` and extracting gives back the original.**

This is the `mappedRoundTrip` lemma — proved automatically by Dafny, not tested with examples. If this property breaks, the restriction bypass returns.

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

### `isIPv4MappedIPv6` (`src/utils/ipaddr.verified.ts`)

Checks if a binary IPv6 address is IPv4-mapped (`::ffff:x.x.x.x`). Uses `bigint` with `>>`.

- Equivalence: result matches `ipv6binary / 2^32 === 0xffff`

### `convertIPv4MappedIPv6ToIPv4` (`src/utils/ipaddr.verified.ts`)

Extracts the IPv4 portion (lower 32 bits) from an IPv4-mapped IPv6 address. Uses `bigint` with `&`.

- Equivalence: result matches `ipv6binary % 2^32`
- **32-bit bounds:** result in `[0, 2^32 - 1]`

### `mappedIsDetected` (`src/utils/ipaddr.verified.ts`)

Equivalence property: any IPv4 address embedded as `::ffff:x.x.x.x` is correctly detected as IPv4-mapped.

- `isIPv4MappedIPv6(0xffff00000000 + ipv4Addr) === true` for all 32-bit `ipv4Addr`

### `mappedRoundTrip` (`src/utils/ipaddr.verified.ts`)

**The CVE-relevant equivalence property.** Proves the round-trip that the CVE fix depends on: embedding an IPv4 address as IPv4-mapped IPv6 and extracting gives back the original.

- `convertIPv4MappedIPv6ToIPv4(0xffff00000000 + ipv4Addr) === ipv4Addr` for all 32-bit `ipv4Addr`

The pre-fix code didn't do this round-trip — it treated `::ffff:192.168.1.1` as a plain IPv6 address, so IPv4 restriction rules didn't match it. The fix added detection (`isIPv4MappedIPv6`) + extraction (`convertIPv4MappedIPv6ToIPv4`), and these two lemmas prove that detection and extraction are correct and compose correctly.

## File Structure

```
src/middleware/ip-restriction/
  index.ts                  ← Production middleware, imports from verified.ts
  verified.ts               ← Annotated TypeScript (normalizeMappedCIDRMeta, ipv4StaticRuleAliases)
  verified.dfy              ← Dafny verification target (4 verified, 0 errors)
  verified.dfy.gen          ← Generated Dafny (regeneratable)

src/utils/
  ipaddr.ts                 ← Production IP utilities, imports from ipaddr.verified.ts
  ipaddr.verified.ts        ← Annotated TypeScript (functions + equivalence properties)
  ipaddr.verified.dfy       ← Dafny verification target (12 verified, 0 errors)
  ipaddr.verified.dfy.gen   ← Generated Dafny (regeneratable)
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

See `LS_TODO.md` for remaining issues (arrow functions, template literals, property shorthand, cross-file imports).

## Roadmap

### CIDR mask computation

Extract the mask expression `((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)` and verify it produces a contiguous bitmask with exactly `prefix` leading 1-bits.
