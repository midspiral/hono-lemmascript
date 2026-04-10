# Hono IP Restriction — Verified with LemmaScript

This is a fork of [honojs/hono](https://github.com/honojs/hono) with formal verification of the IP restriction middleware using [LemmaScript](https://github.com/midspiral/LemmaScript) (Dafny backend).

The IP restriction middleware recently had a CVE fix for IPv4-mapped IPv6 address bypass. We verify the core functions introduced by that fix — proving they preserve prefix bounds, correctly generate address aliases, and faithfully implement IPv4-mapped IPv6 detection and extraction. All verified functions are wired into the production code.

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

## File Structure

```
src/middleware/ip-restriction/
  index.ts                  ← Production middleware, imports from verified.ts
  verified.ts               ← Annotated TypeScript (normalizeMappedCIDRMeta, ipv4StaticRuleAliases)
  verified.dfy              ← Dafny verification target (4 verified, 0 errors)
  verified.dfy.gen          ← Generated Dafny (regeneratable)

src/utils/
  ipaddr.ts                 ← Production IP utilities, imports from ipaddr.verified.ts
  ipaddr.verified.ts        ← Annotated TypeScript (isIPv4MappedIPv6, convertIPv4MappedIPv6ToIPv4)
  ipaddr.verified.dfy       ← Dafny verification target (6 verified, 0 errors)
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

This case study drove several improvements to LemmaScript:

- **`bigint` support:** `bigint` type maps to Dafny `int`, literals like `32n` strip the `n` suffix
- **Bitwise operators (Dafny):** `>>` and `<<` translate to division/multiplication by powers of 2; `&` with power-of-2 masks translates to `%`

See `LS_TODO.md` for remaining issues (arrow functions, template literals, property shorthand, cross-file imports).

## Roadmap

### CIDR mask computation

Extract the mask expression `((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)` and verify it produces a contiguous bitmask with exactly `prefix` leading 1-bits.

### IPv4/IPv6 equivalence property

The security invariant that would have caught the CVE: **an IPv4 address and its `::ffff:` mapped form produce the same match result.** This requires extracting more of `buildMatcher`'s logic into pure, verifiable functions. It is the end goal of this verification effort.
