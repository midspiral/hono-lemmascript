# LemmaScript Verification Candidates

Verification targets for hono's IP restriction middleware and supporting utilities, using [LemmaScript](https://github.com/midspiral/LemmaScript) with the Dafny backend.

## Done

### `normalizeMappedCIDRMeta` (`src/middleware/ip-restriction/verified.ts`)

Normalizes CIDR metadata for IPv4-mapped IPv6 addresses. Extracted from `buildMatcher` in `index.ts`.

Verified properties:
- Branch-by-branch correctness (IPv4 passthrough, mapped IPv6 conversion, plain IPv6 passthrough)
- **Prefix bounds preservation**: output prefix is in `[0,32]` when `isIPv4`, `[0,128]` otherwise, given valid input bounds. This guarantees the downstream mask computation `1n << BigInt(prefix)` can't overflow.

### `ipv4StaticRuleAliases` (`src/middleware/ip-restriction/verified.ts`)

Generates both forms of an IPv4 static rule (original + `::ffff:` mapped).

Verified properties:
- Returns exactly 2 elements
- First element is the original rule, second is the `::ffff:` mapped form

### `isIPv4MappedIPv6` (`src/utils/ipaddr.verified.ts`)

Checks if a binary IPv6 address is IPv4-mapped (`::ffff:x.x.x.x`). Uses `bigint` with `>>`.

Verified properties:
- Equivalence: result matches `ipv6binary / 2^32 === 0xffff`

### `convertIPv4MappedIPv6ToIPv4` (`src/utils/ipaddr.verified.ts`)

Extracts the IPv4 portion (lower 32 bits) from an IPv4-mapped IPv6 address. Uses `bigint` with `&`.

Verified properties:
- Equivalence: result matches `ipv6binary % 2^32`
- **32-bit bounds**: result is in `[0, 4294967295]`

### `resolveIPv4Addr` (`src/utils/ipaddr.verified.ts`)

Resolves a remote address to its IPv4 form. Extracted from `buildMatcher` and wired in.

Verified properties:
- Branch correctness (IPv4 passthrough, mapped extraction)
- **32-bit bounds** on result

### Equivalence properties (`src/utils/ipaddr.verified.ts`)

- **`mappedIsDetected`**: embedded IPv4 is detected as mapped
- **`mappedRoundTrip`**: embed-then-extract is the identity
- **`cveMappedEquivalence`**: `resolveIPv4Addr` gives the same result for direct IPv4 and its `::ffff:` mapped form

### `addIPv4StaticRule` (`src/middleware/ip-restriction/verified.ts`)

Adds both alias forms to a static rule set. Proves both are members.

Verified properties:
- `rule in result` and `'::ffff:' + rule in result`

Together, the static and CIDR paths are covered:
- **Static rules:** both forms are in the set (`addIPv4StaticRule`)
- **CIDR rules:** `resolveIPv4Addr` returns the same value for both forms (`cveMappedEquivalence`)

The remaining unverified part is the loop and control flow in `buildMatcher`.

## Candidates

### CIDR mask computation

The expression `((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)` computes a bitmask with exactly `prefix` leading 1-bits. Could extract as a pure function and verify:
- Mask has exactly `prefix` set bits
- Mask bits are contiguous and left-aligned
- `addr & mask` preserves only the network portion
