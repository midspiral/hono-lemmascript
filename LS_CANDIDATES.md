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

### `mappedIsDetected` (`src/utils/ipaddr.verified.ts`)

Equivalence property: any IPv4 address embedded as `::ffff:x.x.x.x` is correctly detected as IPv4-mapped.

Verified properties:
- `isIPv4MappedIPv6(0xffff00000000 + ipv4Addr) === true` for all 32-bit `ipv4Addr`

### `mappedRoundTrip` (`src/utils/ipaddr.verified.ts`)

**The CVE-relevant equivalence property.** Proves that embedding an IPv4 address as IPv4-mapped IPv6 and extracting gives back the original — the invariant the CVE attacker violated.

Verified properties:
- `convertIPv4MappedIPv6ToIPv4(0xffff00000000 + ipv4Addr) === ipv4Addr` for all 32-bit `ipv4Addr`

## Candidates

### CIDR mask computation

The expression `((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)` computes a bitmask with exactly `prefix` leading 1-bits. Could extract as a pure function and verify:
- Mask has exactly `prefix` set bits
- Mask bits are contiguous and left-aligned
- `addr & mask` preserves only the network portion
