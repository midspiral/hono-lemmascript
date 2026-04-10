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

## Candidates

### `ipaddr.ts` utilities (`src/utils/ipaddr.ts`)

Pure functions doing binary arithmetic on IP addresses. Foundation of the CVE fix.

- `isIPv4MappedIPv6(addr: bigint): boolean` — verify it checks exactly the `::ffff:0:0/96` prefix
- `convertIPv4MappedIPv6ToIPv4(addr: bigint): bigint` — verify result is in 32-bit range, and round-trips with the reverse conversion
- `convertIPv4ToBinary` / `convertIPv6ToBinary` — verify output bit-width invariants

### CIDR mask computation

The expression `((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)` computes a bitmask with exactly `prefix` leading 1-bits. Could extract as a pure function and verify:
- Mask has exactly `prefix` set bits
- Mask bits are contiguous and left-aligned
- `addr & mask` preserves only the network portion

### IPv4/IPv6 equivalence property

The security invariant that would have caught the CVE: "an IPv4 address and its `::ffff:` mapped form produce the same match result." This is a property on the matcher itself, not a helper — harder to verify, may require extracting the matching logic into a pure function.
