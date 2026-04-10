export function isIPv4MappedIPv6(ipv6binary: bigint): boolean {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === (ipv6binary / 0x100000000n === 0xffffn)
  return ipv6binary >> 32n === 0xffffn
}

export function convertIPv4MappedIPv6ToIPv4(ipv6binary: bigint): bigint {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === ipv6binary % 0x100000000n
  //@ ensures \result >= 0
  //@ ensures \result <= 0xffffffffn
  return ipv6binary & 0xffffffffn
}

// --- Matcher building block ---

/**
 * Resolve a remote address to its IPv4 form.
 * Direct IPv4 passes through; mapped IPv6 extracts the IPv4 portion.
 * Extracted from buildMatcher (lines 121-126 of index.ts).
 */
export function resolveIPv4Addr(remoteAddr: bigint, isIPv4: boolean): bigint {
  //@ verify
  //@ requires remoteAddr >= 0
  //@ requires isIPv4 ==> remoteAddr <= 0xffffffffn
  //@ requires !isIPv4 ==> isIPv4MappedIPv6(remoteAddr)
  //@ ensures isIPv4 ==> \result === remoteAddr
  //@ ensures !isIPv4 ==> \result === convertIPv4MappedIPv6ToIPv4(remoteAddr)
  //@ ensures \result >= 0
  //@ ensures \result <= 0xffffffffn
  if (isIPv4) return remoteAddr
  return convertIPv4MappedIPv6ToIPv4(remoteAddr)
}

// --- Equivalence properties ---

const MAPPED_PREFIX = 0xffff00000000n

/**
 * Any IPv4-mapped IPv6 address is detected as mapped.
 */
export function mappedIsDetected(ipv4Addr: bigint): boolean {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === true
  return isIPv4MappedIPv6(MAPPED_PREFIX + ipv4Addr)
}

/**
 * Round-trip: embedding an IPv4 address as ::ffff:x.x.x.x and extracting
 * gives back the original.
 */
export function mappedRoundTrip(ipv4Addr: bigint): bigint {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === ipv4Addr
  return convertIPv4MappedIPv6ToIPv4(MAPPED_PREFIX + ipv4Addr)
}

/**
 * Resolving an IPv4 address directly gives the same result as
 * resolving its ::ffff: mapped form.
 */
export function cveMappedEquivalence(ipv4Addr: bigint): boolean {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === true
  return resolveIPv4Addr(ipv4Addr, true) === resolveIPv4Addr(MAPPED_PREFIX + ipv4Addr, false)
}

// --- CIDR mask computation ---

/**
 * Compute a CIDR mask with `prefix` leading 1-bits in a `bits`-wide field.
 * Extracted from buildMatcher line 84:
 *   ((1n << BigInt(prefix)) - 1n) << BigInt((isIPv4 ? 32 : 128) - prefix)
 */
export function cidrMask(prefix: number, bits: number): bigint {
  //@ verify
  //@ requires prefix >= 0 && prefix <= bits
  //@ requires bits >= 0
  //@ ensures \result >= 0
  return ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix)
}

// --- CIDR matching ---

/**
 * Check if an address matches a CIDR rule (addr & mask === maskedAddr).
 * Extracted from the CIDR loop in buildMatcher.
 */
export function cidrMatch(addr: bigint, mask: bigint, maskedAddr: bigint): boolean {
  //@ verify
  //@ requires addr >= 0
  //@ requires mask >= 0
  //@ requires maskedAddr >= 0
  return (addr & mask) === maskedAddr
}

/**
 * CIDR match equivalence: matching a direct IPv4 address against a CIDR rule
 * gives the same result as matching its ::ffff: mapped form, after resolution.
 */
export function cveCidrEquivalence(ipv4Addr: bigint, mask: bigint, maskedAddr: bigint): boolean {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ requires mask >= 0
  //@ requires maskedAddr >= 0
  //@ ensures \result === cidrMatch(resolveIPv4Addr(MAPPED_PREFIX + ipv4Addr, false), mask, maskedAddr)
  return cidrMatch(resolveIPv4Addr(ipv4Addr, true), mask, maskedAddr)
}
