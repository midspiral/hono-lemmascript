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
 * THE CVE PROPERTY: resolving an IPv4 address directly gives the same
 * result as resolving its ::ffff: mapped form. This is what the CVE
 * attacker exploited — the pre-fix code didn't have this equivalence.
 */
export function cveMappedEquivalence(ipv4Addr: bigint): boolean {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === true
  return resolveIPv4Addr(ipv4Addr, true) === resolveIPv4Addr(MAPPED_PREFIX + ipv4Addr, false)
}
