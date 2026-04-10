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
 * gives back the original. This is the core property the CVE fix relies on.
 */
export function mappedRoundTrip(ipv4Addr: bigint): bigint {
  //@ verify
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === ipv4Addr
  return convertIPv4MappedIPv6ToIPv4(MAPPED_PREFIX + ipv4Addr)
}
