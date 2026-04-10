// Self-contained matcher verification.

function isIPv4MappedIPv6(ipv6binary: bigint): boolean {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === (ipv6binary / 0x100000000n === 0xffffn)
  return ipv6binary >> 32n === 0xffffn
}

function convertIPv4MappedIPv6ToIPv4(ipv6binary: bigint): bigint {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === ipv6binary % 0x100000000n
  //@ ensures \result >= 0
  //@ ensures \result <= 0xffffffffn
  return ipv6binary & 0xffffffffn
}

function resolveIPv4Addr(remoteAddr: bigint, isIPv4: boolean): bigint {
  //@ verify
  //@ requires remoteAddr >= 0
  //@ requires isIPv4 ==> remoteAddr <= 0xffffffffn
  //@ requires !isIPv4 ==> isIPv4MappedIPv6(remoteAddr)
  //@ ensures \result >= 0
  //@ ensures \result <= 0xffffffffn
  if (isIPv4) return remoteAddr
  return convertIPv4MappedIPv6ToIPv4(remoteAddr)
}

interface CIDRRule {
  isIPv4: boolean
  maskedAddr: bigint
  mask: bigint
}

/**
 * Match a single IPv4 CIDR rule against a resolved IPv4 address.
 */
function matchIPv4CIDR(
  remoteIPv4Addr: bigint,
  mask: bigint,
  maskedAddr: bigint
): boolean {
  //@ verify
  //@ requires remoteIPv4Addr >= 0
  //@ requires mask >= 0
  //@ requires maskedAddr >= 0
  return (remoteIPv4Addr & mask) === maskedAddr
}

/**
 * The matcher's CIDR check for a single rule, as written in buildMatcher.
 */
function matchSingleCIDR(
  rule: CIDRRule,
  remoteAddr: bigint,
  remoteIPv4Addr: bigint | undefined,
  remoteIsIPv4: boolean
): boolean {
  //@ verify
  //@ requires remoteAddr >= 0
  //@ requires remoteIPv4Addr !== undefined ==> remoteIPv4Addr >= 0
  //@ requires rule.mask >= 0
  //@ requires rule.maskedAddr >= 0
  if (rule.isIPv4) {
    if (remoteIPv4Addr === undefined) {
      return false
    }
    return matchIPv4CIDR(remoteIPv4Addr, rule.mask, rule.maskedAddr)
  }
  if (remoteIsIPv4) {
    return false
  }
  return (remoteAddr & rule.mask) === rule.maskedAddr
}

const MAPPED_PREFIX = 0xffff00000000n

/**
 * For any IPv4 CIDR rule: matching a direct IPv4 address through the
 * matcher's CIDR check gives the same result as matching its ::ffff:
 * mapped form. This is the matcher-level CVE equivalence.
 */
function matcherCIDREquivalence(
  rule: CIDRRule,
  ipv4Addr: bigint
): boolean {
  //@ verify
  //@ requires rule.isIPv4
  //@ requires rule.mask >= 0
  //@ requires rule.maskedAddr >= 0
  //@ requires ipv4Addr >= 0 && ipv4Addr <= 0xffffffffn
  //@ ensures \result === matchSingleCIDR(rule, MAPPED_PREFIX + ipv4Addr, resolveIPv4Addr(MAPPED_PREFIX + ipv4Addr, false), false)
  return matchSingleCIDR(rule, ipv4Addr, resolveIPv4Addr(ipv4Addr, true), true)
}
