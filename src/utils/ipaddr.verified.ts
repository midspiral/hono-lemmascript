export function isIPv4MappedIPv6(ipv6binary: bigint): boolean {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === (ipv6binary / 4294967296 === 65535)
  return ipv6binary >> 32n === 0xffffn
}

export function convertIPv4MappedIPv6ToIPv4(ipv6binary: bigint): bigint {
  //@ verify
  //@ requires ipv6binary >= 0
  //@ ensures \result === ipv6binary % 4294967296
  //@ ensures \result >= 0
  //@ ensures \result <= 4294967295
  return ipv6binary & 0xffffffffn
}
