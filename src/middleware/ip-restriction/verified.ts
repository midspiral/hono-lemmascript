type AddressType = 'IPv4' | 'IPv6'

type NormalizedMappedCIDRMeta = {
  isIPv4: boolean
  prefix: number
}

export function normalizeMappedCIDRMeta(
  type: AddressType,
  prefix: number,
  isMappedIPv6: boolean
): NormalizedMappedCIDRMeta {
  //@ verify
  //@ ensures type === 'IPv4' ==> \result.isIPv4 === true
  //@ ensures type === 'IPv4' ==> \result.prefix === prefix
  //@ ensures type === 'IPv6' && !(isMappedIPv6 && prefix >= 96) ==> \result.isIPv4 === false
  //@ ensures type === 'IPv6' && !(isMappedIPv6 && prefix >= 96) ==> \result.prefix === prefix
  //@ ensures type === 'IPv6' && isMappedIPv6 && prefix >= 96 ==> \result.isIPv4 === true
  //@ ensures type === 'IPv6' && isMappedIPv6 && prefix >= 96 ==> \result.prefix === prefix - 96
  if (type === 'IPv4') {
    return {
      isIPv4: true,
      prefix: prefix,
    }
  }

  if (isMappedIPv6 && prefix >= 96) {
    return {
      isIPv4: true,
      prefix: prefix - 96,
    }
  }

  return {
    isIPv4: false,
    prefix: prefix,
  }
}

export function ipv4StaticRuleAliases(rule: string): string[] {
  //@ verify
  //@ ensures \result.length === 2
  //@ ensures \result[0] === rule
  //@ ensures \result[1] === '::ffff:' + rule
  return [rule, '::ffff:' + rule]
}
