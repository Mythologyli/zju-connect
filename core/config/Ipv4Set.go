package config

import (
	"inet.af/netaddr"
	"strings"
)

var Ipv4Set *netaddr.IPSet

func GenerateIpv4Set() error {
	ipv4SetBuilder := netaddr.IPSetBuilder{}

	dnsIps := GetDnsIps()
	if dnsIps != nil {
		for _, ip := range dnsIps {
			ipv4SetBuilder.Add(netaddr.MustParseIP(ip))
		}
	}

	ipv4RangeRules := GetIpv4Rules()
	if ipv4RangeRules != nil {
		for _, rule := range *ipv4RangeRules {
			if rule.CIDR {
				ipv4SetBuilder.AddPrefix(netaddr.MustParseIPPrefix(rule.Rule))
			} else {
				ip1 := netaddr.MustParseIP(strings.Split(rule.Rule, "~")[0])
				ip2 := netaddr.MustParseIP(strings.Split(rule.Rule, "~")[1])
				ipv4SetBuilder.AddRange(netaddr.IPRangeFrom(ip1, ip2))
			}
		}
	}

	var err error
	Ipv4Set, err = ipv4SetBuilder.IPSet()
	if err != nil {
		return err
	}

	return nil
}

func IsIpv4SetAvailable() bool {
	return Ipv4Set != nil
}

func GetIpv4Set() *netaddr.IPSet {
	return Ipv4Set
}
