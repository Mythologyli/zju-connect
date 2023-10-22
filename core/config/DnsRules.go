package config

import (
	"log"

	"github.com/cornelk/hashmap"
)

// domain[ip]
var dnsRules *hashmap.Map[string, string]
var dnsIps []string

func AppendSingleDnsRule(domain, ip string, debug bool) {
	if dnsRules == nil {
		dnsRules = hashmap.New[string, string]()
	}

	if debug {
		log.Printf("AppendSingleDnsRule: %s[%s]", domain, ip)
	}

	dnsRules.Set(domain, ip)
	dnsIps = append(dnsIps, ip)
}

func GetSingleDnsRule(domain string) (string, bool) {
	return dnsRules.Get(domain)
}

func IsDnsRuleAvailable() bool {
	return dnsRules != nil
}

func GetDnsRuleLen() int {
	if IsDnsRuleAvailable() {
		return dnsRules.Len()
	} else {
		return 0
	}
}

func GetDnsIps() []string {
	return dnsIps
}
