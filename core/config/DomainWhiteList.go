package config

import (
	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/cornelk/hashmap"
	"log"
)

// domain[[]int {min, max}]
var domainRules *hashmap.Map[string, []int]

func AppendSingleDomainRule(host string, ports []int, debug bool) {
	if domainRules == nil {
		domainRules = hashmap.New[string, []int]()
	}

	var domain = domainutil.Domain(host)
	if domain == "" {
		domain = host
	}

	if debug {
		log.Printf("AppendSingleDomainRule: %s[%v]", domain, ports)
	}

	domainRules.Set(domain, ports)
}

func GetSingleDomainRule(host string) ([]int, bool) {
	var domain = domainutil.Domain(host)
	if domain == "" {
		domain = host
	}

	return domainRules.Get(domain)
}

func IsDomainRuleAvailable() bool {
	return domainRules != nil
}

func GetDomainRuleLen() int {
	if IsDomainRuleAvailable() {
		return domainRules.Len()
	} else {
		return 0
	}
}
