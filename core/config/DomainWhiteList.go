package config

import (
	"log"

	"github.com/cornelk/hashmap"
)

// domain[[]int {min, max}]
var domainRules *hashmap.Map[string, []int]

func AppendSingleDomainRule(domain string, ports []int, debug bool) {
	if domainRules == nil {
		domainRules = hashmap.New[string, []int]()
	}

	if debug {
		log.Printf("AppendSingleDomainRule: %s[%v]", domain, ports)
	}

	domainRules.Set(domain, ports)
}

func GetSingleDomainRule(domain string) ([]int, bool) {
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
