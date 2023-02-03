package config

import (
	"container/list"
	"log"
	"strings"
)

var ZjuForceProxyRules *list.List

func AppendSingleZjuForceProxyRule(keyword string, debug bool) {
	if ZjuForceProxyRules == nil {
		ZjuForceProxyRules = list.New()
	}

	if debug {
		log.Printf("AppendSingleZjuForceProxyRule: %s", keyword)
	}

	ZjuForceProxyRules.PushBack(keyword)
}

func IsInZjuForceProxyRule(domain string) bool {
	for e := ZjuForceProxyRules.Front(); e != nil; e = e.Next() {
		if strings.Contains(domain, e.Value.(string)) {
			return true
		}
	}

	return false
}

func IsZjuForceProxyRuleAvailable() bool {
	return ZjuForceProxyRules != nil
}

func GetZjuForceProxyRuleLen() int {
	if IsZjuForceProxyRuleAvailable() {
		return ZjuForceProxyRules.Len()
	} else {
		return 0
	}
}
