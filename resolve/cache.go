package resolve

import (
	"net"

	"github.com/patrickmn/go-cache"
)

func (r *Resolver) getDNSCache(host string) (net.IP, bool) {
	host = normalizeHostname(host)
	if item, found := r.dnsCache.Get(host); found {
		return item.(net.IP), found
	} else {
		return nil, found
	}
}

func (r *Resolver) setDNSCache(host string, ip net.IP) {
	host = normalizeHostname(host)
	r.dnsCache.Set(host, ip, cache.DefaultExpiration)
}

func (r *Resolver) SetPermanentDNS(host string, ip net.IP) {
	host = normalizeHostname(host)
	r.dnsCache.Set(host, ip, cache.NoExpiration)
}
