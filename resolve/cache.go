package resolve

import (
	"github.com/patrickmn/go-cache"
	"net"
)

func (r *Resolver) getDNSCache(host string) (net.IP, bool) {
	if item, found := r.dnsCache.Get(host); found {
		return item.(net.IP), found
	} else {
		return nil, found
	}
}

func (r *Resolver) setDNSCache(host string, ip net.IP) {
	r.dnsCache.Set(host, ip, cache.DefaultExpiration)
}

func (r *Resolver) SetPermanentDNS(host string, ip net.IP) {
	r.dnsCache.Set(host, ip, cache.NoExpiration)
}
