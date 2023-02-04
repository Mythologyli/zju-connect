package core

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

// only store domain -> ip, don't store ip -> ip
var dnsCaches *DnsCache
var once sync.Once

type DnsCache struct {
	cache *cache.Cache
}

func GetDnsCache(host string) (net.IP, bool) {
	once.Do(func() {
		dnsCaches = &DnsCache{
			cache: cache.New(time.Duration(DnsTTL)*time.Second, time.Duration(DnsTTL)*2*time.Second),
		}
	})
	if item, found := dnsCaches.cache.Get(host); found {
		if DebugDump {
			log.Printf("GetDnsCache: %s -> %s", host, item.(net.IP).String())
		}
		return item.(net.IP), found
	} else {
		if DebugDump {
			log.Printf("GetDnsCache: %s -> not found", host)
		}
		return nil, found
	}
}

func SetDnsCache(host string, ip net.IP) {
	once.Do(func() {
		dnsCaches = &DnsCache{
			cache: cache.New(time.Duration(DnsTTL)*time.Second, time.Duration(DnsTTL)*2*time.Second),
		}
	})
	if DebugDump {
		log.Printf("SetDnsCache: %s -> %s", host, ip.String())
	}
	dnsCaches.cache.Set(host, ip, cache.DefaultExpiration)
}
