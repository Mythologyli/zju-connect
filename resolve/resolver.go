package resolve

import (
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/patrickmn/go-cache"
	"net"
	"strings"
	"sync"
	"time"
)

type Resolver struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	ttl               uint64
	domainResources   map[string]client.DomainResource
	dnsResource       map[string]net.IP
	useRemoteDNS      bool

	dnsCache *cache.Cache

	timer  *time.Timer
	useTCP bool
	// check to use tcp resolver or udp resolver
	tcpLock sync.RWMutex
	// check to handle concurrent same dns query
	// only the goroutine which get the lock can use remoteResolver
	// MUST handler lock/unlock carefully!
	concurResolveLock sync.Map
}

type contextKey string

var (
	ContextKeyResolveHost    = contextKey("RESOLVE_HOST")
	ContextKeyDomainResource = contextKey("DOMAIN_RESOURCE")
	ContextKeyDomain         = contextKey("DOMAIN")
)

// Resolve ip address. If the host could be visited via VPN, this function set a DOMAIN_RESOURCE value in context. If resolve success, this function set a RESOLVE_HOST value in context.
func (r *Resolver) Resolve(ctx context.Context, host string) (resCtx context.Context, resIP net.IP, resErr error) {
	defer func() {
		if resErr == nil {
			resCtx = context.WithValue(resCtx, ContextKeyResolveHost, host)
		}
	}()
	if r.domainResources != nil {
		for domain, resource := range r.domainResources {
			if strings.HasSuffix(host, domain) {
				ctx = context.WithValue(ctx, ContextKeyDomainResource, resource)
				ctx = context.WithValue(ctx, ContextKeyDomain, host)
				log.DebugPrintf("Domain resource found: %s", domain)
				break
			}
		}
	}

	if cachedIP, found := r.getDNSCache(host); found {
		log.Printf("%s -> %s", host, cachedIP.String())
		return ctx, cachedIP, nil
	}

	if r.dnsResource != nil {
		if ip, found := r.dnsResource[host]; found {
			log.Printf("%s -> %s", host, ip.String())
			return ctx, ip, nil
		}
	}

	if r.useRemoteDNS {
		r.tcpLock.RLock()
		useTCP := r.useTCP
		r.tcpLock.RUnlock()
		resolveLockItem, _ := r.concurResolveLock.LoadOrStore(host, new(sync.Mutex))
		resolveLock := resolveLockItem.(*sync.Mutex)
		if resolveLock.TryLock() {
			if !useTCP {
				ips, err := r.remoteUDPResolver.LookupIP(context.Background(), "ip4", host)
				if err != nil {
					if ips, err = r.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
						resolveLock.Unlock()
						// All remote DNS failed, so we keep do nothing but use secondary dns
						log.Printf("Resolve IPv4 addr failed using ZJU UDP/TCP DNS: " + host + ", using secondary DNS instead")
						return r.ResolveWithSecondaryDNS(ctx, host)
					} else {
						r.tcpLock.Lock()
						r.useTCP = true
						if r.timer == nil {
							r.timer = time.AfterFunc(10*time.Minute, func() {
								r.tcpLock.Lock()
								r.useTCP = false
								r.timer = nil
								r.tcpLock.Unlock()
							})
						}
						r.tcpLock.Unlock()
					}
				}
				// Set DNS cache if tcp or udp DNS success
				r.setDNSCache(host, ips[0])
				resolveLock.Unlock()
				log.Printf("%s -> %s", host, ips[0].String())
				return ctx, ips[0], nil
			} else {
				// Only try tcp and secondary DNS
				if ips, err := r.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
					resolveLock.Unlock()
					log.Printf("Resolve IPv4 addr failed using ZJU TCP DNS: " + host + ", using secondary DNS instead")
					return r.ResolveWithSecondaryDNS(ctx, host)
				} else {
					r.setDNSCache(host, ips[0])
					resolveLock.Unlock()
					log.Printf("%s -> %s", host, ips[0].String())
					return ctx, ips[0], nil
				}
			}
		} else {
			// waiting dns query for remoteResolve finish
			resolveLock.Lock()
			resolveLock.Unlock()
			// if host handled by remoteResolver, it must exist in DNSCache
			if cachedIP, found := r.getDNSCache(host); found {
				return ctx, cachedIP, nil
			}
			return r.ResolveWithSecondaryDNS(ctx, host)
		}
	} else {
		return r.ResolveWithSecondaryDNS(ctx, host)
	}
}

func (r *Resolver) RemoteUDPResolver() (*net.Resolver, error) {
	if r.remoteUDPResolver != nil {
		return r.remoteUDPResolver, nil
	} else {
		return nil, errors.New("remote UDP resolver is nil")
	}
}

func (r *Resolver) RemoteTCPResolver() (*net.Resolver, error) {
	if r.remoteTCPResolver != nil {
		return r.remoteTCPResolver, nil
	} else {
		return nil, errors.New("remote TCP resolver is nil")
	}
}

func (r *Resolver) ResolveWithSecondaryDNS(ctx context.Context, host string) (context.Context, net.IP, error) {
	if targets, err := r.secondaryResolver.LookupIP(ctx, "ip4", host); err != nil {
		log.Printf("Resolve IPv4 addr failed using secondary DNS: " + host + ". Try IPv6 addr")

		if targets, err = r.secondaryResolver.LookupIP(ctx, "ip6", host); err != nil {
			log.Printf("Resolve IPv6 addr failed using secondary DNS: " + host)
			return ctx, nil, err
		} else {
			log.Printf("%s -> %s", host, targets[0].String())
			return ctx, targets[0], nil
		}
	} else {
		log.Printf("%s -> %s", host, targets[0].String())
		return ctx, targets[0], nil
	}
}

func (r *Resolver) CleanCache(duration time.Duration) {
	for {
		time.Sleep(duration)
		// dnsCache already cleaned
		// r.dnsCache.DeleteExpired()
		r.concurResolveLock.Range(func(key, value any) bool {
			r.concurResolveLock.Delete(key)
			return true
		})
		log.Printf("Clean DNS Cache: OK")
	}
}

func NewResolver(stack stack.Stack, remoteDNSServer, secondaryDNSServer string, ttl uint64, domainResources map[string]client.DomainResource, dnsResource map[string]net.IP, useRemoteDNS bool) *Resolver {
	//domainSuffixTree := domainsuffixtrie.NewDomainSuffixTrie[bool]()
	//for domain := range domainResource {
	//	_ = domainSuffixTree.AddDomainSuffix(domain, true)
	//}

	resolver := &Resolver{
		remoteUDPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialUDP(context.Background(), &net.UDPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		remoteTCPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialTCP(context.Background(), &net.TCPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		ttl:             ttl,
		domainResources: domainResources,
		dnsResource:     dnsResource,
		dnsCache:        cache.New(time.Duration(ttl)*time.Second, time.Duration(ttl)*2*time.Second),
		useRemoteDNS:    useRemoteDNS,
	}

	if secondaryDNSServer != "" {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.DialUDP(network, nil, &net.UDPAddr{
					IP:   net.ParseIP(secondaryDNSServer),
					Port: 53,
				})
			},
		}
	} else {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}
	// sleep 10 times ttl
	go resolver.CleanCache(time.Duration(ttl) * time.Second * 10)
	return resolver
}
