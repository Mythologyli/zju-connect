package resolve

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/patrickmn/go-cache"
	"golang.org/x/sync/singleflight"
)

type Resolver struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	ttl               uint64
	domainIndex       *domainResourceIndex
	dnsResource       map[string]net.IP
	useRemoteDNS      bool

	dnsCache *cache.Cache

	IPPool *ippool.IPPool[client.DomainResource]

	timer  *time.Timer
	useTCP bool
	// check to use tcp resolver or udp resolver
	tcpLock           sync.RWMutex
	resolveGroup      singleflight.Group
	activeResolutions atomic.Int64

	closeOnce sync.Once
}

func (r *Resolver) coordinationEntryCount() int {
	return int(r.activeResolutions.Load())
}

type contextKey string

var (
	ContextKeyFakeIP         = contextKey("FAKE_IP")
	ContextKeyResolveHost    = contextKey("RESOLVE_HOST")
	ContextKeyDomainResource = contextKey("DOMAIN_RESOURCE")
)

// Resolve ip address. If the host could be visited via VPN, this function set a DOMAIN_RESOURCE value in context. If resolve success, this function set a RESOLVE_HOST value in context.
func (r *Resolver) Resolve(ctx context.Context, host string) (resCtx context.Context, resIP net.IP, resErr error) {
	host = normalizeHostname(host)
	defer func() {
		if resErr == nil {
			resCtx = context.WithValue(resCtx, ContextKeyResolveHost, host)
		}
	}()
	var domainResourceFound = false
	var domainResource client.DomainResource
	if domain, resource, found := matchDomainResource(r.domainIndex, host); found {
		domainResourceFound = true
		domainResource = resource
		ctx = context.WithValue(ctx, ContextKeyDomainResource, resource)
		log.DebugPrintf("Domain resource found: %s", domain)
	}

	if cachedIP, found := r.getDNSCache(host); found {
		log.Printf("%s -> %s", host, cachedIP.String())
		return ctx, cachedIP, nil
	}

	if r.dnsResource != nil {
		if ip, found := r.dnsResource[host]; found {
			log.Printf("%s -> %s", host, ip.String())
			if domainResourceFound {
				err := r.IPPool.SetIPDomain(ip, host, domainResource)
				if err != nil {
					log.DebugPrintf("Set IP err: %s", err)
				}
			}
			return ctx, ip, nil
		}

		if fakeIPValue := ctx.Value(ContextKeyFakeIP); fakeIPValue != nil {
			if domainResourceFound {
				ip := r.IPPool.GenerateIP(host, domainResource)
				log.Printf("%s -> %s (Fake IP)", host, ip.String())
				return ctx, ip, nil
			}
		}
	}

	if r.useRemoteDNS {
		resultCh := r.resolveGroup.DoChan(host, func() (any, error) {
			r.activeResolutions.Add(1)
			defer r.activeResolutions.Add(-1)
			return r.resolveRemote(ctx, host)
		})
		select {
		case <-ctx.Done():
			return ctx, nil, ctx.Err()
		case result := <-resultCh:
			if result.Err != nil {
				log.Printf("Resolve IPv4 addr failed using remote DNS: %s, using secondary DNS instead", host)
				return r.ResolveWithSecondaryDNS(ctx, host)
			}
			ip := result.Val.(net.IP)
			log.Printf("%s -> %s", host, ip.String())
			return ctx, ip, nil
		}
	} else {
		return r.ResolveWithSecondaryDNS(ctx, host)
	}
}

func matchDomainResource(index *domainResourceIndex, host string) (string, client.DomainResource, bool) {
	return index.Match(host)
}

func (r *Resolver) resolveRemote(ctx context.Context, host string) (net.IP, error) {
	r.tcpLock.RLock()
	useTCP := r.useTCP
	r.tcpLock.RUnlock()

	if useTCP {
		ips, err := r.remoteTCPResolver.LookupIP(ctx, "ip4", host)
		return r.cacheFirstIP(host, ips, err)
	}

	ips, udpErr := r.remoteUDPResolver.LookupIP(ctx, "ip4", host)
	if udpErr == nil {
		return r.cacheFirstIP(host, ips, nil)
	}
	ips, tcpErr := r.remoteTCPResolver.LookupIP(ctx, "ip4", host)
	if tcpErr != nil {
		return nil, errors.Join(udpErr, tcpErr)
	}

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
	return r.cacheFirstIP(host, ips, nil)
}

func (r *Resolver) cacheFirstIP(host string, ips []net.IP, err error) (net.IP, error) {
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS lookup returned no addresses")
	}
	r.setDNSCache(host, ips[0])
	return ips[0], nil
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
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
		log.Printf("Resolve IPv4 addr failed using secondary DNS: %s. Try IPv6 addr", host)

		if targets, err = r.secondaryResolver.LookupIP(ctx, "ip6", host); err != nil {
			log.Printf("Resolve IPv6 addr failed using secondary DNS: %s", host)
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

func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		r.tcpLock.Lock()
		if r.timer != nil {
			r.timer.Stop()
			r.timer = nil
		}
		r.tcpLock.Unlock()
	})
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
				return stack.DialUDP(ctx, &net.UDPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		remoteTCPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialTCP(ctx, &net.TCPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		ttl:          ttl,
		domainIndex:  newDomainResourceIndex(domainResources),
		dnsResource:  dnsResource,
		dnsCache:     cache.New(time.Duration(ttl)*time.Second, time.Duration(ttl)*2*time.Second),
		useRemoteDNS: useRemoteDNS,
	}

	if secondaryDNSServer != "" {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(secondaryDNSServer, "53"))
			},
		}
	} else {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}
	var err error
	resolver.IPPool, err = ippool.NewIPPool[client.DomainResource]("198.18.0.0/16")
	if err != nil {
		log.Fatalf("Create Fake IP Pool failed: %v", err)
	}

	return resolver
}
