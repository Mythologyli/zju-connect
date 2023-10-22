package core

import (
	"github.com/mythologyli/zju-connect/core/config"
	"golang.org/x/net/context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"log"
	"net"
	"sync"
	"time"
)

type DnsResolve struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	timer             *time.Timer
	useTCP            bool
	lock              sync.RWMutex
}

func (resolve *DnsResolve) ResolveWithSecondaryDns(ctx context.Context, host string) (context.Context, net.IP, error) {
	if targets, err := resolve.secondaryResolver.LookupIP(ctx, "ip4", host); err != nil {
		log.Printf("Resolve IPv4 addr failed using secondary DNS: " + host + ". Try IPv6 addr.")

		if targets, err = resolve.secondaryResolver.LookupIP(ctx, "ip6", host); err != nil {
			log.Printf("Resolve IPv6 addr failed using secondary DNS: " + host + ". Reject connection.")
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

func (resolve *DnsResolve) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	var useProxy = false
	if config.IsZjuForceProxyRuleAvailable() {
		if isInZjuForceProxyRule := config.IsInZjuForceProxyRule(host); isInZjuForceProxyRule {
			useProxy = true
		}
	}
	if !useProxy && config.IsDomainRuleAvailable() {
		if _, found := config.GetSingleDomainRule(host); found {
			useProxy = true
		}
	}

	ctx = context.WithValue(ctx, "USE_PROXY", useProxy)

	if cachedIP, found := GetDnsCache(host); found {
		log.Printf("%s -> %s", host, cachedIP.String())
		return ctx, cachedIP, nil
	}

	if config.IsDnsRuleAvailable() {
		if ip, hasDnsRule := config.GetSingleDnsRule(host); hasDnsRule {
			ctx = context.WithValue(ctx, "USE_PROXY", true)
			log.Printf("%s -> %s", host, ip)
			return ctx, net.ParseIP(ip), nil
		}
	}

	if UseZjuDns {
		resolve.lock.RLock()
		useTCP := resolve.useTCP
		resolve.lock.RUnlock()

		if !useTCP {
			targets, err := resolve.remoteUDPResolver.LookupIP(context.Background(), "ip4", host)
			if err != nil {
				if targets, err = resolve.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
					// all zju dns failed, so we keep do nothing but use secondary dns
					// host ipv4 and host ipv6 don't set cache
					log.Printf("Resolve IPv4 addr failed using ZJU UDP/TCP DNS: " + host + ", using secondary DNS instead.")
					return resolve.ResolveWithSecondaryDns(ctx, host)
				} else {
					resolve.lock.Lock()
					resolve.useTCP = true
					if resolve.timer == nil {
						resolve.timer = time.AfterFunc(10*time.Minute, func() {
							resolve.lock.Lock()
							resolve.useTCP = false
							resolve.timer = nil
							resolve.lock.Unlock()
						})
					}
					resolve.lock.Unlock()
				}
			}
			// set dns cache if tcp or udp dns success
			//TODO: whether we need all dns records? or only 10.0.0.0/8 ?
			SetDnsCache(host, targets[0])
			log.Printf("%s -> %s", host, targets[0].String())
			return ctx, targets[0], nil
		} else {
			// only try tcp and secondary dns
			if targets, err := resolve.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
				log.Printf("Resolve IPv4 addr failed using ZJU TCP DNS: " + host + ", using secondary DNS instead.")
				return resolve.ResolveWithSecondaryDns(ctx, host)
			} else {
				SetDnsCache(host, targets[0])
				log.Printf("%s -> %s", host, targets[0].String())
				return ctx, targets[0], nil
			}
		}
	} else {
		// because of OS cache, don't need extra dns memory cache
		return resolve.ResolveWithSecondaryDns(ctx, host)
	}
}

func SetupDnsResolve(zjuDnsServer string, client *EasyConnectClient) *DnsResolve {
	var dns DnsResolve
	if TunMode {
		dns = DnsResolve{
			remoteUDPResolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					addrDns := net.UDPAddr{
						IP:   net.ParseIP(zjuDnsServer),
						Port: 53,
					}

					bind := net.UDPAddr{
						IP:   net.IP(client.clientIp),
						Port: 0,
					}

					return net.DialUDP(network, &bind, &addrDns)
				},
			},
			remoteTCPResolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					addrDns := net.TCPAddr{
						IP:   net.ParseIP(zjuDnsServer),
						Port: 53,
					}

					bind := net.TCPAddr{
						IP:   net.IP(client.clientIp),
						Port: 0,
					}

					return net.DialTCP(network, &bind, &addrDns)
				},
			},
			useTCP: false,
			timer:  nil,
		}
	} else {
		dns = DnsResolve{
			remoteUDPResolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					addrDns := tcpip.FullAddress{
						NIC:  defaultNIC,
						Port: uint16(53),
						Addr: tcpip.AddrFromSlice(net.ParseIP(ZjuDnsServer).To4()),
					}

					bind := tcpip.FullAddress{
						NIC:  defaultNIC,
						Addr: tcpip.AddrFromSlice(client.clientIp),
					}

					return gonet.DialUDP(client.gvisorStack, &bind, &addrDns, header.IPv4ProtocolNumber)
				},
			},
			remoteTCPResolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					addrDns := tcpip.FullAddress{
						NIC:  defaultNIC,
						Port: uint16(53),
						Addr: tcpip.AddrFromSlice(net.ParseIP(ZjuDnsServer).To4()),
					}
					return gonet.DialTCP(client.gvisorStack, addrDns, header.IPv4ProtocolNumber)
				},
			},
			useTCP: false,
			timer:  nil,
		}
	}

	if SecondaryDnsServer != "" {
		dns.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				addrDns := net.UDPAddr{
					IP:   net.ParseIP(SecondaryDnsServer),
					Port: 53,
				}

				return net.DialUDP(network, nil, &addrDns)
			},
		}
	} else {
		dns.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}

	return &dns
}
