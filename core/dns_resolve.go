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
	timer             *time.Timer
	useTCP            bool
	lock              sync.RWMutex
}

func (resolve *DnsResolve) ResolveWithLocal(ctx context.Context, host string) (context.Context, net.IP, error) {
	if target, err := net.ResolveIPAddr("ip4", host); err != nil {
		log.Printf("Resolve IPv4 addr failed using local DNS: " + host + ". Try IPv6 addr.")

		if target, err = net.ResolveIPAddr("ip6", host); err != nil {
			log.Printf("Resolve IPv6 addr failed using local DNS: " + host + ". Reject connection.")
			return ctx, nil, err
		} else {
			log.Printf("%s -> %s", host, target.IP.String())
			return ctx, target.IP, nil
		}
	} else {
		log.Printf("%s -> %s", host, target.IP.String())
		return ctx, target.IP, nil
	}
}

func (resolve *DnsResolve) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
	if config.IsDnsRuleAvailable() {
		if ip, hasDnsRule := config.GetSingleDnsRule(host); hasDnsRule {
			ctx = context.WithValue(ctx, "USE_PROXY", true)
			log.Printf("%s -> %s", host, ip)
			return ctx, net.ParseIP(ip), nil
		}
	}
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

	if UseZjuDns {
		if cachedIP, found := GetDnsCache(host); found {
			log.Printf("%s -> %s", host, cachedIP.String())
			return ctx, cachedIP, nil
		} else {
			resolve.lock.RLock()
			useTCP := resolve.useTCP
			resolve.lock.RUnlock()

			if !useTCP {
				targets, err := resolve.remoteUDPResolver.LookupIP(context.Background(), "ip4", host)
				if err != nil {
					if targets, err = resolve.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
						// all zju dns failed, so we keep do nothing but use local dns
						// host ipv4 and host ipv6 don't set cache
						log.Printf("Resolve IPv4 addr failed using ZJU UDP/TCP DNS: " + host + ", using local DNS instead.")
						return resolve.ResolveWithLocal(ctx, host)
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
				// only try tcp and local dns
				if targets, err := resolve.remoteTCPResolver.LookupIP(context.Background(), "ip4", host); err != nil {
					log.Printf("Resolve IPv4 addr failed using ZJU TCP DNS: " + host + ", using local DNS instead.")
					return resolve.ResolveWithLocal(ctx, host)
				} else {
					SetDnsCache(host, targets[0])
					log.Printf("%s -> %s", host, targets[0].String())
					return ctx, targets[0], nil
				}
			}
		}

	} else {
		// because of OS cache, don't need extra dns memory cache
		return resolve.ResolveWithLocal(ctx, host)
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

	return &dns
}