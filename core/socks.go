package core

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"ZJUConnect/core/config"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/socks5"
)

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("Addr: %s, useProxy: false", addr)

	return goDial(ctx, network, addr)
}

func ServeSocks5(ipStack *stack.Stack, selfIp []byte, bindAddr string) {
	var remoteResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return gonet.DialContextTCP(ctx, ipStack, tcpip.FullAddress{
				NIC:  defaultNIC,
				Port: uint16(53),
				Addr: tcpip.Address(net.ParseIP("10.10.0.21").To4()),
			}, header.IPv4ProtocolNumber)
		},
	}

	server := socks5.Server{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {

			log.Printf("Socks dial: %s", addr)

			parts := strings.Split(addr, ":")

			host := parts[0]
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("Invalid port: " + parts[1])
			}

			var hasDnsRule = false
			var isInZjuForceProxyRule = false
			var useProxy = false

			var target *net.IPAddr

			if ProxyAll {
				useProxy = true
			}

			if !useProxy && config.IsDomainRuleAvailable() {
				_, useProxy = config.GetSingleDomainRule(host)
			}

			if config.IsDnsRuleAvailable() {
				var ip string
				ip, hasDnsRule = config.GetSingleDnsRule(host)

				if hasDnsRule {
					host = ip
					useProxy = true
				}
			}

			if !useProxy && config.IsZjuForceProxyRuleAvailable() {
				isInZjuForceProxyRule = config.IsInZjuForceProxyRule(host)

				if isInZjuForceProxyRule {
					useProxy = true
				}
			}
			if pureIp := net.ParseIP(host); pureIp != nil {
				// host is pure IP format, e.g.: "10.10.10.10"
				target = &net.IPAddr{IP: pureIp}
			} else {
				// host is domain, e.g.: "mail.zju.edu.cn"
				if UseZjuDns {
					if cachedIP, found := GetDnsCache(host); found {
						target = &net.IPAddr{IP: cachedIP}
					} else {
						targets, err := remoteResolver.LookupIP(context.Background(), "ip4", host)
						if err != nil {
							log.Printf("Resolve IPv4 addr failed using ZJU DNS: " + host + ", using local DNS instead.")

							target, err = net.ResolveIPAddr("ip4", host)
							if err != nil {
								log.Printf("Resolve IPv4 addr failed using local DNS: " + host + ". Use direct connection.")
								return dialDirect(ctx, network, addr)
							}
						} else {
							target = &net.IPAddr{IP: targets[0]}
							//TODO: whether need all dns records? or only 10.0.0.0/8 ?
							SetDnsCache(host, targets[0])
						}
					}

				} else {
					// because of OS cache, don't need extra dns memory cache
					target, err = net.ResolveIPAddr("ip4", host)
					if err != nil {
						log.Printf("Resolve IPv4 addr failed using local DNS: " + host + ". Use direct connection.")
						return dialDirect(ctx, network, addr)
					}
				}
			}

			if !useProxy && config.IsDomainRuleAvailable() {
				_, useProxy = config.GetSingleDomainRule(target.IP.String())
			}

			if !useProxy && config.IsZjuForceProxyRuleAvailable() {
				isInZjuForceProxyRule = config.IsInZjuForceProxyRule(target.IP.String())

				if isInZjuForceProxyRule {
					useProxy = true
				}
			}

			if !useProxy && config.IsIpv4RuleAvailable() {
				if DebugDump {
					log.Printf("IPv4 rule is available ")
				}
				for _, rule := range *config.GetIpv4Rules() {
					if rule.CIDR {
						_, cidr, _ := net.ParseCIDR(rule.Rule)
						if DebugDump {
							log.Printf("CIDR test: %s %s %v", target.IP, rule.Rule, cidr.Contains(target.IP))
						}

						if cidr.Contains(target.IP) {
							if DebugDump {
								log.Printf("CIDR matched: %s %s", target.IP, rule.Rule)
							}

							useProxy = true
						}
					} else {
						if DebugDump {
							log.Printf("Raw match test: %s %s", target.IP, rule.Rule)
						}

						ip1 := net.ParseIP(strings.Split(rule.Rule, "~")[0])
						ip2 := net.ParseIP(strings.Split(rule.Rule, "~")[1])

						if bytes.Compare(target.IP, ip1) >= 0 && bytes.Compare(target.IP, ip2) <= 0 {
							if DebugDump {
								log.Printf("Raw matched: %s %s", ip1, ip2)
							}

							useProxy = true
						}
					}
				}
			}

			if useProxy {
				if network != "tcp" {
					log.Printf("Proxy only support TCP. Use direct connection.")

					return dialDirect(ctx, network, addr)
				}

				addrTarget := tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(port),
					Addr: tcpip.Address(target.IP),
				}

				bind := tcpip.FullAddress{
					NIC:  defaultNIC,
					Addr: tcpip.Address(selfIp),
				}

				log.Printf("Addr: %s, UseProxy: %v, UseCustomDns: %v, IsForceProxy: %v, ResolvedIp: %s", addr, useProxy, hasDnsRule, isInZjuForceProxyRule, target.IP.String())

				return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
			} else {
				return dialDirect(ctx, network, addr)
			}
		},
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("socks listen failed: " + err.Error())
	}

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	err = server.Serve(listener)
	panic(err)
}
