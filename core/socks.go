package core

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"EasierConnect/core/config"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/socks5"
)

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

			log.Printf("socks dial: %s", addr)

			parts := strings.Split(addr, ":")

			host := parts[0]
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("invalid port: " + parts[1])
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

			if UseZjuDns {
				targets, err := remoteResolver.LookupIP(context.Background(), "ip4", host)
				if err != nil {
					return nil, errors.New("resolve ip addr failed: " + host)

					//////////////////////Use Local
				}
				target = &net.IPAddr{IP: targets[0]}
			} else {
				target, err = net.ResolveIPAddr("ip", host)
				if err != nil {
					return nil, errors.New("resolve ip addr failed: " + host)
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
					log.Printf("Ipv4Rule is available ")
				}
				for _, rule := range *config.GetIpv4Rules() {
					if rule.CIDR {
						_, cidr, _ := net.ParseCIDR(rule.Rule)
						if DebugDump {
							log.Printf("Cidr test: %s %s %v", target.IP, rule.Rule, cidr.Contains(target.IP))
						}

						if cidr.Contains(target.IP) {
							if DebugDump {
								log.Printf("Cidr matched: %s %s", target.IP, rule.Rule)
							}

							useProxy = true
						}
					} else {
						if DebugDump {
							log.Printf("raw match test: %s %s", target.IP, rule.Rule)
						}

						ip1 := net.ParseIP(strings.Split(rule.Rule, "~")[0])
						ip2 := net.ParseIP(strings.Split(rule.Rule, "~")[1])

						if bytes.Compare(target.IP, ip1) >= 0 && bytes.Compare(target.IP, ip2) <= 0 {
							if DebugDump {
								log.Printf("raw matched: %s %s", ip1, ip2)
							}

							useProxy = true
						}
					}
				}
			}

			// if !useProxy && config.IsDomainRuleAvailable() {
			// 	_, allowAllWebSites := config.GetSingleDomainRule("*")

			// 	if allowAllWebSites {
			// 		useProxy = true
			// 	}
			// }

			if useProxy {
				if network != "tcp" {
					return nil, errors.New("only support tcp")
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

				log.Printf("Addr: %s, useProxy: %v, useCustomDns: %v, isForceProxy: %v, ResolvedIp: %s", addr, useProxy, hasDnsRule, isInZjuForceProxyRule, target.IP.String())

				return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
			}

			if UseZjuDns {
				// Use local DNS Server now
				target, err = net.ResolveIPAddr("ip", host)
				if err != nil {
					return nil, errors.New("resolve ip addr failed: " + host)
				}
			}

			goDialer := &net.Dialer{}
			goDial := goDialer.DialContext

			log.Printf("Addr: %s, useProxy: %v, useCustomDns: %v, isForceProxy: %v, ResolvedIp: %s", addr, useProxy, hasDnsRule, isInZjuForceProxyRule, target.IP.String())

			return goDial(ctx, network, target.IP.String()+":"+parts[1])
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
