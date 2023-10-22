package core

import (
	"bytes"
	"context"
	"errors"
	"github.com/mythologyli/zju-connect/core/config"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"strconv"
	"strings"
)

type Dialer struct {
	selfIp []byte

	gvisorStack *stack.Stack
}

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> DIRECT", addr)

	return goDial(ctx, network, addr)
}

func (dialer *Dialer) DialIpAndPort(ctx context.Context, network, addr string) (net.Conn, error) {
	// Check if is IPv6
	if strings.Count(addr, ":") > 1 {
		return dialDirect(ctx, network, addr)
	}

	parts := strings.Split(addr, ":")

	// in normal situation, addr must be a pure valid IP
	// because we use `DnsResolve` to resolve domain name before call `DialIpAndPort`
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.New("Invalid port in address: " + addr)
	}

	var isInZjuForceProxyRule = false
	var useProxy = false

	var target *net.IPAddr

	if pureIp := net.ParseIP(host); pureIp != nil {
		// host is pure IP format, e.g.: "10.10.10.10"
		target = &net.IPAddr{IP: pureIp}
	} else {
		// illegal situation
		log.Printf("Illegal situation, host is not pure IP format: %s", host)
		return dialDirect(ctx, network, addr)
	}

	if ProxyAll {
		useProxy = true
	}

	if res := ctx.Value("USE_PROXY"); res != nil && res.(bool) {
		useProxy = true
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
		addrTarget := tcpip.FullAddress{
			NIC:  defaultNIC,
			Port: uint16(port),
			Addr: tcpip.AddrFromSlice(target.IP),
		}

		bind := tcpip.FullAddress{
			NIC:  defaultNIC,
			Addr: tcpip.AddrFromSlice(dialer.selfIp),
		}

		if network == "tcp" {
			log.Printf("%s -> PROXY", addr)
			return gonet.DialTCPWithBind(context.Background(), dialer.gvisorStack, bind, addrTarget, header.IPv4ProtocolNumber)
		} else if network == "udp" {
			log.Printf("%s -> PROXY", addr)
			return gonet.DialUDP(dialer.gvisorStack, &bind, &addrTarget, header.IPv4ProtocolNumber)
		} else {
			log.Printf("Proxy only support TCP/UDP. Connection to %s will use direct connection.", addr)
			return dialDirect(ctx, network, addr)
		}
	} else {
		return dialDirect(ctx, network, addr)
	}
}

func (dialer *Dialer) Dial(ctx context.Context, dnsResolve *DnsResolve, network string, addr string) (net.Conn, error) {
	// Check if is IPv6
	if strings.Count(addr, ":") > 1 {
		return dialDirect(ctx, network, addr)
	}

	parts := strings.Split(addr, ":")
	host := parts[0]
	port := parts[1]

	ctx, ip, err := dnsResolve.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	if strings.Count(ip.String(), ":") > 0 {
		return dialDirect(ctx, network, addr)
	}

	return dialer.DialIpAndPort(ctx, network, ip.String()+":"+port)
}