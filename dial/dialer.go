package dial

import (
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/stack"
	"inet.af/netaddr"
	"net"
	"strconv"
	"strings"
)

import (
	"context"
	"errors"
)

type Dialer struct {
	stack        stack.Stack
	resolver     *resolve.Resolver
	ipResource   *netaddr.IPSet
	alwaysUseVPN bool
}

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> DIRECT", addr)

	return goDial(ctx, network, addr)
}

func (d *Dialer) DialIPPort(ctx context.Context, network, addr string) (net.Conn, error) {
	// If addr is IPv6, use direct connection
	if strings.Count(addr, ":") > 1 {
		return dialDirect(ctx, network, addr)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("Invalid address: " + addr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("Invalid port in address: " + addr)
	}

	var useVPN = false
	var target *net.IPAddr

	if pureIp := net.ParseIP(host); pureIp != nil {
		target = &net.IPAddr{IP: pureIp}
	} else {
		log.Printf("Illegal situation, host is not pure IP format: %s", host)
		return dialDirect(ctx, network, addr)
	}

	if d.alwaysUseVPN {
		useVPN = true
	}

	if res := ctx.Value("USE_VPN"); res != nil && res.(bool) {
		useVPN = true
	}

	if !useVPN && d.ipResource != nil {
		ip, ok := netaddr.FromStdIP(target.IP)
		if ok {
			if d.ipResource.Contains(ip) {
				useVPN = true
			}
		}
	}

	if useVPN {
		if network == "tcp" {
			log.Printf("%s -> VPN", addr)

			return d.stack.DialTCP(&net.TCPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else if network == "udp" {
			log.Printf("%s -> VPN", addr)

			return d.stack.DialUDP(&net.UDPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else {
			log.Printf("VPN only support TCP/UDP. Connection to %s will use direct connection", addr)
			return dialDirect(ctx, network, addr)
		}
	} else {
		return dialDirect(ctx, network, addr)
	}
}

func (d *Dialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	// If addr is IPv6, use direct connection
	if strings.Count(addr, ":") > 1 {
		return dialDirect(ctx, network, addr)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return dialDirect(ctx, network, addr)
	}

	ctx, ip, err := d.resolver.Resolve(ctx, host)
	if err != nil {
		return dialDirect(ctx, network, addr)
	}

	if strings.Count(ip.String(), ":") > 0 {
		return dialDirect(ctx, network, addr)
	}

	return d.DialIPPort(ctx, network, ip.String()+":"+port)
}

func NewDialer(stack stack.Stack, resolver *resolve.Resolver, ipResource *netaddr.IPSet, alwaysUseVPN bool) *Dialer {
	return &Dialer{
		stack:        stack,
		resolver:     resolver,
		ipResource:   ipResource,
		alwaysUseVPN: alwaysUseVPN,
	}
}
