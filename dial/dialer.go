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
	stack                stack.Stack
	resolver             *resolve.Resolver
	ipResource           *netaddr.IPSet
	alwaysUseVPN         bool
	dialDirectHTTPProxy  string // format: "ip:port"
	dialDirectSocksProxy string // WORKING IN PROCESS
}

// usedAddr maybe ip:port or hostname:port, it doesn't matter
func (d *Dialer) dialDirectWithHTTPProxy(ctx context.Context, usedAddr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> PROXY[%s]", usedAddr, d.dialDirectHTTPProxy)
	conn, err := goDial(ctx, "tcp", d.dialDirectHTTPProxy)
	if err != nil {
		return nil, err
	}
	_, _ = conn.Write([]byte("CONNECT " + usedAddr + " HTTP/1.1\r\n\r\n"))
	connBuf := make([]byte, 256)
	n, _ := conn.Read(connBuf)
	if strings.Contains(string(connBuf[:n]), "200") {
		return conn, nil
	} else {
		return nil, errors.New("PROXY CONNECT ERROR")
	}
}

func (d *Dialer) dialDirectWithoutProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext
	log.Printf("%s -> DIRECT", addr)
	return goDial(ctx, network, addr)
}

// dialDirectIP need have a `hostAddr` parameter, which will be passed to PROXY. But `hostAddr` maybe empty, ipAddr never be empty.
func (d *Dialer) dialDirectIP(ctx context.Context, network, ipAddr string, hostAddr string) (net.Conn, error) {
	// only support http proxy now and tcp network type
	if d.dialDirectHTTPProxy != "" && network == "tcp" {
		usedAddr := ipAddr
		if hostAddr != "" {
			usedAddr = hostAddr
		}
		return d.dialDirectWithHTTPProxy(ctx, usedAddr)
	} else {
		return d.dialDirectWithoutProxy(ctx, network, ipAddr)
	}
}

func (d *Dialer) dialDirectHost(ctx context.Context, network, hostAddr string) (net.Conn, error) {
	// only support http proxy now and tcp network type
	if d.dialDirectHTTPProxy != "" && network == "tcp" {
		return d.dialDirectWithHTTPProxy(ctx, hostAddr)
	} else {
		return d.dialDirectWithoutProxy(ctx, network, hostAddr)
	}
}

func (d *Dialer) DialIPPort(ctx context.Context, network, ipAddr string) (net.Conn, error) {
	hostAddr := ""
	if _, hostAddrOK := ctx.Value("RESOLVE_HOST").(string); hostAddrOK {
		// hostAddr doesn't have port field at now
		hostAddr = ctx.Value("RESOLVE_HOST").(string)
	}
	parts := strings.Split(ipAddr, ":")
	if len(parts) >= 2 {
		// maybe need extra check for parts[len(parts)-1] is port or not?
		hostAddr += ":" + parts[len(parts)-1]
	}

	// If addr is IPv6, use direct connection
	if len(parts) > 2 {
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
	}

	ip, portStr, err := net.SplitHostPort(ipAddr)
	if err != nil {
		return nil, errors.New("Invalid address: " + ipAddr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("Invalid port in address: " + ipAddr)
	}

	var useVPN = false
	var target *net.IPAddr

	if pureIp := net.ParseIP(ip); pureIp != nil {
		target = &net.IPAddr{IP: pureIp}
	} else {
		log.Printf("Illegal situation, host is not pure IP format: %s", ip)
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
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
			log.Printf("%s -> VPN", ipAddr)

			return d.stack.DialTCP(&net.TCPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else if network == "udp" {
			log.Printf("%s -> VPN", ipAddr)

			return d.stack.DialUDP(&net.UDPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else {
			log.Printf("VPN only support TCP/UDP. Connection to %s will use direct connection", ipAddr)
			return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
		}
	} else {
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
	}
}

func (d *Dialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	// If addr is IPv6, use direct connection
	if strings.Count(addr, ":") > 1 {
		return d.dialDirectIP(ctx, network, addr, "")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.dialDirectHost(ctx, network, addr)
	}

	var ip net.IP
	if ip = net.ParseIP(host); ip == nil {
		ctx, ip, err = d.resolver.Resolve(ctx, host)
		if err != nil {
			return d.dialDirectHost(ctx, network, addr)
		}

		if strings.Count(ip.String(), ":") > 0 {
			return d.dialDirectIP(ctx, network, ip.String()+":"+port, addr)
		}
	}

	return d.DialIPPort(ctx, network, ip.String()+":"+port)
}

func NewDialer(stack stack.Stack, resolver *resolve.Resolver, ipResource *netaddr.IPSet, alwaysUseVPN bool, dialDirectProxy string) *Dialer {
	if strings.HasPrefix(dialDirectProxy, "http://") {
		dialDirectProxy = strings.TrimPrefix(dialDirectProxy, "http://")
	} else if len(dialDirectProxy) > 0 {
		log.Println("暂不支持除[http]之外的DialDirectProxy，忽略该配置项")
		dialDirectProxy = ""
	}
	return &Dialer{
		stack:                stack,
		resolver:             resolver,
		ipResource:           ipResource,
		alwaysUseVPN:         alwaysUseVPN,
		dialDirectHTTPProxy:  dialDirectProxy,
		dialDirectSocksProxy: "",
	}
}
