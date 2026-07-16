package underlay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Dialer creates connections on the interface that was used to reach the VPN
// server before the TUN interface was installed. This prevents VPN underlay
// connections from being captured by the TUN interface itself.
type Dialer struct {
	interfaceName string
}

type Options struct {
	// InterfaceName explicitly selects the interface used by underlay sockets.
	// It takes precedence over AutoDetect.
	InterfaceName string
	AutoDetect    bool
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, address string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	config = config.Clone()
	if config.ServerName == "" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr == nil {
			config.ServerName = host
		}
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func New(serverAddress string, options ...Options) *Dialer {
	option := Options{AutoDetect: true}
	if len(options) > 0 {
		option = options[0]
	}
	if option.InterfaceName != "" {
		return &Dialer{interfaceName: option.InterfaceName}
	}
	if !option.AutoDetect {
		return &Dialer{}
	}
	return &Dialer{interfaceName: detectInterface(serverAddress)}
}

func (d *Dialer) InterfaceName() string {
	if d == nil {
		return ""
	}
	return d.interfaceName
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := &net.Dialer{}
	if d != nil && d.interfaceName != "" {
		if err := bindInterface(nd, d.interfaceName); err != nil {
			return nil, fmt.Errorf("bind underlay interface %q: %w", d.interfaceName, err)
		}
	}
	return nd.DialContext(ctx, network, address)
}

func (d *Dialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func detectInterface(serverAddress string) string {
	host, port, err := net.SplitHostPort(serverAddress)
	if err != nil {
		host = serverAddress
		port = "443"
	}
	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return ""
	}
	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	_ = conn.Close()

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil && ip.Equal(localIP) {
				return iface.Name
			}
		}
	}
	return ""
}
