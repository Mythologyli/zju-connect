package underlay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	tun "github.com/mythologyli/sing-tun"
	"github.com/mythologyli/zju-connect/log"
	"github.com/sagernet/sing/common/logger"
)

// Dialer creates connections on the interface that was used to reach the VPN
// server before the TUN interface was installed. This prevents VPN underlay
// connections from being captured by the TUN interface itself.
type Dialer struct {
	mu            sync.RWMutex
	interfaceName string
	autoDetect    bool
	excludedIPs   []net.IP
	requireBound  bool
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

func New(options ...Options) (*Dialer, error) {
	option := Options{AutoDetect: true}
	if len(options) > 0 {
		option = options[0]
	}
	d := &Dialer{autoDetect: option.AutoDetect}
	if option.InterfaceName != "" {
		d.updateInterfaceName(option.InterfaceName)
		d.autoDetect = false
	}
	return d, nil
}

// Close releases resources owned by the dialer.
func (d *Dialer) Close() error {
	return nil
}

func (d *Dialer) InterfaceName() string {
	if d == nil {
		return ""
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.interfaceName
}

// ExcludeIP prevents an interface carrying ip from being selected as the
// underlay. VPN clients use this to exclude their own TUN interface.
func (d *Dialer) ExcludeIP(ip net.IP) {
	if d == nil || ip == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.excludedIPs = append(d.excludedIPs, append(net.IP(nil), ip...))
	d.requireBound = true
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	interfaceName := d.ensureInterface(address)
	d.mu.RLock()
	autoDetect := d.autoDetect
	requireBound := d.requireBound
	d.mu.RUnlock()
	if autoDetect && requireBound && interfaceName == "" {
		interfaceName = d.refreshInterface()
		if interfaceName == "" {
			return nil, fmt.Errorf("no usable underlay interface")
		}
	}

	conn, err := dialOnInterface(ctx, network, address, interfaceName)
	if err == nil {
		return conn, nil
	}

	refreshedInterface := d.refreshInterface()
	if refreshedInterface == "" || refreshedInterface == interfaceName {
		return nil, err
	}

	conn, retryErr := dialOnInterface(ctx, network, address, refreshedInterface)
	if retryErr != nil {
		return nil, fmt.Errorf("dial underlay via %q failed after %q failed: %w", refreshedInterface, interfaceName, retryErr)
	}
	return conn, nil
}

func (d *Dialer) ensureInterface(address string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.autoDetect || d.interfaceName != "" {
		return d.interfaceName
	}
	if interfaceName := detectInterface(address); usableInterface(interfaceName, d.excludedIPs) {
		d.updateInterfaceName(interfaceName)
	}
	return d.interfaceName
}

func (d *Dialer) updateInterfaceName(interfaceName string) {
	if interfaceName == "" || interfaceName == d.interfaceName {
		return
	}
	d.interfaceName = interfaceName
	log.Printf("Underlay interface: %s", interfaceName)
}

func dialContextOnInterface(ctx context.Context, network, address, interfaceName string) (net.Conn, error) {
	nd := &net.Dialer{}
	if interfaceName != "" {
		if err := bindInterface(nd, interfaceName); err != nil {
			return nil, fmt.Errorf("bind underlay interface %q: %w", interfaceName, err)
		}
	}
	return nd.DialContext(ctx, network, address)
}

var dialOnInterface = dialContextOnInterface

func (d *Dialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func detectInterface(targetAddress string) string {
	if interfaceName := findDefaultInterface(); usableInterface(interfaceName, nil) {
		return interfaceName
	}

	// This fallback is primarily for platforms without a default-interface
	// monitor. The first DialContext runs before the TUN interface is installed.
	host, port, err := net.SplitHostPort(targetAddress)
	if err != nil {
		host = targetAddress
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
				if usableInterface(iface.Name, nil) {
					return iface.Name
				}
				return ""
			}
		}
	}
	return ""
}

func (d *Dialer) refreshInterface() string {
	d.mu.RLock()
	autoDetect := d.autoDetect
	d.mu.RUnlock()
	if !autoDetect {
		return ""
	}

	interfaceName := findDefaultInterface()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !usableInterface(interfaceName, d.excludedIPs) {
		return ""
	}
	d.updateInterfaceName(interfaceName)
	return interfaceName
}

var findDefaultInterface = detectDefaultInterface

func detectDefaultInterface() string {
	networkMonitor, err := tun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return ""
	}
	if err := networkMonitor.Start(); err != nil {
		_ = networkMonitor.Close()
		return ""
	}
	defer networkMonitor.Close()

	interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkMonitor, logger.NOP(), tun.DefaultInterfaceMonitorOptions{OverrideAndroidVPN: true})
	if err != nil {
		return ""
	}
	if err := interfaceMonitor.Start(); err != nil {
		_ = interfaceMonitor.Close()
		return ""
	}
	defer interfaceMonitor.Close()

	return interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified())
}

func usableInterface(interfaceName string, excludedIPs []net.IP) bool {
	if interfaceName == "" {
		return false
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	if len(excludedIPs) == 0 {
		return true
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		var interfaceIP net.IP
		switch value := address.(type) {
		case *net.IPNet:
			interfaceIP = value.IP
		case *net.IPAddr:
			interfaceIP = value.IP
		}
		for _, excludedIP := range excludedIPs {
			if interfaceIP != nil && interfaceIP.Equal(excludedIP) {
				return false
			}
		}
	}
	return true
}
