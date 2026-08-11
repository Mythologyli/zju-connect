package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"

	tun "github.com/mythologyli/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
)

type Endpoint struct {
	client client.Client

	ifce      tun.Tun
	ifceName  string
	ifceIndex int
	readLock  sync.Mutex
	writeLock sync.Mutex
	configMu  sync.RWMutex
	ip        net.IP

	ipSetBuilder netaddr.IPSetBuilder
	ipSet        *netaddr.IPSet

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	ep.writeLock.Lock()
	defer ep.writeLock.Unlock()
	_, err := ep.ifce.Write(buf)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	ep.readLock.Lock()
	defer ep.readLock.Unlock()
	return ep.ifce.Read(buf)
}

func (s *Stack) AddRoute(target string) error {
	command := exec.Command("route", "-n", "add", "-net", target, "-interface", s.endpoint.ifceName)
	err := command.Run()
	if err != nil {
		return err
	}

	s.endpoint.ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix(target))
	s.endpoint.ipSet, _ = s.endpoint.ipSetBuilder.IPSet()

	return nil
}

func (s *Stack) AddDnsServer(dnsServer string, targetHost string) error {
	fileName := fmt.Sprintf("/etc/resolver/%s", targetHost)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString(fmt.Sprintf("nameserver %s\n", dnsServer))

	hook_func.RegisterTerminalFunc("DelDnsServer_"+targetHost, func(ctx context.Context) error {
		delCommand := exec.Command("rm", fmt.Sprintf("/etc/resolver/%s", targetHost))
		delErr := delCommand.Run()
		if delErr != nil {
			return delErr
		}
		return nil
	})
	return nil
}

func NewStack(vpnClient client.Client, dnsHijack, fakeIP bool, ipResources []client.IPResource) (*Stack, error) {
	var err error
	s := &Stack{}
	s.ipResources = ipResources
	s.fakeIP = fakeIP
	s.endpoint = &Endpoint{
		client: vpnClient,
	}
	s.endpoint.ipSetBuilder = netaddr.IPSetBuilder{}

	s.endpoint.ip, err = vpnClient.IP()
	if err != nil {
		return nil, err
	}
	ipPrefix, _ := netip.ParsePrefix(s.endpoint.ip.String() + "/32")
	tunName := "utun0"
	tunName = tun.CalculateInterfaceName(tunName)
	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
		// Inet4Address and Inet4RouteAddress must be set concurrently if we want to enable AutoRoute
		// otherwise the sing-tun will add weird router
		AutoRoute: false,
	}

	ifce, err := tun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	hook_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
		return ifce.Close()
	})
	s.endpoint.ifce = ifce
	s.endpoint.ifceName = tunName
	netIfce, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, err
	}

	s.endpoint.ifceIndex = netIfce.Index
	log.Printf("Interface Name: %s, index %d\n", tunName, netIfce.Index)

	// We need this dialer to bind to device otherwise packets will not be sent via TUN
	// Doesn't work on macOS. See  https://github.com/Mythologyli/zju-connect/pull/44#issuecomment-1784050022
	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error { // By ChenXuzheng
			return c.Control(func(fd uintptr) {
				if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, s.endpoint.ifceIndex); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
	}

	// Doesn't work on macOS. See  https://github.com/Mythologyli/zju-connect/pull/44#issuecomment-1784050022
	s.endpoint.udpDialer = &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error { // By ChenXuzheng
			return c.Control(func(fd uintptr) {
				if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, s.endpoint.ifceIndex); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
	}
	if dnsHijack {
		dnsServers, err := hook_func.ListNetworkServices()
		if err != nil {
			return nil, err
		}
		for _, dnsServer := range dnsServers {
			if hook_func.SetDNSServerWithHook(dnsServer, s.endpoint.ip.String()) != nil {
				log.Println("Warning: failed to set DNS server", s.endpoint.ifceName)
			}
		}
	}
	client.RegisterIPUpdateHandler(vpnClient, s.updateIP)
	return s, nil
}

func (s *Stack) updateIP(ip net.IP) error {
	newIP := ip.To4()
	if newIP == nil {
		return fmt.Errorf("virtual IP update is not IPv4")
	}
	s.endpoint.configMu.Lock()
	defer s.endpoint.configMu.Unlock()
	oldIP := append(net.IP(nil), s.endpoint.ip...)
	if oldIP.Equal(newIP) {
		return nil
	}
	add := exec.Command("ifconfig", s.endpoint.ifceName, "inet", newIP.String(), newIP.String(), "netmask", "255.255.255.255", "alias")
	if output, err := add.CombinedOutput(); err != nil {
		return fmt.Errorf("add virtual IP: %w: %s", err, output)
	}
	del := exec.Command("ifconfig", s.endpoint.ifceName, "inet", oldIP.String(), "-alias")
	if output, err := del.CombinedOutput(); err != nil {
		_ = exec.Command("ifconfig", s.endpoint.ifceName, "inet", newIP.String(), "-alias").Run()
		return fmt.Errorf("remove old virtual IP: %w: %s", err, output)
	}
	s.endpoint.ip = append(net.IP(nil), newIP...)
	s.endpoint.tcpDialer.LocalAddr = &net.TCPAddr{IP: append(net.IP(nil), newIP...)}
	s.endpoint.udpDialer.LocalAddr = &net.UDPAddr{IP: append(net.IP(nil), newIP...)}
	return nil
}
