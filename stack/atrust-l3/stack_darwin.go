package atrustl3

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"

	tun "github.com/cxz66666/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/unix"
)

type Endpoint struct {
	ifce      tun.Tun
	ifceName  string
	ifceIndex int
	readLock  sync.Mutex
	writeLock sync.Mutex
	ip        net.IP

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
	return command.Run()
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
		return delCommand.Run()
	})
	return nil
}

func NewStack(aTrustClient *atrustclient.Client, dnsHijack bool, ipResources []client.IPResource) (*Stack, error) {
	s, err := newStack(aTrustClient)
	if err != nil {
		return nil, err
	}
	if ipResources != nil {
		s.ipResources = ipResources
	}

	ipPrefix, _ := netip.ParsePrefix(s.ip.String() + "/32")
	tunName := "utun0"
	tunName = tun.CalculateInterfaceName(tunName)
	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
		AutoRoute: false,
	}

	ifce, err := tun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	hook_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
		return ifce.Close()
	})

	s.endpoint = &Endpoint{
		ifce:     ifce,
		ifceName: tunName,
		ip:       s.ip,
	}
	netIfce, err := net.InterfaceByName(tunName)
	if err != nil {
		return nil, err
	}
	log.Printf("Interface Name: %s, index %d\n", tunName, netIfce.Index)
	s.endpoint.ifceIndex = netIfce.Index

	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, s.endpoint.ifceIndex); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
	}

	s.endpoint.udpDialer = &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, s.endpoint.ifceIndex); err != nil {
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

	return s, nil
}
