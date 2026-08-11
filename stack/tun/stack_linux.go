//go:build !android

package tun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"

	tun "github.com/mythologyli/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
)

type Endpoint struct {
	client client.Client

	ifce      tun.Tun
	ifceName  string
	readLock  sync.Mutex
	writeLock sync.Mutex
	configMu  sync.RWMutex
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
	command := exec.Command("ip", "route", "add", target, "dev", s.endpoint.ifceName)
	err := command.Run()
	if err != nil {
		return err
	}

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

	s.endpoint.ip, err = vpnClient.IP()
	if err != nil {
		return nil, err
	}
	ipPrefix, _ := netip.ParsePrefix(s.endpoint.ip.String() + "/32")
	tunName := "ZJU-Connect"
	tunName = tun.CalculateInterfaceName(tunName)

	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
	}
	if dnsHijack {
		tunOptions.AutoRoute = true
		tunOptions.TableIndex = 1897
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
	log.Printf("Interface Name: %s\n", tunName)

	// We need this dialer to bind to device otherwise packets will not be sent via TUN
	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifceName); err != nil {
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
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifceName); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifceName)
				}
			})
		},
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
	add := exec.Command("ip", "address", "replace", newIP.String()+"/32", "dev", s.endpoint.ifceName)
	if output, err := add.CombinedOutput(); err != nil {
		return fmt.Errorf("add virtual IP: %w: %s", err, output)
	}
	del := exec.Command("ip", "address", "del", oldIP.String()+"/32", "dev", s.endpoint.ifceName)
	if output, err := del.CombinedOutput(); err != nil {
		_ = exec.Command("ip", "address", "del", newIP.String()+"/32", "dev", s.endpoint.ifceName).Run()
		return fmt.Errorf("remove old virtual IP: %w: %s", err, output)
	}
	s.endpoint.ip = append(net.IP(nil), newIP...)
	s.endpoint.tcpDialer.LocalAddr = &net.TCPAddr{IP: append(net.IP(nil), newIP...)}
	s.endpoint.udpDialer.LocalAddr = &net.UDPAddr{IP: append(net.IP(nil), newIP...)}
	return nil
}
