//go:build !android

package atrustl3

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"

	tun "github.com/cxz66666/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
)

type Endpoint struct {
	ifce      tun.Tun
	ifceName  string
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
	command := exec.Command("ip", "route", "add", target, "dev", s.endpoint.ifceName)
	return command.Run()
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

	s.endpoint = &Endpoint{
		ifce:     ifce,
		ifceName: tunName,
		ip:       s.ip,
	}
	log.Printf("Interface Name: %s\n", tunName)

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

	return s, nil
}
