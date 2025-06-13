//go:build !android

package tun

import (
	"context"
	tun "github.com/cxz66666/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"
)

type Endpoint struct {
	easyConnectClient *easyconnect.Client

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
	err := command.Run()
	if err != nil {
		return err
	}

	return nil
}

func NewStack(easyConnectClient *easyconnect.Client, dnsHijack bool, ipResources []client.IPResource) (*Stack, error) {
	var err error
	s := &Stack{}
	s.ipResources = ipResources
	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	s.endpoint.ip, err = easyConnectClient.IP()
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

	return s, nil
}
