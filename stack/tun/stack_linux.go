package tun

import (
	tun "github.com/cxz66666/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"syscall"
)

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	ifce      tun.Tun
	ifceName  string
	readLock  sync.Mutex
	writeLock sync.Mutex
	ip        net.IP

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
}

func (ep *Endpoint) Write(buf []byte) error {
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

func NewStack(easyConnectClient *client.EasyConnectClient, dnsServer string) (*Stack, error) {
	var err error
	s := &Stack{}
	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	s.endpoint.ip, err = easyConnectClient.IP()
	if err != nil {
		return nil, err
	}
	ipPrefix, _ := netip.ParsePrefix(s.endpoint.ip.String() + "/8")
	tunName := "zjuconnect"
	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
		AutoRoute:  true,
		TableIndex: 1897,
	}
	tunName = tun.CalculateInterfaceName(tunName)
	ifce, err := tun.New(tunOptions)
	if err != nil {
		return nil, err
	}
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
