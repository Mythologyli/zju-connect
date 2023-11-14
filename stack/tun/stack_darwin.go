package tun

import (
	"context"
	"fmt"
	tun "github.com/cxz66666/sing-tun"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/terminal_func"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

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

	terminal_func.RegisterTerminalFunc("DelDnsServer_"+targetHost, func(ctx context.Context) error {
		delCommand := exec.Command("rm", fmt.Sprintf("/etc/resolver/%s", targetHost))
		delErr := delCommand.Run()
		if delErr != nil {
			return delErr
		}
		return nil
	})
	return nil
}

func NewStack(easyConnectClient *client.EasyConnectClient, dnsHijack bool) (*Stack, error) {
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
	zjuPrefix, _ := netip.ParsePrefix("10.0.0.0/8")
	tunName := "utun0"
	tunName = tun.CalculateInterfaceName(tunName)
	tunOptions := tun.Options{
		Name: tunName,
		MTU:  MTU,
		Inet4Address: []netip.Prefix{
			ipPrefix,
		},
		Inet4RouteAddress: []netip.Prefix{
			zjuPrefix,
		},
		AutoRoute:  true,
		TableIndex: 1897,
	}

	ifce, err := tun.New(tunOptions)
	if err != nil {
		return nil, err
	}
	terminal_func.RegisterTerminalFunc("Close Tun Device", func(ctx context.Context) error {
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
		if err = s.AddDnsServer(s.endpoint.ip.String(), "zju.edu.cn"); err != nil {
			log.Printf("AddDnsServer failed: %v", err)
		}
		if err = s.AddDnsServer(s.endpoint.ip.String(), "cc98.org"); err != nil {
			log.Printf("AddDnsServer failed: %v", err)
		}
	}
	return s, nil
}
