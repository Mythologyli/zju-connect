package tun

import (
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/songgao/water"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
)

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	ifce      *water.Interface
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
	command := exec.Command("ip", "route", "add", target, "dev", s.endpoint.ifce.Name())
	err := command.Run()
	if err != nil {
		return err
	}

	return nil
}

func NewStack(easyConnectClient *client.EasyConnectClient, dnsServer string) (*Stack, error) {
	s := &Stack{}

	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Interface Name: %s\n", ifce.Name())

	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	s.endpoint.ifce = ifce

	s.endpoint.ip, err = easyConnectClient.IP()
	if err != nil {
		return nil, err
	}

	// We need this dialer to bind to device otherwise packets will not be sent via TUN
	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifce.Name()); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifce.Name())
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
				if err := syscall.BindToDevice(int(fd), s.endpoint.ifce.Name()); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifce.Name())
				}
			})
		},
	}

	cmd := exec.Command("ip", "link", "set", ifce.Name(), "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	// Set MTU to 1400 otherwise error may occur when packets are large
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "mtu", strconv.Itoa(int(MTU)))
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	cmd = exec.Command("ip", "addr", "add", s.endpoint.ip.String()+"/8", "dev", ifce.Name())
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	return s, nil
}
