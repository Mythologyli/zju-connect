package tun

import (
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/songgao/water"
	"golang.org/x/sys/unix"
	"net"
	"os/exec"
	"syscall"
)

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	ifce *water.Interface
	ip   net.IP

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
}

func (ep *Endpoint) Write(buf []byte) error {
	_, err := ep.ifce.Write(buf)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	return ep.ifce.Read(buf)
}

func (s *Stack) AddRoute(target string) error {
	command := exec.Command("route", "-n", "add", "-net", target, "-interface", s.endpoint.ifce.Name())
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

	// Get index of TUN interface
	netIfce, err := net.InterfaceByName(ifce.Name())
	if err != nil {
		return nil, err
	}

	ifceIndex := netIfce.Index

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
		Control: func(network, address string, c syscall.RawConn) error { // By ChenXuzheng
			return c.Control(func(fd uintptr) {
				if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, ifceIndex); err != nil {
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
		Control: func(network, address string, c syscall.RawConn) error { // By ChenXuzheng
			return c.Control(func(fd uintptr) {
				if err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVIF, ifceIndex); err != nil {
					log.Println("Warning: failed to bind to interface", s.endpoint.ifce.Name())
				}
			})
		},
	}

	cmd := exec.Command("ifconfig", ifce.Name(), s.endpoint.ip.String(), "255.0.0.0", s.endpoint.ip.String())
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	if err = s.AddRoute("10.0.0.0/8"); err != nil {
		log.Printf("Run AddRoute 10.0.0.0/8 failed: %v", err)
	}

	// Set MTU to 1400 otherwise error may occur when packets are large
	cmd = exec.Command("ifconfig", ifce.Name(), "mtu", strconv.Itoa(int(MTU)), "up")
	err = cmd.Run()
	if err != nil {
		log.Printf("Run %s failed: %v", cmd.String(), err)
	}

	return s, nil
}
