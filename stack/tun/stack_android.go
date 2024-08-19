package tun

import (
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/net/ipv4"
	"io"
	"net"
	"os"
	"syscall"
)

const MTU uint32 = 1400

type Stack struct {
	endpoint *Endpoint
	rvpnConn io.ReadWriteCloser
}

func (s *Stack) Run() {
	var connErr error
	s.rvpnConn, connErr = client.NewRvpnConn(s.endpoint.easyConnectClient)
	if connErr != nil {
		return
	}
	// Read from VPN server and send to TUN stack
	go func() {
		for {
			buf := make([]byte, MTU)
			n, err := s.rvpnConn.Read(buf)
			if err != nil {
				log.Printf("Error occurred while reading from VPN server: %v", err)
				return
			}
			log.DebugPrintf("Recv: read %d bytes", n)
			log.DebugDumpHex(buf[:n])

			err = s.endpoint.Write(buf[:n])
			if err != nil {
				log.Printf("Error occurred while writing to TUN stack: %v", err)
				return
			}
		}
	}()

	// Read from TUN stack and send to VPN server
	for {
		buf := make([]byte, MTU)
		n, err := s.endpoint.Read(buf)
		if err != nil {
			log.Printf("Error occurred while reading from TUN stack: %v", err)
			return
		}

		header, err := ipv4.ParseHeader(buf[:n])
		if err != nil {
			continue
		}

		// Filter out non-TCP/UDP packets otherwise error may occur
		if header.Protocol != syscall.IPPROTO_TCP && header.Protocol != syscall.IPPROTO_UDP {
			continue
		}

		n, err = s.rvpnConn.Write(buf[:n])
		if err != nil {
			log.Printf("Error occurred while writing to VPN server: %v", err)
			return
		}
		log.DebugPrintf("Send: wrote %d bytes", n)
		log.DebugDumpHex(buf[:n])
	}
}

type Endpoint struct {
	easyConnectClient *client.EasyConnectClient

	readWriteCloser io.ReadWriteCloser
	ip              net.IP

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	_, err := ep.readWriteCloser.Write(buf)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	return ep.readWriteCloser.Read(buf)
}

func (s *Stack) AddRoute(target string) error {
	return nil
}

func NewStack(easyConnectClient *client.EasyConnectClient) (*Stack, error) {
	s := &Stack{}

	s.endpoint = &Endpoint{
		easyConnectClient: easyConnectClient,
	}

	var err error
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
	}

	s.endpoint.udpDialer = &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
	}

	return s, nil
}

func (s *Stack) SetupTun(fd int) {
	s.endpoint.readWriteCloser = os.NewFile(uintptr(fd), "tun")
}
