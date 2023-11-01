package tun

import (
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/net/ipv4"
	"io"
	"syscall"
)

type Stack struct {
	endpoint *Endpoint
	rvpnConn io.ReadWriteCloser
}

func (s *Stack) Run() {
	s.rvpnConn, _ = client.NewRvpnConn(s.endpoint.easyConnectClient)

	// Read from VPN server and send to TUN stack
	go func() {
		for {
			buf := make([]byte, 1500)
			n, _ := s.rvpnConn.Read(buf)

			log.DebugPrintf("Recv: read %d bytes", n)
			log.DebugDumpHex(buf[:n])

			err := s.endpoint.Write(buf[:n])
			if err != nil {
				log.Printf("Error occurred while writing to TUN stack: %v", err)
				panic(err)
			}
		}
	}()

	// Read from TUN stack and send to VPN server
	for {
		buf := make([]byte, 1500)
		n, err := s.endpoint.Read(buf)
		if err != nil {
			log.Printf("Error occurred while reading from TUN stack: %v", err)
			// TODO graceful shutdown
			panic(err)
		}

		if n < 20 {
			continue
		}

		header, err := ipv4.ParseHeader(buf[:n])
		if err != nil {
			continue
		}

		// Filter out non-TCP/UDP packets otherwise error may occur
		if header.Protocol != syscall.IPPROTO_TCP && header.Protocol != syscall.IPPROTO_UDP {
			continue
		}

		_, _ = s.rvpnConn.Write(buf[:n])

		log.DebugPrintf("Send: wrote %d bytes", n)
		log.DebugDumpHex(buf[:n])
	}
}
