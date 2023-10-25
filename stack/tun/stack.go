package tun

import (
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/net/ipv4"
)

const tcpProtocolNumber = 6
const udpProtocolNumber = 17

type Stack struct {
	endpoint *Endpoint
}

func (s *Stack) Run() {
	sendConn, err := s.endpoint.easyConnectClient.SendConn()
	if err != nil {
		panic(err)
	}

	recvConn, err := s.endpoint.easyConnectClient.RecvConn()
	if err != nil {
		panic(err)
	}

	sendErrCount := 0
	recvErrCount := 0

	// Read from VPN server and send to TUN stack
	go func() {
		for {
			buf := make([]byte, 1500)
			n, err := recvConn.Read(buf)
			if err != nil {
				if recvErrCount < 5 {
					log.Printf("Error occurred while receiving, retrying: %v", err)

					// Do handshake again and create a new recvConn
					recvConn, err = s.endpoint.easyConnectClient.RecvConn()
					if err != nil {
						panic(err)
					}
				} else {
					panic("recv retry limit exceeded.")
				}

				recvErrCount++
			} else {
				log.DebugPrintf("Recv: read %d bytes", n)
				log.DebugDumpHex(buf[:n])

				err := s.endpoint.Write(buf[:n])
				if err != nil {
					return
				}
			}
		}
	}()

	// Read from TUN stack and send to VPN server
	for {
		buf := make([]byte, 1500)
		n, err := s.endpoint.Read(buf)

		header, err := ipv4.ParseHeader(buf[:n])
		if err != nil {
			continue
		}

		// Filter out non-TCP/UDP packets otherwise error may occur
		if header.Protocol != tcpProtocolNumber && header.Protocol != udpProtocolNumber {
			continue
		}

		if err != nil {
			if sendErrCount < 5 {
				log.Printf("Error occurred while sending, retrying: %v", err)

				// Do handshake again and create a new sendConn
				sendConn, err = s.endpoint.easyConnectClient.SendConn()
				if err != nil {
					panic(err)
				}
			} else {
				panic("send retry limit exceeded.")
			}

			sendErrCount++
		} else {
			log.DebugPrintf("Send: wrote %d bytes", n)
			log.DebugDumpHex(buf[:n])

			_, err := sendConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}
}
