package tun

import (
	"context"
	"fmt"
	"io"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"github.com/mythologyli/zju-connect/log"
)

const MTU uint32 = 1400

type Stack struct {
	endpoint *Endpoint
	rvpnConn io.ReadWriteCloser
	resolve  zcdns.LocalServer
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) Run() {
	s.rvpnConn, _ = client.NewRvpnConn(s.endpoint.easyConnectClient)

	// Read from VPN server and send to TUN stack
	go func() {
		for {
			buf := make([]byte, MTU)
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
		buf := make([]byte, MTU)
		n, err := s.endpoint.Read(buf)
		if err != nil {
			log.Printf("Error occurred while reading from TUN stack: %v", err)
			// TODO graceful shutdown
			panic(err)
		}

		if n < zctcpip.IPv4PacketMinLength {
			continue
		}

		packet := buf[:n]
		switch ipVersion := packet[0] >> 4; ipVersion {
		case zctcpip.IPv4Version:
			err = s.processIPV4(packet)
		default:
			err = fmt.Errorf("unsupport IP version %d", ipVersion)
		}
		if err != nil {
			log.Printf("Error occurred while processing IP packet: %v", err)
			continue
		}

	}
}

func (s *Stack) processIPV4(packet zctcpip.IPv4Packet) error {
	switch packet.Protocol() {
	case zctcpip.TCP:
		return s.processIPV4TCP(packet, packet.Payload())
	case zctcpip.UDP:
		return s.processIPV4UDP(packet, packet.Payload())
	case zctcpip.ICMP:
		return s.processIPV4ICMP(packet, packet.Payload())
	default:
		return fmt.Errorf("unknown protocol %d", packet[9])
	}
}

func (s *Stack) processIPV4TCP(packet zctcpip.IPv4Packet, _ zctcpip.TCPPacket) error {
	if !packet.DestinationIP().IsGlobalUnicast() {
		return s.endpoint.Write(packet)
	}
	n, err := s.rvpnConn.Write(packet)
	log.DebugPrintf("Send: wrote %d bytes", n)
	log.DebugDumpHex(packet[:n])

	return err
}

func (s *Stack) processIPV4UDP(packet zctcpip.IPv4Packet, udpPacket zctcpip.UDPPacket) error {
	if !packet.DestinationIP().IsGlobalUnicast() {
		return s.endpoint.Write(packet)
	}
	log.Printf("receive  %s:%d -> %s:%d udp", packet.SourceIP(), udpPacket.SourcePort(), packet.DestinationIP(), udpPacket.DestinationPort())

	if s.shouldHijackUDPDns(packet, udpPacket) {
		log.Printf("hijack %s:%d -> %s:%d dns query", packet.SourceIP(), udpPacket.SourcePort(), packet.DestinationIP(), udpPacket.DestinationPort())
		msg := dns.Msg{}
		if err := msg.Unpack(udpPacket.Payload()); err != nil {
			return err
		}
		resMsg, err := s.resolve.HandleDnsMsg(context.Background(), &msg)
		fmt.Println(resMsg.String(), err)
		return nil
	}

	n, err := s.rvpnConn.Write(packet)
	log.DebugPrintf("Send: wrote %d bytes", n)
	log.DebugDumpHex(packet[:n])

	return err
}

func (s *Stack) processIPV4ICMP(packet zctcpip.IPv4Packet, icmpHeader zctcpip.ICMPPacket) error {
	log.Printf("icmp %s -> %s", packet.SourceIP(), packet.DestinationIP())
	if icmpHeader.Type() != zctcpip.ICMPTypePingRequest || icmpHeader.Code() != 0 {
		return nil
	}
	icmpHeader.SetType(zctcpip.ICMPTypePingResponse)
	sourceIP := packet.SourceIP()
	packet.SetSourceIP(packet.DestinationIP())
	packet.SetDestinationIP(sourceIP)

	icmpHeader.ResetChecksum()
	packet.ResetChecksum()

	return s.endpoint.Write(packet)
}

// only can handle udp dns query!
func (s *Stack) shouldHijackUDPDns(ipHeader zctcpip.IPv4Packet, udpHeader zctcpip.UDPPacket) bool {
	if udpHeader.DestinationPort() != 53 {
		return false
	}
	if ipHeader.SourceIP().Equal(s.endpoint.ip) {
		return false
	}
	if !ipHeader.DestinationIP().IsGlobalUnicast() {
		return false
	}

	return true
}
