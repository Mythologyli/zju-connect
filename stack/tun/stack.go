//go:build !android

package tun

import (
	"bytes"
	"context"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"io"

	tun "github.com/cxz66666/sing-tun"
	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"github.com/mythologyli/zju-connect/log"
)

const MTU uint32 = 1400

type Stack struct {
	endpoint    *Endpoint
	rvpnConn    io.ReadWriteCloser
	resolve     zcdns.LocalServer
	ipResources []client.IPResource
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) Run() {
	var connErr error
	s.rvpnConn, connErr = easyconnect.NewRvpnConn(s.endpoint.easyConnectClient)
	if connErr != nil {
		panic(connErr)
	}
	// Read from VPN server and send to TUN stack
	go func() {
		for {
			buf := make([]byte, MTU+tun.PacketOffset)
			n, err := s.rvpnConn.Read(buf)
			if err != nil {
				panic(err)
			}
			log.DebugPrintf("Recv: read %d bytes", n)
			log.DebugDumpHex(buf[:n])

			err = s.endpoint.Write(buf[:n])
			if err != nil {
				if hook_func.IsTerminal() {
					return
				} else {
					log.Printf("Error occurred while writing to TUN stack: %v", err)
					panic(err)
				}
			}
		}
	}()

	// Read from TUN stack and send to VPN server
	for {
		buf := make([]byte, MTU+tun.PacketOffset)
		n, err := s.endpoint.Read(buf)
		if err != nil {
			if hook_func.IsTerminal() {
				return
			} else {
				log.Printf("Error occurred while reading from TUN stack: %v", err)
				panic(err)
			}
		}

		if n < zctcpip.IPv4PacketMinLength {
			continue
		}

		// whether this should be a blocking operation?
		packet := buf[tun.PacketOffset:n]
		switch ipVersion := packet[0] >> 4; ipVersion {
		case zctcpip.IPv4Version:
			err = s.processIPV4(packet)
		default:
			err = fmt.Errorf("unsupport IP version %d", ipVersion)
		}
		if err != nil {
			log.DebugPrintf("Error occurred while processing IP packet: %v", err)
			continue
		}

	}
}

func (s *Stack) processIPV4(packet zctcpip.IPv4Packet) error {
	protocol := ""
	port := -1
	switch packet.Protocol() {
	case zctcpip.TCP:
		protocol = "tcp"
		port = int(zctcpip.TCPPacket(packet.Payload()).DestinationPort())
	case zctcpip.UDP:
		udpPacket := zctcpip.UDPPacket(packet.Payload())
		if s.shouldHijackUDPDns(packet, udpPacket) {
			newPacket := make(zctcpip.IPv4Packet, len(packet))
			copy(newPacket, packet)
			newUdpPacket := zctcpip.UDPPacket(newPacket.Payload())
			// need to be non-blocking
			go s.doHijackUDPDns(newPacket, newUdpPacket)
			return nil
		}

		protocol = "udp"
		port = int(zctcpip.UDPPacket(packet.Payload()).DestinationPort())
	case zctcpip.ICMP:
		protocol = "icmp"
	default:
		return fmt.Errorf("protocol %d not supported, skip", packet.Protocol())
	}

	for _, resource := range s.ipResources {
		if bytes.Compare(packet.DestinationIP(), resource.IPMin) >= 0 && bytes.Compare(packet.DestinationIP(), resource.IPMax) <= 0 {
			if resource.Protocol == protocol || resource.Protocol == "all" {
				if protocol == "icmp" {
					return s.processIPV4ICMP(packet, packet.Payload())
				}

				if resource.PortMin <= port && port <= resource.PortMax {
					if protocol == "tcp" {
						return s.processIPV4TCP(packet, packet.Payload())
					} else {
						return s.processIPV4UDP(packet, packet.Payload())
					}
				}
			}
		}
	}

	if port != -1 {
		return fmt.Errorf("no VPN resources found for %s:%d, [%s], skip", packet.DestinationIP(), port, protocol)
	} else {
		return fmt.Errorf("no VPN resources found for %s, [%s], skip", packet.DestinationIP(), protocol)
	}
}

func (s *Stack) processIPV4TCP(packet zctcpip.IPv4Packet, tcpPacket zctcpip.TCPPacket) error {
	log.DebugPrintf("receive tcp %s:%d -> %s:%d", packet.SourceIP(), tcpPacket.SourcePort(), packet.DestinationIP(), tcpPacket.DestinationPort())

	if !packet.DestinationIP().IsGlobalUnicast() {
		return s.endpoint.Write(packet)
	}
	n, err := s.rvpnConn.Write(packet)
	if err != nil {
		panic(err)
	}
	log.DebugPrintf("Send: wrote %d bytes", n)
	log.DebugDumpHex(packet[:n])

	return err
}

func (s *Stack) processIPV4UDP(packet zctcpip.IPv4Packet, udpPacket zctcpip.UDPPacket) error {
	log.DebugPrintf("receive udp %s:%d -> %s:%d", packet.SourceIP(), udpPacket.SourcePort(), packet.DestinationIP(), udpPacket.DestinationPort())

	if !packet.DestinationIP().IsGlobalUnicast() {
		return s.endpoint.Write(packet)
	}

	n, err := s.rvpnConn.Write(packet)
	if err != nil {
		panic(err)
	}
	log.DebugPrintf("Send: wrote %d bytes", n)
	log.DebugDumpHex(packet[:n])

	return err
}

func (s *Stack) processIPV4ICMP(packet zctcpip.IPv4Packet, icmpHeader zctcpip.ICMPPacket) error {
	log.DebugPrintf("receive icmp %s -> %s", packet.SourceIP(), packet.DestinationIP())
	if icmpHeader.Code() != 0 {
		return nil
	}

	n, err := s.rvpnConn.Write(packet)
	if err != nil {
		panic(err)
	}
	log.DebugPrintf("Send: wrote %d bytes", n)
	log.DebugDumpHex(packet[:n])

	return err
}

// only can handle udp dns query!
func (s *Stack) shouldHijackUDPDns(ipHeader zctcpip.IPv4Packet, udpHeader zctcpip.UDPPacket) bool {
	if udpHeader.DestinationPort() != 53 {
		return false
	}
	return s.resolve.CheckDnsHijack(ipHeader.DestinationIP())
}

func (s *Stack) doHijackUDPDns(ipHeader zctcpip.IPv4Packet, udpHeader zctcpip.UDPPacket) {
	log.DebugPrintf("hijack dns %s:%d -> %s:%d", ipHeader.SourceIP(), udpHeader.SourcePort(), ipHeader.DestinationIP(), udpHeader.DestinationPort())
	msg := dns.Msg{}
	if err := msg.Unpack(udpHeader.Payload()); err != nil {
		log.Printf("unpack dns msg error: %v", err)
		return
	}
	resMsg, err := s.resolve.HandleDnsMsg(context.Background(), &msg)
	if err != nil {
		log.Printf("hijack dns %s:%d -> %s:%d error: %v", ipHeader.SourceIP(), udpHeader.SourcePort(), ipHeader.DestinationIP(), udpHeader.DestinationPort(), err)
		return
	}

	resByte, err := resMsg.Pack()
	if err != nil {
		log.Printf("pack dns msg error: %v", err)
		return
	}

	totalLen := int(ipHeader.HeaderLen()) + zctcpip.UDPHeaderSize + len(resByte)

	newPacket := make(zctcpip.IPv4Packet, totalLen)
	copy(newPacket, ipHeader[:ipHeader.HeaderLen()])
	newPacket.SetTotalLength(uint16(totalLen))
	newPacket.SetSourceIP(ipHeader.DestinationIP())
	newPacket.SetDestinationIP(ipHeader.SourceIP())

	newUDPHeader := zctcpip.UDPPacket(newPacket.Payload())
	newUDPHeader.SetSourcePort(udpHeader.DestinationPort())
	newUDPHeader.SetDestinationPort(udpHeader.SourcePort())
	newUDPHeader.SetLength(zctcpip.UDPHeaderSize + uint16(len(resByte)))
	copy(newUDPHeader.Payload(), resByte)

	newUDPHeader.ResetChecksum(newPacket.PseudoSum())
	newPacket.ResetChecksum()
	_ = s.endpoint.Write(newPacket)
}
