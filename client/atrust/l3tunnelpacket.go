package atrust

import (
	"bytes"
	"fmt"

	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"github.com/mythologyli/zju-connect/log"
)

func (t *L3Tunnel) processIPV4(packet zctcpip.IPv4Packet) error {
	protocol := ""
	port := -1
	switch packet.Protocol() {
	case zctcpip.TCP:
		protocol = "tcp"
		port = int(zctcpip.TCPPacket(packet.Payload()).DestinationPort())
	case zctcpip.UDP:
		protocol = "udp"
		port = int(zctcpip.UDPPacket(packet.Payload()).DestinationPort())
	case zctcpip.ICMP:
		protocol = "icmp"
	default:
		return fmt.Errorf("protocol %d not supported, skip", packet.Protocol())
	}

	for _, resource := range t.ipResources {
		if bytes.Compare(packet.DestinationIP(), resource.IPMin) >= 0 && bytes.Compare(packet.DestinationIP(), resource.IPMax) <= 0 {
			if resource.Protocol == protocol || resource.Protocol == "all" {
				if protocol == "icmp" {
					return t.writePacket(packet, resource.AppID, resource.NodeGroupID)
				}

				if resource.PortMin <= port && port <= resource.PortMax {
					return t.writePacket(packet, resource.AppID, resource.NodeGroupID)
				}
			}
		}
	}

	if port != -1 {
		return fmt.Errorf("no VPN resources found for %s:%d, [%s], skip", packet.DestinationIP(), port, protocol)
	}
	return fmt.Errorf("no VPN resources found for %s, [%s], skip", packet.DestinationIP(), protocol)
}

func (t *L3Tunnel) writePacket(packet zctcpip.IPv4Packet, appID, nodeGroupID string) error {
	meta, err := buildPacketMeta(packet)
	if err != nil {
		return err
	}
	meta.key = connTrackKey(meta)

	conn, err := t.getConn(nodeGroupID)
	if err != nil {
		return err
	}
	log.DebugPrintf("atrust-l3: send packet appID=%s group=%s len=%d", appID, nodeGroupID, len(packet))
	logPacket("send", packet)
	return conn.WritePacket(meta, appID, nodeGroupID, packet)
}

func buildPacketMeta(packet zctcpip.IPv4Packet) (packetMeta, error) {
	if packet.Protocol() == zctcpip.ICMP {
		return packetMeta{
			atype:   4,
			proto:   int(packet.Protocol()),
			srcIP:   packet.SourceIP(),
			dstIP:   packet.DestinationIP(),
			srcPort: 0,
			dstPort: 0,
		}, nil
	}

	var srcPort, dstPort uint16
	switch packet.Protocol() {
	case zctcpip.TCP:
		tcpPacket := zctcpip.TCPPacket(packet.Payload())
		srcPort = tcpPacket.SourcePort()
		dstPort = tcpPacket.DestinationPort()
	case zctcpip.UDP:
		udpPacket := zctcpip.UDPPacket(packet.Payload())
		srcPort = udpPacket.SourcePort()
		dstPort = udpPacket.DestinationPort()
	default:
		return packetMeta{}, fmt.Errorf("unsupported protocol %d", packet.Protocol())
	}

	return packetMeta{
		atype:   4,
		proto:   int(packet.Protocol()),
		srcIP:   packet.SourceIP(),
		dstIP:   packet.DestinationIP(),
		srcPort: srcPort,
		dstPort: dstPort,
	}, nil
}

func logPacket(direction string, packet []byte) {
	if len(packet) == 0 {
		log.DebugPrintf("atrust-l3: %s packet len=0", direction)
		return
	}

	version := packet[0] >> 4
	switch version {
	case zctcpip.IPv4Version:
		ipHeader := zctcpip.IPv4Packet(packet)
		if !ipHeader.Valid() {
			log.DebugPrintf("atrust-l3: %s ipv4 invalid len=%d", direction, len(packet))
			log.DebugDumpHex(packet)
			return
		}
		switch ipHeader.Protocol() {
		case zctcpip.TCP:
			payload := ipHeader.Payload()
			if len(payload) < zctcpip.TCPHeaderSize {
				log.DebugPrintf("atrust-l3: %s tcp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			tcpHeader := zctcpip.TCPPacket(payload)
			if !tcpHeader.Valid() {
				log.DebugPrintf("atrust-l3: %s tcp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			log.DebugPrintf("atrust-l3: %s tcp %s:%d -> %s:%d len=%d", direction, ipHeader.SourceIP(), tcpHeader.SourcePort(), ipHeader.DestinationIP(), tcpHeader.DestinationPort(), len(packet))
		case zctcpip.UDP:
			payload := ipHeader.Payload()
			if len(payload) < zctcpip.UDPHeaderSize {
				log.DebugPrintf("atrust-l3: %s udp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			udpHeader := zctcpip.UDPPacket(payload)
			if !udpHeader.Valid() {
				log.DebugPrintf("atrust-l3: %s udp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			log.DebugPrintf("atrust-l3: %s udp %s:%d -> %s:%d len=%d", direction, ipHeader.SourceIP(), udpHeader.SourcePort(), ipHeader.DestinationIP(), udpHeader.DestinationPort(), len(packet))
		case zctcpip.ICMP:
			log.DebugPrintf("atrust-l3: %s icmp %s -> %s len=%d", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
		default:
			log.DebugPrintf("atrust-l3: %s proto %d %s -> %s len=%d", direction, ipHeader.Protocol(), ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
		}
	case 6:
		log.DebugPrintf("atrust-l3: %s ipv6 len=%d", direction, len(packet))
	default:
		log.DebugPrintf("atrust-l3: %s ipver %d len=%d", direction, version, len(packet))
	}
	log.DebugDumpHex(packet)
}
