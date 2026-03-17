package atrust

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/mythologyli/zju-connect/client"
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
		return fmt.Errorf("protocol %d: %w", packet.Protocol(), client.ErrResourceNotFound)
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
		return fmt.Errorf("%s:%d, [%s]: %w", packet.DestinationIP(), port, protocol, client.ErrResourceNotFound)
	}
	return fmt.Errorf("%s, [%s]: %w", packet.DestinationIP(), protocol, client.ErrResourceNotFound)
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
	log.DebugPrintf("l3-tunnel send packet appID=%s group=%s len=%d", appID, nodeGroupID, len(packet))
	logPacket("send", packet)
	err = conn.WritePacket(meta, appID, nodeGroupID, packet)
	for retry := 0; retry < 5 && isClosedConnErr(err); retry++ {
		// If the cached tunnel conn was closed by network flaps, evict it and retry.
		log.Println("Write packet failed with closed connection, evicting conn and retrying...")
		t.evictConn(nodeGroupID, conn)
		retryConn, retryErr := t.getConn(nodeGroupID)
		if retryErr != nil {
			return retryErr
		}
		conn = retryConn
		err = conn.WritePacket(meta, appID, nodeGroupID, packet)
	}
	return err
}

func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
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
		log.DebugPrintf("l3-tunnel %s packet len=0", direction)
		return
	}

	version := packet[0] >> 4
	switch version {
	case zctcpip.IPv4Version:
		ipHeader := zctcpip.IPv4Packet(packet)
		if !ipHeader.Valid() {
			log.DebugPrintf("l3-tunnel %s ipv4 invalid len=%d", direction, len(packet))
			log.DebugDumpHex(packet)
			return
		}
		switch ipHeader.Protocol() {
		case zctcpip.TCP:
			payload := ipHeader.Payload()
			if len(payload) < zctcpip.TCPHeaderSize {
				log.DebugPrintf("l3-tunnel %s tcp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			tcpHeader := zctcpip.TCPPacket(payload)
			if !tcpHeader.Valid() {
				log.DebugPrintf("l3-tunnel %s tcp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			log.DebugPrintf("l3-tunnel %s tcp %s:%d -> %s:%d len=%d", direction, ipHeader.SourceIP(), tcpHeader.SourcePort(), ipHeader.DestinationIP(), tcpHeader.DestinationPort(), len(packet))
		case zctcpip.UDP:
			payload := ipHeader.Payload()
			if len(payload) < zctcpip.UDPHeaderSize {
				log.DebugPrintf("l3-tunnel %s udp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			udpHeader := zctcpip.UDPPacket(payload)
			if !udpHeader.Valid() {
				log.DebugPrintf("l3-tunnel %s udp %s -> %s len=%d invalid", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
				log.DebugDumpHex(packet)
				return
			}
			log.DebugPrintf("l3-tunnel %s udp %s:%d -> %s:%d len=%d", direction, ipHeader.SourceIP(), udpHeader.SourcePort(), ipHeader.DestinationIP(), udpHeader.DestinationPort(), len(packet))
		case zctcpip.ICMP:
			log.DebugPrintf("l3-tunnel %s icmp %s -> %s len=%d", direction, ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
		default:
			log.DebugPrintf("l3-tunnel %s proto %d %s -> %s len=%d", direction, ipHeader.Protocol(), ipHeader.SourceIP(), ipHeader.DestinationIP(), len(packet))
		}
	case 6:
		log.DebugPrintf("l3-tunnel %s ipv6 len=%d", direction, len(packet))
	default:
		log.DebugPrintf("l3-tunnel %s ipver %d len=%d", direction, version, len(packet))
	}
	log.DebugDumpHex(packet)
}
