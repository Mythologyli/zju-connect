package atrust

import (
	"fmt"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"github.com/mythologyli/zju-connect/log"
)

func (t *L3Tunnel) processIPv6(packet zctcpip.IPv6Packet) error {
	meta, protocol, port, err := buildIPv6PacketMeta(packet)
	if err != nil {
		return err
	}
	resource, ok := t.resourceIndex.Match(meta.dstIP, protocol, port)
	if !ok {
		if port >= 0 {
			return fmt.Errorf("%s:%d, [%s]: %w", meta.dstIP, port, protocol, client.ErrResourceNotFound)
		}
		return fmt.Errorf("%s, [%s]: %w", meta.dstIP, protocol, client.ErrResourceNotFound)
	}
	meta.key = connTrackKey(meta)
	log.DebugPrintf("l3-tunnel send IPv6 packet appID=%s group=%s len=%d", resource.AppID, resource.NodeGroupID, len(packet))
	return t.writePacketWithMeta(packet, meta, resource.AppID, resource.NodeGroupID)
}

func buildIPv6PacketMeta(packet zctcpip.IPv6Packet) (packetMeta, string, int, error) {
	next, payload, err := packet.TransportPayload()
	if err != nil {
		return packetMeta{}, "", -1, err
	}
	meta := packetMeta{
		atype: 6,
		proto: int(next),
		srcIP: packet.SourceIP(),
		dstIP: packet.DestinationIP(),
	}
	switch next {
	case zctcpip.TCP:
		tcp := zctcpip.TCPPacket(payload)
		if !tcp.Valid() {
			return packetMeta{}, "", -1, fmt.Errorf("invalid IPv6 TCP packet")
		}
		meta.srcPort, meta.dstPort = tcp.SourcePort(), tcp.DestinationPort()
		return meta, "tcp", int(meta.dstPort), nil
	case zctcpip.UDP:
		udp := zctcpip.UDPPacket(payload)
		if !udp.Valid() {
			return packetMeta{}, "", -1, fmt.Errorf("invalid IPv6 UDP packet")
		}
		meta.srcPort, meta.dstPort = udp.SourcePort(), udp.DestinationPort()
		return meta, "udp", int(meta.dstPort), nil
	case zctcpip.ICMPv6:
		return meta, "icmp", -1, nil
	default:
		return packetMeta{}, "", -1, fmt.Errorf("unsupported IPv6 protocol %d", next)
	}
}
