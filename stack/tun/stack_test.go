//go:build !android

package tun

import (
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type recordingNetworkDispatcher struct {
	packet *stack.PacketBuffer
}

func (d *recordingNetworkDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, packet *stack.PacketBuffer) {
	d.packet = packet
}

func (*recordingNetworkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func TestProcessIPV4TCPReleasesPacketBuffer(t *testing.T) {
	dispatcher := &recordingNetworkDispatcher{}
	s := &Stack{
		endpoint:            &Endpoint{client: &atrust.Client{}},
		tcpListenerEndpoint: &TCPListenerEndpoint{dispatcher: dispatcher},
	}

	packet := make(zctcpip.IPv4Packet, zctcpip.IPv4HeaderSize+zctcpip.TCPHeaderSize)
	packet[0] = zctcpip.IPv4Version << 4
	packet.SetHeaderLen(zctcpip.IPv4HeaderSize)
	packet.SetTotalLength(uint16(len(packet)))
	packet.SetProtocol(zctcpip.TCP)
	packet.SetSourceIP(net.IPv4(192, 0, 2, 1))
	packet.SetDestinationIP(net.IPv4(198, 51, 100, 1))
	tcpPacket := zctcpip.TCPPacket(packet.Payload())
	tcpPacket.SetSourcePort(12345)
	tcpPacket.SetDestinationPort(443)

	if err := s.processIPV4TCP(packet, tcpPacket); err != nil {
		t.Fatalf("processIPV4TCP() error = %v", err)
	}
	if dispatcher.packet == nil {
		t.Fatal("packet was not delivered to TCP listener stack")
	}
	if refs := dispatcher.packet.ReadRefs(); refs != 0 {
		t.Fatalf("PacketBuffer refs after delivery = %d, want 0", refs)
	}
}
