package zctcpip

import (
	"encoding/binary"
	"testing"
)

func TestIPv6TransportPayloadSkipsExtensionHeaders(t *testing.T) {
	packet := make(IPv6Packet, IPv6HeaderSize+8+TCPHeaderSize)
	packet[0] = IPv6Version << 4
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-IPv6HeaderSize))
	packet[6] = 0
	packet[IPv6HeaderSize] = TCP
	packet[IPv6HeaderSize+1] = 0
	tcp := TCPPacket(packet[IPv6HeaderSize+8:])
	tcp[12] = 5 << 4

	protocol, payload, err := packet.TransportPayload()
	if err != nil {
		t.Fatalf("TransportPayload() error = %v", err)
	}
	if protocol != TCP || len(payload) != TCPHeaderSize {
		t.Fatalf("TransportPayload() = %d, %d bytes, want TCP and %d bytes", protocol, len(payload), TCPHeaderSize)
	}
}
