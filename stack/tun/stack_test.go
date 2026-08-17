//go:build !android

package tun

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type recordingNetworkDispatcher struct {
	packet *stack.PacketBuffer
}

type recordingL3Conn struct {
	packet []byte
}

func (*recordingL3Conn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingL3Conn) Write(packet []byte) (int, error) {
	c.packet = append(c.packet[:0], packet...)
	return len(packet), nil
}

func (*recordingL3Conn) Close() error { return nil }

func TestStaticResourceMatchBoundaries(t *testing.T) {
	s := &Stack{ipResources: []client.IPResource{
		{IPMin: net.IPv4(10, 0, 0, 10), IPMax: net.IPv4(10, 0, 0, 20), PortMin: 80, PortMax: 90, Protocol: "tcp"},
		{IPMin: net.IPv4(192, 0, 2, 1), IPMax: net.IPv4(192, 0, 2, 1), PortMin: 0, PortMax: 65535, Protocol: "all"},
	}}
	tests := []struct {
		name     string
		ip       net.IP
		protocol string
		port     int
		want     bool
	}{
		{name: "range start", ip: net.IPv4(10, 0, 0, 10), protocol: "tcp", port: 80, want: true},
		{name: "range end", ip: net.IPv4(10, 0, 0, 20), protocol: "tcp", port: 90, want: true},
		{name: "below range", ip: net.IPv4(10, 0, 0, 9), protocol: "tcp", port: 80},
		{name: "port excluded", ip: net.IPv4(10, 0, 0, 15), protocol: "tcp", port: 443},
		{name: "protocol excluded", ip: net.IPv4(10, 0, 0, 15), protocol: "udp", port: 80},
		{name: "all protocol", ip: net.IPv4(192, 0, 2, 1), protocol: "icmp", port: -1, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := s.matchesStaticResource(test.ip, test.protocol, test.port); got != test.want {
				t.Fatalf("matchesStaticResource(%s, %s, %d) = %t, want %t", test.ip, test.protocol, test.port, got, test.want)
			}
		})
	}
}

func TestStaticResourceDecisionCacheIsBounded(t *testing.T) {
	s := &Stack{}
	for port := 0; port < resourceDecisionCacheSize+1000; port++ {
		_ = s.matchesStaticResource(net.IPv4(203, 0, 113, 1), "tcp", port)
	}
	s.resourceCache.mu.RLock()
	defer s.resourceCache.mu.RUnlock()
	if entries := len(s.resourceCache.values); entries > resourceDecisionCacheSize {
		t.Fatalf("resource decision cache entries = %d, want at most %d", entries, resourceDecisionCacheSize)
	}
}

func BenchmarkStaticResourceMatch(b *testing.B) {
	for _, resourceCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", resourceCount), func(b *testing.B) {
			resources := make([]client.IPResource, resourceCount)
			for i := range resources {
				ip := net.IPv4(10, byte(i>>8), byte(i), 1)
				resources[i] = client.IPResource{IPMin: ip, IPMax: ip, PortMin: 443, PortMax: 443, Protocol: "tcp"}
			}
			s := &Stack{ipResources: resources}
			target := resources[len(resources)-1].IPMin
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !s.matchesStaticResource(target, "tcp", 443) {
					b.Fatal("target did not match")
				}
			}
		})
	}
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

	if err := s.processIPV4TCP(packet, tcpPacket, true); err != nil {
		t.Fatalf("processIPV4TCP() error = %v", err)
	}
	if dispatcher.packet == nil {
		t.Fatal("packet was not delivered to TCP listener stack")
	}
	if refs := dispatcher.packet.ReadRefs(); refs != 0 {
		t.Fatalf("PacketBuffer refs after delivery = %d, want 0", refs)
	}
}

func TestProcessIPV4TCPPreferringL3BypassesTCPListener(t *testing.T) {
	dispatcher := &recordingNetworkDispatcher{}
	l3Conn := &recordingL3Conn{}
	s := &Stack{
		endpoint:            &Endpoint{client: &atrust.Client{}},
		tcpListenerEndpoint: &TCPListenerEndpoint{dispatcher: dispatcher},
		l3Conn:              l3Conn,
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

	if err := s.processIPV4TCP(packet, tcpPacket, false); err != nil {
		t.Fatalf("processIPV4TCP() error = %v", err)
	}
	if dispatcher.packet != nil {
		t.Fatal("TCP-prefers-L3 packet was delivered to TCP listener")
	}
	if !bytes.Equal(l3Conn.packet, packet) {
		t.Fatalf("L3 packet = %x, want %x", l3Conn.packet, packet)
	}
}
