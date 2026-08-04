package gvisor

import (
	"bytes"
	"testing"
)

var joinedPacketSink []byte

func TestJoinPacketSlicesPreservesContent(t *testing.T) {
	slices := [][]byte{{0x45, 0x00}, {}, {0x12, 0x34, 0x56}, {0x78}}
	want := []byte{0x45, 0x00, 0x12, 0x34, 0x56, 0x78}
	if got := joinPacketSlices(slices); !bytes.Equal(got, want) {
		t.Fatalf("joinPacketSlices() = % X, want % X", got, want)
	}
}

func TestInboundPacketBufferPreservesReadBytes(t *testing.T) {
	buf := []byte{0x45, 0x00, 0x12, 0x34, 0x00, 0x00}
	const bytesRead = 4
	packet := makeInboundPacketBuffer(buf, bytesRead)
	defer packet.DecRef()
	got := joinPacketSlices(packet.AsSlices())
	if !bytes.Equal(got[:bytesRead], buf[:bytesRead]) {
		t.Fatalf("packet prefix = % X, want % X", got[:bytesRead], buf[:bytesRead])
	}
}

func TestInboundPacketBufferExcludesUnreadCapacity(t *testing.T) {
	buf := []byte{0x45, 0x00, 0x12, 0x34, 0xde, 0xad}
	const bytesRead = 4
	packet := makeInboundPacketBuffer(buf, bytesRead)
	defer packet.DecRef()

	got := joinPacketSlices(packet.AsSlices())
	if !bytes.Equal(got, buf[:bytesRead]) {
		t.Fatalf("packet = % X, want only read bytes % X", got, buf[:bytesRead])
	}
}

func TestJoinPacketSlicesAllocatesOnce(t *testing.T) {
	slices := [][]byte{make([]byte, 20), make([]byte, 20), make([]byte, 1160)}
	if allocs := testing.AllocsPerRun(1000, func() { joinedPacketSink = joinPacketSlices(slices) }); allocs != 1 {
		t.Fatalf("joinPacketSlices allocations = %v, want 1", allocs)
	}
}

func BenchmarkJoinPacketSlices(b *testing.B) {
	slices := [][]byte{make([]byte, 20), make([]byte, 20), make([]byte, 1160)}
	b.ReportAllocs()
	b.SetBytes(1200)
	for i := 0; i < b.N; i++ {
		joinedPacketSink = joinPacketSlices(slices)
	}
}
