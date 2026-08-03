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
