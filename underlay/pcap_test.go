package underlay

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPCAPCaptureRecordsTCPInBothDirections(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		request := make([]byte, len("hello"))
		if _, readErr := io.ReadFull(conn, request); readErr != nil {
			serverErr <- readErr
			return
		}
		_, writeErr := conn.Write([]byte("world"))
		serverErr <- writeErr
	}()

	path := filepath.Join(t.TempDir(), "underlay.pcap")
	capture, err := newPCAPCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wrapped := capture.Wrap(conn)
	if _, err := wrapped.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("world"))
	if _, err := io.ReadFull(wrapped, reply); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("PCAP permissions = %o, want 600", got)
	}
	packets := parsePCAPPackets(t, data)
	if len(packets) != 2 {
		t.Fatalf("packet count = %d, want 2", len(packets))
	}
	assertIPv4TCPPacket(t, packets[0], "hello")
	assertIPv4TCPPacket(t, packets[1], "world")
	if !bytes.Equal(packets[0][20:22], packets[1][22:24]) ||
		!bytes.Equal(packets[0][22:24], packets[1][20:22]) {
		t.Fatal("capture did not reverse source and destination ports")
	}
}

func TestNewReportsPCAPInitializationError(t *testing.T) {
	_, err := New(Options{
		AutoDetect:    false,
		DebugPCAPFile: filepath.Join(t.TempDir(), "missing", "capture.pcap"),
	})
	if err == nil || !strings.Contains(err.Error(), "initialize underlay PCAP capture") {
		t.Fatalf("New error = %v, want PCAP initialization error", err)
	}
}

func TestPCAPCaptureQueueBlocksUntilSpaceIsAvailable(t *testing.T) {
	capture := &pcapCapture{events: make(chan captureEvent, 1)}
	if err := capture.enqueue(captureEvent{}); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		result <- capture.enqueue(captureEvent{})
	}()
	<-started
	select {
	case err := <-result:
		t.Fatalf("enqueue returned before queue space was available: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	<-capture.events
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue remained blocked after queue space became available")
	}
}

func TestPCAPCaptureConcurrentClose(t *testing.T) {
	capture, err := newPCAPCapture(filepath.Join(t.TempDir(), "capture.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- capture.Close()
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPCAPCaptureSplitsLargePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	capture, err := newPCAPCapture(path)
	if err != nil {
		t.Fatal(err)
	}
	conn := &pcapConn{
		capture: capture,
		connID:  1,
		local:   &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		remote:  &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
	}
	payload := bytes.Repeat([]byte{0xab}, maxTCPPayload*2+1)
	conn.capturePayload(captureOutgoing, payload, time.Now())
	if err := capture.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	packets := parsePCAPPackets(t, data)
	if len(packets) != 3 {
		t.Fatalf("packet count = %d, want 3", len(packets))
	}
	for i, want := range []int{maxTCPPayload, maxTCPPayload, 1} {
		if got := len(packets[i]) - 40; got != want {
			t.Fatalf("packet %d payload length = %d, want %d", i, got, want)
		}
	}
}

func TestPCAPCaptureReturnsBackgroundWriteError(t *testing.T) {
	capture, err := newPCAPCapture(filepath.Join(t.TempDir(), "capture.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := capture.enqueue(captureEvent{
		connID:    1,
		direction: captureOutgoing,
		timestamp: time.Now(),
		local:     &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345},
		remote:    &net.TCPAddr{IP: net.ParseIP("198.51.100.2"), Port: 443},
		payload:   []byte("payload"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := capture.Close(); err == nil {
		t.Fatal("Close returned nil after the capture file became unwritable")
	}
}

func parsePCAPPackets(t *testing.T, data []byte) [][]byte {
	t.Helper()
	if len(data) < 24 {
		t.Fatalf("PCAP length = %d, want at least 24", len(data))
	}
	if got := binary.LittleEndian.Uint32(data[0:4]); got != 0xa1b2c3d4 {
		t.Fatalf("PCAP magic = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(data[20:24]); got != pcapLinkTypeRaw {
		t.Fatalf("PCAP link type = %d, want %d", got, pcapLinkTypeRaw)
	}

	var packets [][]byte
	for offset := 24; offset < len(data); {
		if len(data)-offset < 16 {
			t.Fatalf("truncated PCAP record header at %d", offset)
		}
		length := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		offset += 16
		if length < 0 || len(data)-offset < length {
			t.Fatalf("truncated PCAP packet at %d", offset)
		}
		packets = append(packets, data[offset:offset+length])
		offset += length
	}
	return packets
}

func assertIPv4TCPPacket(t *testing.T, packet []byte, payload string) {
	t.Helper()
	if len(packet) != 40+len(payload) {
		t.Fatalf("packet length = %d, want %d", len(packet), 40+len(payload))
	}
	if packet[0]>>4 != 4 || packet[9] != 6 {
		t.Fatalf("packet is not IPv4/TCP: version=%d protocol=%d", packet[0]>>4, packet[9])
	}
	if checksum(packet[:20]) != 0 {
		t.Fatal("invalid IPv4 header checksum")
	}
	pseudo := make([]byte, 12+len(packet)-20)
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
	copy(pseudo[12:], packet[20:])
	if checksum(pseudo) != 0 {
		t.Fatal("invalid TCP checksum")
	}
	if got := string(packet[40:]); got != payload {
		t.Fatalf("TCP payload = %q, want %q", got, payload)
	}
}
