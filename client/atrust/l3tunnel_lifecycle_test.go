package atrust

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	zlog "github.com/mythologyli/zju-connect/log"
)

func TestForwardFromConnPreservesPacket(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		incoming:     make(chan []byte, 1),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel := &L3Tunnel{
		conns:    map[string]*l3TunnelConn{"group": conn},
		dataChan: make(chan []byte, 1),
		closeCh:  make(chan struct{}),
	}
	want := makeUDPPacket(12345, 53)
	done := make(chan struct{})
	go func() {
		tunnel.forwardFromConn("group", conn)
		close(done)
	}()
	conn.incoming <- want

	select {
	case got := <-tunnel.dataChan:
		if !bytes.Equal(got, want) {
			t.Fatalf("forwarded packet = % X, want % X", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("packet was not forwarded")
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not stop after connection close")
	}
}

func TestForwardFromConnStopsWhenTunnelClosesWithFullQueue(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		incoming:     make(chan []byte),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel := &L3Tunnel{
		conns:    map[string]*l3TunnelConn{"group": conn},
		dataChan: make(chan []byte, 1),
		closeCh:  make(chan struct{}),
	}
	tunnel.dataChan <- []byte("queue full")
	done := make(chan struct{})
	go func() {
		tunnel.forwardFromConn("group", conn)
		close(done)
	}()
	sent := make(chan struct{})
	go func() {
		conn.incoming <- makeUDPPacket(12345, 53)
		close(sent)
	}()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("forwarder did not receive packet")
	}

	tunnel.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwarder remained blocked after tunnel close")
	}
}

func TestReadLoopDropsDataWhenIncomingQueueIsFull(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	frameData := []byte{l3Version, cmdDataResp, 0x00, 0x01, 0x45}
	conn := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		reader:       bufio.NewReader(bytes.NewReader(frameData)),
		incoming:     make(chan []byte, 1),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	conn.incoming <- []byte("already queued")
	go conn.readLoop()

	select {
	case <-conn.closeCh:
	case <-time.After(time.Second):
		t.Fatal("read loop stopped consuming frames when data queue was full")
	}
	if got := len(conn.incoming); got != 1 {
		t.Fatalf("incoming queue length = %d, want 1", got)
	}
}

func TestLogPacketDisabledAllocatesNothing(t *testing.T) {
	zlog.DisableDebug()
	packet := makeUDPPacket(12345, 53)
	if allocations := testing.AllocsPerRun(1000, func() {
		logPacket("send", packet)
	}); allocations != 0 {
		t.Fatalf("disabled logPacket allocations = %v, want 0", allocations)
	}
}

func TestPooledDataPayloadPreservesWireFormat(t *testing.T) {
	got := getDataPayload("x", []byte{1, 2, 3})
	want := []byte{l3Version, cmdDataReq, 0x01, 'x', 0x00, 0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(got.payload, want) {
		t.Fatalf("pooled payload = % X, want % X", got.payload, want)
	}
	putDataPayload(got)

	next := getDataPayload("yz", []byte{4, 5})
	wantNext := []byte{l3Version, cmdDataReq, 0x02, 'y', 'z', 0x00, 0x00, 0x01, 0x00, 0x02, 0x04, 0x05}
	if !bytes.Equal(next.payload, wantNext) {
		t.Fatalf("reused payload = % X, want % X", next.payload, wantNext)
	}
	putDataPayload(next)
}

func BenchmarkGetDataPayload(b *testing.B) {
	packet := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for i := 0; i < b.N; i++ {
		payload := getDataPayload("connect-token", packet)
		putDataPayload(payload)
	}
}

func TestL3ConnWritePreservesLengthAndResourceError(t *testing.T) {
	tunnel := &L3Tunnel{resourceIndex: ipresource.New(nil), closeCh: make(chan struct{})}
	conn := &L3Conn{l3Tunnel: tunnel, closeCh: make(chan struct{})}
	packet := makeUDPPacket(12345, 53)

	n, err := conn.Write(packet)
	if n != len(packet) {
		t.Fatalf("Write() length = %d, want %d", n, len(packet))
	}
	if !errors.Is(err, client.ErrResourceNotFound) {
		t.Fatalf("Write() error = %v, want resource-not-found", err)
	}
}

func TestL3ConnWritesDoNotBlockUnrelatedFlows(t *testing.T) {
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	conn := &L3Conn{l3Tunnel: &L3Tunnel{closeCh: make(chan struct{})}, closeCh: make(chan struct{}), writePacket: func(packet []byte) error {
		if packet[0] == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		return nil
	}}

	firstDone := make(chan struct{})
	go func() {
		_, _ = conn.Write([]byte{1})
		close(firstDone)
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first write did not start")
	}

	secondDone := make(chan struct{})
	go func() {
		_, _ = conn.Write([]byte{2})
		close(secondDone)
	}()
	select {
	case <-secondDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("unrelated write was blocked by the first flow")
	}

	close(releaseFirst)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first write did not finish")
	}
}

func TestL3ConnCloseUnblocksRead(t *testing.T) {
	tunnel := &L3Tunnel{dataChan: make(chan []byte), closeCh: make(chan struct{})}
	conn := &L3Conn{l3Tunnel: tunnel, closeCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1500))
		done <- err
	}()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

func TestL3TunnelCloseUnblocksL3ConnRead(t *testing.T) {
	tunnel := &L3Tunnel{
		conns:    make(map[string]*l3TunnelConn),
		dataChan: make(chan []byte),
		closeCh:  make(chan struct{}),
	}
	conn := &L3Conn{l3Tunnel: tunnel, closeCh: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1500))
		done <- err
	}()

	tunnel.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read() error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel close did not unblock Read")
	}
}

func TestEvictConnClosesRemovedTunnel(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel := &L3Tunnel{conns: map[string]*l3TunnelConn{"group": conn}}

	tunnel.evictConn("group", conn)

	select {
	case <-conn.closeCh:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("evicted tunnel connection was not closed")
	}
	select {
	case <-transport.closed:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("evicted tunnel transport was not closed")
	}
}

func TestConntrackCapacityIsBounded(t *testing.T) {
	const maxEntries = 16384
	manager := newConntrackMgr()
	for i := 0; i < maxEntries+3616; i++ {
		manager.getOrCreate(stringKey(i), "app", "group")
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if entries := len(manager.byKey); entries > maxEntries {
		t.Fatalf("byKey entries = %d, want at most %d", entries, maxEntries)
	}
	if entries := len(manager.byID); entries > maxEntries {
		t.Fatalf("byID entries = %d, want at most %d", entries, maxEntries)
	}
	if manager.byKey["0"] != nil {
		t.Fatal("least recently used conntrack entry was not evicted")
	}
}

func TestConntrackExpiryRemovesBothIndexes(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.ttl = time.Minute
	manager.now = func() time.Time { return now }
	first := manager.getOrCreate("first", "app", "group")
	now = now.Add(30 * time.Second)
	second := manager.getOrCreate("second", "app", "group")
	now = now.Add(31 * time.Second)

	manager.removeExpired()

	if manager.getByKey(first.key) != nil || manager.getByID(first.authID) != nil {
		t.Fatal("expired conntrack remained in an index")
	}
	if manager.getByKey(second.key) != second || manager.getByID(second.authID) != second {
		t.Fatal("active conntrack was removed")
	}
}

func TestTCPFinAndResetCloseConntrack(t *testing.T) {
	for _, flag := range []uint16{zctcpip.TCPFin, zctcpip.TCPRst} {
		packet := makeTCPPacket(flag)
		if !packetClosesConntrack(packet) {
			t.Fatalf("TCP flag 0x%x did not close conntrack", flag)
		}
	}
	if packetClosesConntrack(makeTCPPacket(zctcpip.TCPAck)) {
		t.Fatal("TCP ACK unexpectedly closed conntrack")
	}
}

func makeTCPPacket(flags uint16) []byte {
	packet := make(zctcpip.IPv4Packet, zctcpip.IPv4HeaderSize+zctcpip.TCPHeaderSize)
	packet[0] = zctcpip.IPv4Version << 4
	packet.SetHeaderLen(zctcpip.IPv4HeaderSize)
	packet.SetTotalLength(uint16(len(packet)))
	packet.SetProtocol(zctcpip.TCP)
	tcpPacket := zctcpip.TCPPacket(packet.Payload())
	tcpPacket[13] = byte(flags)
	return packet
}

func makeUDPPacket(srcPort, dstPort uint16) []byte {
	packet := make(zctcpip.IPv4Packet, zctcpip.IPv4HeaderSize+zctcpip.UDPHeaderSize)
	packet[0] = zctcpip.IPv4Version << 4
	packet.SetHeaderLen(zctcpip.IPv4HeaderSize)
	packet.SetTotalLength(uint16(len(packet)))
	packet.SetProtocol(zctcpip.UDP)
	packet.SetSourceIP(net.IPv4(192, 0, 2, 1))
	packet.SetDestinationIP(net.IPv4(198, 51, 100, 1))
	udpPacket := zctcpip.UDPPacket(packet.Payload())
	udpPacket.SetSourcePort(srcPort)
	udpPacket.SetDestinationPort(dstPort)
	udpPacket.SetLength(zctcpip.UDPHeaderSize)
	return packet
}

func stringKey(value int) string {
	var buf [20]byte
	n := len(buf)
	for {
		n--
		buf[n] = byte('0' + value%10)
		value /= 10
		if value == 0 {
			return string(buf[n:])
		}
	}
}

type trackingNetConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (*trackingNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *trackingNetConn) Write(p []byte) (int, error)    { return len(p), nil }
func (c *trackingNetConn) Close() error                   { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*trackingNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*trackingNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*trackingNetConn) SetDeadline(time.Time) error      { return nil }
func (*trackingNetConn) SetReadDeadline(time.Time) error  { return nil }
func (*trackingNetConn) SetWriteDeadline(time.Time) error { return nil }
