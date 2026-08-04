package service

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	stackpkg "github.com/mythologyli/zju-connect/stack"
)

type udpForwardTestStack struct {
	stackpkg.Stack
	dialUDP func(context.Context, *net.UDPAddr) (net.Conn, error)
}

func (s udpForwardTestStack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return s.dialUDP(ctx, addr)
}

type blockingUDPConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	writeOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingUDPConn() *blockingUDPConn {
	return &blockingUDPConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingUDPConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingUDPConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingUDPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingUDPConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*blockingUDPConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (*blockingUDPConn) SetDeadline(time.Time) error      { return nil }
func (*blockingUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingUDPConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPForwardDialFailureReleasesConcurrentPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var startOnce sync.Once
	forward := &UDPForward{
		stack: udpForwardTestStack{dialUDP: func(context.Context, *net.UDPAddr) (net.Conn, error) {
			startOnce.Do(func() { close(dialStarted) })
			<-releaseDial
			return nil, errors.New("dial failed")
		}},
		dest:             &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53},
		connections:      make(map[netip.AddrPort]*UDPConnection),
		connectionsMutex: new(sync.RWMutex),
		timeout:          time.Minute,
		ctx:              ctx,
		cancel:           cancel,
	}
	forward.bufferPool.New = func() any { return new(udpBuffer) }
	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	const packets = 20
	var wg sync.WaitGroup
	wg.Add(packets)
	for i := 0; i < packets; i++ {
		go func() {
			defer wg.Done()
			forward.handle([]byte("payload"), clientAddr)
		}()
	}

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP dial did not start")
	}
	close(releaseDial)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("packets remained blocked after UDP dial failure")
	}
}

func TestUDPForwardGoroutinesAreBoundedPerClient(t *testing.T) {
	upstream := newBlockingUDPConn()
	forward := newUDPForward(udpForwardTestStack{dialUDP: func(context.Context, *net.UDPAddr) (net.Conn, error) {
		return upstream, nil
	}}, "127.0.0.1:0", "192.0.2.1:53")
	done := make(chan struct{})
	baseline := runtime.NumGoroutine()
	go func() {
		forward.startUDPForward()
		close(done)
	}()

	client, err := net.DialUDP("udp", nil, forward.listenerConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial UDP forwarder: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("first")); err != nil {
		t.Fatalf("write first packet: %v", err)
	}
	select {
	case <-upstream.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream write did not start")
	}

	for i := 0; i < 200; i++ {
		if _, err := client.Write([]byte("packet")); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if growth := runtime.NumGoroutine() - baseline; growth > 20 {
		t.Fatalf("goroutine growth for one blocked UDP client = %d, want at most 20", growth)
	}

	if err := forward.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close UDP forwarder: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP forwarding goroutines did not stop after close")
	}
}

func TestUDPForwardPreservesDatagramsAndReusesSession(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, BufferSize)
		for {
			n, addr, readErr := upstream.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = upstream.WriteToUDP(buf[:n], addr)
		}
	}()

	var dials atomic.Int32
	forward := newUDPForward(udpForwardTestStack{dialUDP: func(ctx context.Context, _ *net.UDPAddr) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "udp", upstream.LocalAddr().String())
	}}, "127.0.0.1:0", "192.0.2.1:53")
	done := make(chan struct{})
	go func() {
		forward.startUDPForward()
		close(done)
	}()
	defer func() {
		_ = forward.Close()
		<-done
	}()

	client, err := net.DialUDP("udp", nil, forward.listenerConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	for _, payload := range [][]byte{[]byte("first datagram"), []byte("second datagram")} {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
		response := make([]byte, BufferSize)
		n, err := client.Read(response)
		if err != nil {
			t.Fatalf("read datagram: %v", err)
		}
		if !bytes.Equal(response[:n], payload) {
			t.Fatalf("response = %q, want %q", response[:n], payload)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dials for one client = %d, want 1", got)
	}
}

func TestUDPForwardEvictsLeastRecentlyActiveConnectionAtCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstCtx, firstCancel := context.WithCancel(ctx)
	secondCtx, secondCancel := context.WithCancel(ctx)
	first := &UDPConnection{ctx: firstCtx, cancel: firstCancel, send: make(chan udpDatagram, 1)}
	second := &UDPConnection{ctx: secondCtx, cancel: secondCancel, send: make(chan udpDatagram, 1)}
	first.lastActive.Store(1)
	second.lastActive.Store(2)
	firstKey := netip.MustParseAddrPort("127.0.0.1:10001")
	secondKey := netip.MustParseAddrPort("127.0.0.1:10002")
	forward := &UDPForward{
		connections:    map[netip.AddrPort]*UDPConnection{firstKey: first, secondKey: second},
		maxConnections: 2,
	}

	evicted := forward.makeRoomForConnectionLocked()
	if evicted != first {
		t.Fatalf("evicted connection = %p, want oldest %p", evicted, first)
	}
	if _, ok := forward.connections[firstKey]; ok {
		t.Fatal("oldest connection remained in the map")
	}
	if _, ok := forward.connections[secondKey]; !ok {
		t.Fatal("newer connection was removed")
	}
}

func TestUDPForwardQueuedMemoryBudgetIsReclaimed(t *testing.T) {
	forward := &UDPForward{maxQueuedBytes: BufferSize}
	first := udpDatagram{data: make([]byte, 1200), buffer: new(udpBuffer)}
	second := udpDatagram{data: make([]byte, 1200), buffer: new(udpBuffer)}
	if !forward.reserveDatagram(&first) {
		t.Fatal("first datagram did not fit empty budget")
	}
	if forward.reserveDatagram(&second) {
		t.Fatal("second datagram exceeded budget but was accepted")
	}
	forward.releaseDatagram(first)
	if !forward.reserveDatagram(&second) {
		t.Fatal("released budget was not reusable")
	}
	forward.releaseDatagram(second)
	if got := forward.queuedBytes.Load(); got != 0 {
		t.Fatalf("queued bytes = %d, want 0", got)
	}
}

func BenchmarkUDPForwardHandle(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	conn := &UDPConnection{ctx: connCtx, cancel: connCancel, send: make(chan udpDatagram, udpForwardQueueSize)}
	forward := &UDPForward{
		connections:      map[netip.AddrPort]*UDPConnection{addr.AddrPort(): conn},
		connectionsMutex: new(sync.RWMutex),
		ctx:              ctx,
		cancel:           cancel,
	}
	forward.bufferPool.New = func() any { return new(udpBuffer) }
	payload := make([]byte, 1200)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		forward.handle(payload, addr)
	}
}
