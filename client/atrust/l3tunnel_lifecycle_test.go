package atrust

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/zctcpip"
	zlog "github.com/mythologyli/zju-connect/log"
)

func TestDefaultHeartbeatIntervalMatchesOfficialClient(t *testing.T) {
	if defaultHeartbeatInterval != 5*time.Second {
		t.Fatalf("default heartbeat interval = %v, want 5s", defaultHeartbeatInterval)
	}
}

func TestDefaultAuthTimingMatchesOfficialClient(t *testing.T) {
	if defaultAuthTimeout != 5*time.Second {
		t.Fatalf("default auth timeout = %v, want 5s", defaultAuthTimeout)
	}
	if defaultAuthRetryWait != 10*time.Second {
		t.Fatalf("default auth retry wait = %v, want 10s", defaultAuthRetryWait)
	}
	if defaultAuthMaxAttempts != 3 {
		t.Fatalf("default auth attempts = %d, want 3", defaultAuthMaxAttempts)
	}
}

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

func TestGetConnCoalescesConcurrentConnects(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{
		client:     client,
		conns:      make(map[string]*l3TunnelConn),
		connecting: make(map[string]*l3TunnelConnectCall),
		dataChan:   make(chan []byte, 1),
		closeCh:    make(chan struct{}),
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	transport := &trackingNetConn{closed: make(chan struct{})}
	want := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		incoming:     make(chan []byte),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel.connect = func(context.Context, string, *conntrackMgr) (*l3TunnelConn, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return want, nil
	}

	const callers = 16
	results := make(chan *l3TunnelConn, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			conn, err := tunnel.getConn("group")
			results <- conn
			errs <- err
		}()
	}
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)

	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("getConn() error = %v", err)
		}
		if got := <-results; got != want {
			t.Fatalf("getConn() = %p, want %p", got, want)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("connect calls = %d, want 1", got)
	}
	tunnel.Close()
}

func TestTunnelAuthUsesContextDeadline(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		tlsConn: tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
	}
	wantDeadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), wantDeadline)
	defer cancel()

	if err := conn.withContextDeadline(ctx, func() error {
		deadlines := transport.recordedDeadlines()
		if len(deadlines) != 1 || !deadlines[0].Equal(wantDeadline) {
			t.Fatalf("active deadlines = %v, want [%v]", deadlines, wantDeadline)
		}
		return nil
	}); err != nil {
		t.Fatalf("withContextDeadline() error = %v", err)
	}
	deadlines := transport.recordedDeadlines()
	if len(deadlines) != 2 || !deadlines[1].IsZero() {
		t.Fatalf("recorded deadlines = %v, want active deadline followed by zero", deadlines)
	}
}

func TestTunnelReconnectUsesFixedIntervalUntilSuccessAndSharesResult(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{
		client:            client,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		dataChan:          make(chan []byte, 1),
		closeCh:           make(chan struct{}),
		reconnectInterval: 10 * time.Millisecond,
	}
	transport := &trackingNetConn{closed: make(chan struct{})}
	want := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		incoming:     make(chan []byte),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	var calls atomic.Int32
	var attemptTimes []time.Time
	var attemptTimesMu sync.Mutex
	tunnel.connect = func(context.Context, string, *conntrackMgr) (*l3TunnelConn, error) {
		call := calls.Add(1)
		attemptTimesMu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		attemptTimesMu.Unlock()
		if call <= 6 {
			return nil, fmt.Errorf("dial failed: %w", net.ErrClosed)
		}
		return want, nil
	}

	tunnel.startReconnect("group")
	got, err := tunnel.getConn("group")
	if err != nil {
		t.Fatalf("getConn() error = %v", err)
	}
	if got != want {
		t.Fatalf("getConn() = %p, want %p", got, want)
	}
	if calls.Load() != 7 {
		t.Fatalf("connect calls = %d, want 7", calls.Load())
	}
	attemptTimesMu.Lock()
	defer attemptTimesMu.Unlock()
	for i := 1; i < len(attemptTimes); i++ {
		elapsed := attemptTimes[i].Sub(attemptTimes[i-1])
		if elapsed < 8*time.Millisecond || elapsed > 100*time.Millisecond {
			t.Fatalf("retry delay %d = %s, want fixed 10ms interval", i, elapsed)
		}
	}
	tunnel.Close()
}

func TestReconnectDoesNotRaceForegroundConnect(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{
		client:            client,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		dataChan:          make(chan []byte, 1),
		closeCh:           make(chan struct{}),
		reconnectInterval: time.Millisecond,
	}
	started := make(chan struct{})
	release := make(chan struct{})
	transport := &trackingNetConn{closed: make(chan struct{})}
	want := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		incoming:     make(chan []byte),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	var calls atomic.Int32
	tunnel.connect = func(context.Context, string, *conntrackMgr) (*l3TunnelConn, error) {
		calls.Add(1)
		close(started)
		<-release
		return want, nil
	}

	result := make(chan *l3TunnelConn, 1)
	go func() {
		conn, _ := tunnel.getConn("group")
		result <- conn
	}()
	<-started
	tunnel.startReconnect("group")
	close(release)
	if got := <-result; got != want {
		t.Fatalf("getConn() = %p, want %p", got, want)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("connect calls = %d, want 1", got)
	}
	tunnel.Close()
}

func TestTunnelReconnectStopsWhenTunnelCloses(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{
		client:            client,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		dataChan:          make(chan []byte, 1),
		closeCh:           make(chan struct{}),
		reconnectInterval: time.Hour,
	}
	attempted := make(chan struct{})
	tunnel.connect = func(context.Context, string, *conntrackMgr) (*l3TunnelConn, error) {
		close(attempted)
		return nil, fmt.Errorf("dial failed: %w", net.ErrClosed)
	}

	result := make(chan error, 1)
	go func() {
		_, err := tunnel.getConn("group")
		result <- err
	}()
	<-attempted
	tunnel.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("getConn() error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("getConn() did not stop after tunnel close")
	}
}

func TestTunnelReconnectPreservesConntrackAndToken(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	tunnel := &L3Tunnel{
		client:            client,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		conntrackMgrs:     make(map[string]*conntrackMgr),
		dataChan:          make(chan []byte, 1),
		closeCh:           make(chan struct{}),
		reconnectInterval: time.Millisecond,
	}
	var calls atomic.Int32
	var first, second *l3TunnelConn
	tunnel.connect = func(_ context.Context, _ string, manager *conntrackMgr) (*l3TunnelConn, error) {
		conn := &l3TunnelConn{
			tlsConn:      tls.Client(&trackingNetConn{closed: make(chan struct{})}, &tls.Config{InsecureSkipVerify: true}),
			incoming:     make(chan []byte),
			closeCh:      make(chan struct{}),
			conntrackMgr: manager,
		}
		if calls.Add(1) == 1 {
			first = conn
		} else {
			second = conn
		}
		return conn, nil
	}

	conn, err := tunnel.getConn("group")
	if err != nil {
		t.Fatal(err)
	}
	manager := conn.conntrackMgr
	ct := manager.getOrCreate("flow", "app", "group")
	manager.completeAuth(ct.authID, "connect-token", nil)

	tunnel.evictConn("group", conn)
	tunnel.startReconnect("group")
	reconnected, err := tunnel.getConn("group")
	if err != nil {
		t.Fatal(err)
	}
	if first != conn || second != reconnected || calls.Load() != 2 {
		t.Fatalf("connections = first %p second %p calls %d", first, second, calls.Load())
	}
	if reconnected.conntrackMgr != manager {
		t.Fatal("reconnect replaced the node group's conntrack manager")
	}
	if manager.getByKey(ct.key) != ct {
		t.Fatal("reconnect replaced the authenticated conntrack")
	}
	if token, authErr, authenticated := manager.authResult(ct); !authenticated || authErr != nil || token != "connect-token" {
		t.Fatalf("auth result after reconnect = token %q, err %v, authenticated %t", token, authErr, authenticated)
	}
	manager.mu.Lock()
	closedBeforeTunnelClose := manager.closed
	manager.mu.Unlock()
	if closedBeforeTunnelClose {
		t.Fatal("transport close also closed the shared conntrack manager")
	}

	tunnel.Close()
	manager.mu.Lock()
	closedAfterTunnelClose := manager.closed
	manager.mu.Unlock()
	if !closedAfterTunnelClose {
		t.Fatal("tunnel close did not close the shared conntrack manager")
	}
}

func TestTunnelRecoversFromReadAndHeartbeatFailures(t *testing.T) {
	tests := []struct {
		name  string
		start func(*l3TunnelConn)
	}{
		{
			name: "TLS EOF",
			start: func(conn *l3TunnelConn) {
				conn.reader = bufio.NewReader(bytes.NewReader(nil))
				go conn.readLoop()
			},
		},
		{
			name: "unknown version",
			start: func(conn *l3TunnelConn) {
				conn.reader = bufio.NewReader(bytes.NewReader([]byte{0xff, cmdDataResp}))
				go conn.readLoop()
			},
		},
		{
			name: "unknown command",
			start: func(conn *l3TunnelConn) {
				conn.reader = bufio.NewReader(bytes.NewReader([]byte{l3Version, 0x92}))
				go conn.readLoop()
			},
		},
		{
			name: "late tunnel auth",
			start: func(conn *l3TunnelConn) {
				conn.reader = bufio.NewReader(bytes.NewReader([]byte{0x53, 0x00, 0x00, 0x00}))
				go conn.readLoop()
			},
		},
		{
			name: "truncated frame",
			start: func(conn *l3TunnelConn) {
				conn.reader = bufio.NewReader(bytes.NewReader([]byte{l3Version, cmdDataResp, 0x00, 0x04, 0x45}))
				go conn.readLoop()
			},
		},
		{
			name: "heartbeat lost",
			start: func(conn *l3TunnelConn) {
				conn.heartbeatInterval = time.Millisecond
				conn.heartbeatMissLimit = 1
				atomic.StoreInt32(&conn.heartbeatMisses, 1)
				go conn.heartbeatLoop()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient("user", "sid", "device", "")
			client.BestNodes = map[string]string{"group": "node:443"}
			manager := newConntrackMgr()
			oldConn := &l3TunnelConn{
				tlsConn:      tls.Client(&trackingNetConn{closed: make(chan struct{})}, &tls.Config{InsecureSkipVerify: true}),
				incoming:     make(chan []byte),
				closeCh:      make(chan struct{}),
				conntrackMgr: manager,
			}
			reconnected := make(chan *l3TunnelConn, 1)
			tunnel := &L3Tunnel{
				client:            client,
				conns:             map[string]*l3TunnelConn{"group": oldConn},
				connecting:        make(map[string]*l3TunnelConnectCall),
				conntrackMgrs:     map[string]*conntrackMgr{"group": manager},
				dataChan:          make(chan []byte, 1),
				closeCh:           make(chan struct{}),
				reconnectInterval: time.Millisecond,
			}
			tunnel.connect = func(_ context.Context, _ string, gotManager *conntrackMgr) (*l3TunnelConn, error) {
				conn := &l3TunnelConn{
					tlsConn:      tls.Client(&trackingNetConn{closed: make(chan struct{})}, &tls.Config{InsecureSkipVerify: true}),
					incoming:     make(chan []byte),
					closeCh:      make(chan struct{}),
					conntrackMgr: gotManager,
				}
				reconnected <- conn
				return conn, nil
			}

			go tunnel.forwardFromConn("group", oldConn)
			test.start(oldConn)
			select {
			case newConn := <-reconnected:
				if newConn.conntrackMgr != manager {
					t.Fatal("recovery replaced conntrack manager")
				}
			case <-time.After(time.Second):
				t.Fatal("failure did not establish a replacement tunnel")
			}
			tunnel.Close()
		})
	}
}

func TestTunnelRecoversFromDataWriteFailure(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.BestNodes = map[string]string{"group": "node:443"}
	manager := newConntrackMgr()
	packet := zctcpip.IPv4Packet(makeUDPPacket(12345, 53))
	meta, err := buildPacketMeta(packet)
	if err != nil {
		t.Fatal(err)
	}
	meta.key = connTrackKey(meta)
	ct := manager.getOrCreate(meta.key, "app", "group")
	manager.completeAuth(ct.authID, "connect-token", nil)
	oldConn := &l3TunnelConn{
		tlsConn:        tls.Client(&trackingNetConn{closed: make(chan struct{})}, &tls.Config{InsecureSkipVerify: true}),
		incoming:       make(chan []byte),
		closeCh:        make(chan struct{}),
		conntrackMgr:   manager,
		writeFrameHook: func([]byte) error { return net.ErrClosed },
	}
	tunnel := &L3Tunnel{
		client:            client,
		conns:             map[string]*l3TunnelConn{"group": oldConn},
		connecting:        make(map[string]*l3TunnelConnectCall),
		conntrackMgrs:     map[string]*conntrackMgr{"group": manager},
		dataChan:          make(chan []byte, 1),
		closeCh:           make(chan struct{}),
		reconnectInterval: time.Millisecond,
	}
	written := make(chan []byte, 1)
	tunnel.connect = func(_ context.Context, _ string, gotManager *conntrackMgr) (*l3TunnelConn, error) {
		return &l3TunnelConn{
			tlsConn:      tls.Client(&trackingNetConn{closed: make(chan struct{})}, &tls.Config{InsecureSkipVerify: true}),
			incoming:     make(chan []byte),
			closeCh:      make(chan struct{}),
			conntrackMgr: gotManager,
			writeFrameHook: func(frame []byte) error {
				written <- append([]byte(nil), frame...)
				return nil
			},
		}, nil
	}

	if err := tunnel.writePacket(packet, "app", "group"); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-written:
		if !bytes.Contains(frame, []byte("connect-token")) {
			t.Fatalf("replacement tunnel did not reuse connect token: % X", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("packet was not retried on a replacement tunnel")
	}
	tunnel.Close()
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

func TestReadLoopProcessesControlFramesWhenIncomingQueueIsFull(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	packet := makeUDPPacket(12345, 53)
	frameData := append([]byte{l3Version, cmdDataResp, byte(len(packet) >> 8), byte(len(packet))}, packet...)
	frameData = append(frameData, l3Version, cmdHeartbeatResp, 0x00, 0x00)
	conn := &l3TunnelConn{
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		reader:       bufio.NewReader(bytes.NewReader(frameData)),
		incoming:     make(chan []byte, 1),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	atomic.StoreInt32(&conn.heartbeatMisses, 2)
	atomic.StoreUint32(&conn.heartbeatHasWrite, 1)
	conn.incoming <- []byte("already queued")
	done := make(chan struct{})
	go func() {
		conn.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("read loop remained blocked by full incoming queue")
	}
	if misses := atomic.LoadInt32(&conn.heartbeatMisses); misses != 0 {
		t.Fatalf("heartbeat misses = %d, want control response processed", misses)
	}
	if hasWrite := atomic.LoadUint32(&conn.heartbeatHasWrite); hasWrite != 0 {
		t.Fatalf("heartbeat hasWrite = %d, want control response to clear activity", hasWrite)
	}
	if got := <-conn.incoming; !bytes.Equal(got, []byte("already queued")) {
		t.Fatalf("full queue content changed to % X", got)
	}
}

func TestIncomingFullQueueDropsPacket(t *testing.T) {
	conn := &l3TunnelConn{
		incoming: make(chan []byte, 1),
		closeCh:  make(chan struct{}),
	}
	conn.incoming <- []byte("full")
	if !conn.deliverIncoming([]byte("dropped")) {
		t.Fatal("full queue was treated as a closed connection")
	}
	if got := <-conn.incoming; !bytes.Equal(got, []byte("full")) {
		t.Fatalf("queued packet = %q, want original packet", got)
	}
	close(conn.closeCh)
	if conn.deliverIncoming([]byte("closed")) {
		t.Fatal("packet was accepted after close")
	}
}

func TestHeartbeatTimeoutClosesTunnelConnection(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		tlsConn:            tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:            make(chan struct{}),
		conntrackMgr:       newConntrackMgr(),
		heartbeatInterval:  5 * time.Millisecond,
		heartbeatMissLimit: 2,
		writeFrameHook:     func([]byte) error { return nil },
	}
	atomic.StoreInt32(&conn.heartbeatMisses, conn.heartbeatMissLimit)

	go conn.heartbeatLoop()
	select {
	case <-conn.closeCh:
	case <-time.After(time.Second):
		t.Fatal("heartbeat timeout did not close the tunnel connection")
	}
	select {
	case <-transport.closed:
	case <-time.After(time.Second):
		t.Fatal("heartbeat timeout did not close the transport")
	}
}

func TestHeartbeatWaitsForFirstInterval(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	written := make(chan struct{}, 1)
	conn := &l3TunnelConn{
		tlsConn:            tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:            make(chan struct{}),
		conntrackMgr:       newConntrackMgr(),
		heartbeatInterval:  50 * time.Millisecond,
		heartbeatMissLimit: 2,
		writeFrameHook: func([]byte) error {
			written <- struct{}{}
			return nil
		},
	}
	go conn.heartbeatLoop()
	select {
	case <-written:
		t.Fatal("heartbeat was sent before the first interval")
	case <-time.After(15 * time.Millisecond):
	}
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not sent after the first interval")
	}
	_ = conn.Close()
}

func TestHeartbeatSuccessfulCommandWriteSuppressesProbe(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	written := make(chan []byte, 2)
	conn := &l3TunnelConn{
		tlsConn:            tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:            make(chan struct{}),
		conntrackMgr:       newConntrackMgr(),
		heartbeatInterval:  40 * time.Millisecond,
		heartbeatMissLimit: 2,
		writeFrameHook: func(frame []byte) error {
			written <- append([]byte(nil), frame...)
			return nil
		},
	}
	atomic.StoreInt32(&conn.heartbeatMisses, 1)
	if err := conn.writeFrame([]byte{l3Version, cmdDataReq}); err != nil {
		t.Fatal(err)
	}
	<-written
	go conn.heartbeatLoop()

	time.Sleep(60 * time.Millisecond)
	if misses := atomic.LoadInt32(&conn.heartbeatMisses); misses != 0 {
		t.Fatalf("heartbeat misses = %d, want command activity to clear misses", misses)
	}
	select {
	case frame := <-written:
		t.Fatalf("heartbeat sent despite command activity: % X", frame)
	default:
	}
	_ = conn.Close()
}

func TestSuccessfulHeartbeatWriteClearsMissesOnNextTick(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	written := make(chan []byte, 2)
	conn := &l3TunnelConn{
		tlsConn:            tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:            make(chan struct{}),
		conntrackMgr:       newConntrackMgr(),
		heartbeatInterval:  30 * time.Millisecond,
		heartbeatMissLimit: 2,
		writeFrameHook: func(frame []byte) error {
			written <- append([]byte(nil), frame...)
			return nil
		},
	}
	go conn.heartbeatLoop()

	select {
	case frame := <-written:
		if !bytes.Equal(frame, []byte{l3Version, cmdHeartbeatReq, 0x00, 0x00}) {
			t.Fatalf("first idle frame = % X, want heartbeat", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("idle heartbeat was not sent")
	}
	if misses := atomic.LoadInt32(&conn.heartbeatMisses); misses != 1 {
		t.Fatalf("misses after heartbeat = %d, want 1", misses)
	}

	time.Sleep(45 * time.Millisecond)
	if misses := atomic.LoadInt32(&conn.heartbeatMisses); misses != 0 {
		t.Fatalf("misses after successful heartbeat activity = %d, want 0", misses)
	}
	select {
	case frame := <-written:
		t.Fatalf("next tick sent a heartbeat instead of consuming hasWrite: % X", frame)
	default:
	}
	_ = conn.Close()
}

func TestFailedCommandWriteDoesNotSetHeartbeatActivity(t *testing.T) {
	conn := &l3TunnelConn{writeFrameHook: func([]byte) error { return io.ErrClosedPipe }}
	if err := conn.writeFrame([]byte{l3Version, cmdDataReq}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("writeFrame() error = %v, want closed pipe", err)
	}
	if atomic.LoadUint32(&conn.heartbeatHasWrite) != 0 {
		t.Fatal("failed command write set heartbeat activity")
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

func TestReadDataResponseUsesLengthPrefix(t *testing.T) {
	payload := makeUDPPacket(12345, 53)
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)

	got, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("readDataRespPayload() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload=% X, want % X", got, payload)
	}
}

type limitedReader struct {
	reader io.Reader
	limit  int
}

func (r limitedReader) Read(p []byte) (int, error) {
	if len(p) > r.limit {
		p = p[:r.limit]
	}
	return r.reader.Read(p)
}

func TestReadFrameHandlesSplitAndCoalescedFrames(t *testing.T) {
	data := []byte{
		l3Version, cmdAuthResp, 0x84, 0x00, 0x02, 'o', 'k',
		l3Version, cmdHeartbeatResp, 0x00, 0x00,
	}
	conn := &l3TunnelConn{reader: bufio.NewReaderSize(limitedReader{reader: bytes.NewReader(data), limit: 1}, 2)}

	authFrame, err := conn.readFrame()
	if err != nil {
		t.Fatalf("readFrame(auth) error = %v", err)
	}
	if authFrame.cmd != cmdAuthResp || authFrame.status != 0x84 || !bytes.Equal(authFrame.payload, []byte("ok")) {
		t.Fatalf("auth frame = %#v", authFrame)
	}
	heartbeatFrame, err := conn.readFrame()
	if err != nil {
		t.Fatalf("readFrame(heartbeat) error = %v", err)
	}
	if heartbeatFrame.cmd != cmdHeartbeatResp || heartbeatFrame.status != 0 || len(heartbeatFrame.payload) != 0 {
		t.Fatalf("heartbeat frame = %#v", heartbeatFrame)
	}
}

func TestReadFrameRejectsUnknownProtocolHeaders(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "version", data: []byte{0x04, cmdDataResp}, want: "version 0x04"},
		{name: "command", data: []byte{l3Version, 0x92, 0x00, 0x00}, want: "command 0x92"},
		{name: "late tunnel auth", data: []byte{0x53, 0x00, 0x00, 0x00}, want: "version 0x53"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &l3TunnelConn{reader: bufio.NewReader(bytes.NewReader(test.data))}
			_, err := conn.readFrame()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("readFrame() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSplitIncomingIPPacketsHandlesMultipleAndPartialPackets(t *testing.T) {
	first := makeUDPPacket(12345, 53)
	second := makeUDPPacket(23456, 443)
	stream := append(append([]byte{}, first...), second[:10]...)

	packets, remaining, err := splitIncomingIPPackets(stream)
	if err != nil || len(packets) != 1 || !bytes.Equal(packets[0], first) {
		t.Fatalf("first split packets=%d err=%v", len(packets), err)
	}
	packets, remaining, err = splitIncomingIPPackets(append(remaining, second[10:]...))
	if err != nil || len(packets) != 1 || !bytes.Equal(packets[0], second) || len(remaining) != 0 {
		t.Fatalf("second split packets=%d remaining=%d err=%v", len(packets), len(remaining), err)
	}
}

func TestSplitIncomingIPPacketsAcceptsLargePacketAcrossFrames(t *testing.T) {
	packet := make([]byte, 2000)
	packet[0] = zctcpip.IPv4Version<<4 | 5
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	packets, remaining, err := splitIncomingIPPackets(packet[:1000])
	if err != nil || len(packets) != 0 || len(remaining) != 1000 {
		t.Fatalf("partial split packets=%d remaining=%d err=%v", len(packets), len(remaining), err)
	}
	packets, remaining, err = splitIncomingIPPackets(append(remaining, packet[1000:]...))
	if err != nil || len(packets) != 1 || !bytes.Equal(packets[0], packet) || len(remaining) != 0 {
		t.Fatalf("complete split packets=%d remaining=%d err=%v", len(packets), len(remaining), err)
	}
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

func TestL3TunnelAcceptsTCPOnlyWhenResourcePrefersL3(t *testing.T) {
	destination := net.IPv4(10, 0, 0, 42)
	resources := []client.IPResource{
		{IPMin: destination, IPMax: destination, PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "tcp-app"},
		{IPMin: destination, IPMax: destination, PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "l3-app", EnableTCPPrefL3: true},
	}
	resource, ok := matchL3IPResource(ipresource.New(resources), destination, "tcp", 443)
	if !ok || resource.AppID != "l3-app" {
		t.Fatalf("L3 match = (%#v, %t), want l3-app", resource, ok)
	}
}

func TestL3ConnReadRejectsShortBuffer(t *testing.T) {
	packet := make([]byte, 1500)
	tunnel := &L3Tunnel{
		dataChan: make(chan []byte, 1),
		closeCh:  make(chan struct{}),
	}
	tunnel.dataChan <- packet
	conn := &L3Conn{l3Tunnel: tunnel, closeCh: make(chan struct{})}

	n, err := conn.Read(make([]byte, 1400))
	if n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() = (%d, %v), want (0, io.ErrShortBuffer)", n, err)
	}
}

func TestClosedTunnelErrorsIncludeEOF(t *testing.T) {
	for _, err := range []error{
		io.EOF,
		io.ErrUnexpectedEOF,
		fmt.Errorf("tls write failed: %w", io.EOF),
		net.ErrClosed,
	} {
		if !isClosedConnErr(err) {
			t.Fatalf("isClosedConnErr(%v) = false, want true", err)
		}
	}
	if isClosedConnErr(errors.New("authentication denied")) {
		t.Fatal("authentication error was classified as a closed tunnel")
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

func TestBestNodeChangeEvictsStaleTunnelConnection(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		addr:         "old.example:443",
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel := &L3Tunnel{conns: map[string]*l3TunnelConn{"group": conn}}

	tunnel.evictStaleConns(map[string]string{"group": "new.example:443"}, "group")

	tunnel.connsMu.Lock()
	_, exists := tunnel.conns["group"]
	tunnel.connsMu.Unlock()
	if exists {
		t.Fatal("stale tunnel connection remained cached")
	}
	select {
	case <-transport.closed:
	case <-time.After(time.Second):
		t.Fatal("stale tunnel connection was not closed")
	}
}

func TestUnchangedBestNodeKeepsTunnelConnection(t *testing.T) {
	transport := &trackingNetConn{closed: make(chan struct{})}
	conn := &l3TunnelConn{
		addr:         "best.example:443",
		tlsConn:      tls.Client(transport, &tls.Config{InsecureSkipVerify: true}),
		closeCh:      make(chan struct{}),
		conntrackMgr: newConntrackMgr(),
	}
	tunnel := &L3Tunnel{conns: map[string]*l3TunnelConn{"group": conn}}

	tunnel.evictStaleConns(map[string]string{"group": "best.example:443"}, "group")

	tunnel.connsMu.Lock()
	got := tunnel.conns["group"]
	tunnel.connsMu.Unlock()
	if got != conn {
		t.Fatal("unchanged tunnel connection was evicted")
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

func TestPendingPacketsFlushInOrderAfterAuthentication(t *testing.T) {
	manager := newConntrackMgr()
	frames := make([][]byte, 0, 3)
	conn := &l3TunnelConn{
		closeCh:      make(chan struct{}),
		authWake:     make(chan struct{}, 1),
		conntrackMgr: manager,
		writeFrameHook: func(frame []byte) error {
			frames = append(frames, append([]byte(nil), frame...))
			return nil
		},
	}
	meta := packetMeta{
		atype: 4, proto: 17,
		srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 1),
		srcPort: 12345, dstPort: 53, key: "flow",
	}
	first := makeUDPPacket(12345, 53)
	wantFirst := append([]byte(nil), first...)
	second := makeUDPPacket(12345, 54)
	if err := conn.WritePacket(meta, "app", "group", first); err != nil {
		t.Fatalf("first WritePacket() error = %v", err)
	}
	if err := conn.WritePacket(meta, "app", "group", second); err != nil {
		t.Fatalf("second WritePacket() error = %v", err)
	}
	first[0] = 0
	if len(frames) != 0 {
		t.Fatalf("wrote %d frames before authentication, want 0", len(frames))
	}

	jobs, more := manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 1 || more {
		t.Fatalf("auth batch = %d, more=%t, want 1, false", len(jobs), more)
	}
	if err := conn.sendAuthRequest(jobs[0].conntrack, jobs[0].meta); err != nil {
		t.Fatalf("sendAuthRequest() error = %v", err)
	}
	manager.markAuthSent(jobs[0].conntrack.authID, time.Now().Add(defaultAuthTimeout))
	response, err := json.Marshal(authResponseIP{
		Data: authResponseIPData{ConntrackHash: jobs[0].conntrack.authID, ConnectToken: "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.handleAuthResp(0, response)

	if len(frames) != 3 {
		t.Fatalf("frame count = %d, want auth plus two data frames", len(frames))
	}
	if frames[0][1] != cmdAuthReq || frames[1][1] != cmdDataReq || frames[2][1] != cmdDataReq {
		t.Fatalf("frame commands = %02x %02x %02x", frames[0][1], frames[1][1], frames[2][1])
	}
	firstPackets, err := parseDataPayload(frames[1][2:])
	if err != nil || len(firstPackets) != 1 || !bytes.Equal(firstPackets[0], wantFirst) {
		t.Fatalf("first flushed packet was not the cached copy: packets=%v err=%v", firstPackets, err)
	}
	secondPackets, err := parseDataPayload(frames[2][2:])
	if err != nil || len(secondPackets) != 1 || !bytes.Equal(secondPackets[0], second) {
		t.Fatalf("second flushed packet mismatch: packets=%v err=%v", secondPackets, err)
	}
}

func TestBuildAuthRequestMatchesOfficialFieldOrderAndSignature(t *testing.T) {
	info := clientInfo{sid: "sid", deviceID: "device", connectionID: "connection"}
	meta := packetMeta{
		atype: 4, proto: 17,
		srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2),
		srcPort: 12345, dstPort: 53,
	}
	ct := &conntrack{appID: "app", authID: 42}
	key := []byte("signing-key")

	encoded, err := buildAuthRequest(info, key, meta, ct)
	if err != nil {
		t.Fatalf("buildAuthRequest() error = %v", err)
	}
	var signed authRequestIP
	if err := json.Unmarshal(encoded, &signed); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	signature := signed.XRequestSig
	signed.XRequestSig = ""
	unsigned, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if signature != calcXRequestSig(key, unsigned) {
		t.Fatalf("signature = %q, want signature of %s", signature, unsigned)
	}

	wantKeys := []string{"sid", "appId", "procHash", "url", "deviceId", "connectionId", "rcAppliedInfo", "lang", "env", "conntrackHash", "ip", "xRequestSig"}
	positions := make([]int, len(wantKeys))
	for i, key := range wantKeys {
		positions[i] = bytes.Index(unsigned, []byte(`"`+key+`"`))
		if positions[i] < 0 {
			t.Fatalf("unsigned request missing %q: %s", key, unsigned)
		}
		if i > 0 && positions[i] <= positions[i-1] {
			t.Fatalf("unsigned request field order does not match binary struct: %s", unsigned)
		}
	}
	if bytes.Contains(unsigned, []byte(`"appToken"`)) || bytes.Contains(unsigned, []byte(`"domain"`)) {
		t.Fatalf("omitempty fields unexpectedly encoded: %s", unsigned)
	}
	if !bytes.Contains(unsigned, []byte(`"rcAppliedInfo":0`)) {
		t.Fatalf("required rcAppliedInfo missing: %s", unsigned)
	}
}

func TestAuthSchedulerCollectsFlowsWithoutPerFlowWorkers(t *testing.T) {
	manager := newConntrackMgr()
	for i := 0; i < 3; i++ {
		key := stringKey(i)
		ct := manager.getOrCreate(key, "app", "group")
		meta := packetMeta{key: key}
		if _, err := manager.cachePacket(ct, meta, []byte{byte(i)}); err != nil {
			t.Fatalf("cachePacket(%d) error = %v", i, err)
		}
	}
	jobs, more := manager.nextAuthBatch(2)
	if len(jobs) != 2 || !more {
		t.Fatalf("first auth batch = %d, more=%t, want 2, true", len(jobs), more)
	}
	jobs, more = manager.nextAuthBatch(2)
	if len(jobs) != 1 || more {
		t.Fatalf("second auth batch = %d, more=%t, want 1, false", len(jobs), more)
	}
	jobs, more = manager.nextAuthBatch(2)
	if len(jobs) != 0 || more {
		t.Fatalf("duplicate auth batch = %d, more=%t, want 0, false", len(jobs), more)
	}
}

func TestAuthFailureClearsOnlyFailedConntrack(t *testing.T) {
	manager := newConntrackMgr()
	conn := &l3TunnelConn{closeCh: make(chan struct{}), conntrackMgr: manager}
	failed := manager.getOrCreate("failed", "app", "group")
	other := manager.getOrCreate("other", "app", "group")
	if _, err := manager.cachePacket(failed, packetMeta{key: failed.key}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(authResponseIP{
		Code: 1, Message: "denied", Data: authResponseIPData{ConntrackHash: failed.authID},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.handleAuthResp(1, response)

	if manager.getByKey(failed.key) != nil {
		t.Fatal("failed conntrack was not removed")
	}
	if manager.getByKey(other.key) != other {
		t.Fatal("unrelated conntrack was removed")
	}
	select {
	case <-conn.closeCh:
		t.Fatal("per-flow authentication failure closed the tunnel")
	default:
	}
}

func TestAuthResponseIgnoresJSONCode(t *testing.T) {
	manager := newConntrackMgr()
	conn := &l3TunnelConn{closeCh: make(chan struct{}), conntrackMgr: manager}
	ct := manager.getOrCreate("flow", "app", "group")
	response, err := json.Marshal(authResponseIP{
		Code: 73600007, Message: "business message",
		Data: authResponseIPData{ConntrackHash: ct.authID, ConnectToken: "token"},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn.handleAuthResp(0, response)

	token, authErr, authenticated := manager.authResult(ct)
	if !authenticated || authErr != nil || token != "token" {
		t.Fatalf("auth result = token %q, err %v, authenticated %t", token, authErr, authenticated)
	}
}

func TestAuthResponseFallsBackToIPTuple(t *testing.T) {
	manager := newConntrackMgr()
	conn := &l3TunnelConn{
		closeCh: make(chan struct{}), conntrackMgr: manager,
		writeFrameHook: func([]byte) error { return nil },
	}
	meta := packetMeta{
		atype: 4, proto: 17,
		srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2),
		srcPort: 12345, dstPort: 53, key: "flow",
	}
	ct := manager.getOrCreate(meta.key, "app", "group")
	if _, err := manager.cachePacket(ct, meta, nil); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(authResponseIP{Data: authResponseIPData{
		ConnectToken: "token",
		IP: authIP{
			Atype: authIPType(meta.atype), Protocol: meta.proto,
			SrcAddr: meta.srcIP.String(), SrcPort: meta.srcPort,
			DestAddr: meta.dstIP.String(), DestPort: meta.dstPort,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	conn.handleAuthResp(0, response)

	token, authErr, authenticated := manager.authResult(ct)
	if !authenticated || authErr != nil || token != "token" {
		t.Fatalf("auth result = token %q, err %v, authenticated %t", token, authErr, authenticated)
	}
}

func TestAuthSuccessAcceptsEmptyConnectToken(t *testing.T) {
	manager := newConntrackMgr()
	frames := make([][]byte, 0, 1)
	conn := &l3TunnelConn{
		closeCh:      make(chan struct{}),
		conntrackMgr: manager,
		writeFrameHook: func(frame []byte) error {
			frames = append(frames, append([]byte(nil), frame...))
			return nil
		},
	}
	ct := manager.getOrCreate("flow", "app", "group")
	packet := makeUDPPacket(12345, 53)
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, packet); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(authResponseIP{
		Data: authResponseIPData{ConntrackHash: ct.authID},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn.handleAuthResp(0, response)

	token, authErr, authenticated := manager.authResult(ct)
	if !authenticated || authErr != nil || token != "" {
		t.Fatalf("auth result = token %q, err %v, authenticated %t", token, authErr, authenticated)
	}
	if len(frames) != 1 || len(frames[0]) < 3 || frames[0][1] != cmdDataReq || frames[0][2] != 0 {
		t.Fatalf("empty-token data frames = %x", frames)
	}
}

func TestAuthResponsePreservesConnectTokenBytes(t *testing.T) {
	manager := newConntrackMgr()
	var frame []byte
	conn := &l3TunnelConn{
		closeCh:      make(chan struct{}),
		conntrackMgr: manager,
		writeFrameHook: func(data []byte) error {
			frame = append([]byte(nil), data...)
			return nil
		},
	}
	ct := manager.getOrCreate("flow", "app", "group")
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, makeUDPPacket(12345, 53)); err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(authResponseIP{
		Data: authResponseIPData{ConntrackHash: ct.authID, ConnectToken: " token "},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn.handleAuthResp(0, response)

	if len(frame) < 3 || frame[2] != 7 || string(frame[3:10]) != " token " {
		t.Fatalf("encoded token was altered: %x", frame)
	}
}

func TestPendingPacketCacheMatchesBinaryLimitAndAuthTimeoutRetries(t *testing.T) {
	manager := newConntrackMgr()
	ct := manager.getOrCreate("flow", "app", "group")
	meta := packetMeta{key: ct.key}
	packet := make([]byte, 300)
	for i := 0; i < defaultPendingPacketLimit; i++ {
		packet[0] = byte(i)
		if _, err := manager.cachePacket(ct, meta, packet); err != nil {
			t.Fatalf("cachePacket(%d) error = %v", i, err)
		}
	}
	if _, err := manager.cachePacket(ct, meta, []byte{0xff}); !errors.Is(err, errPendingPacketCacheFull) {
		t.Fatalf("cachePacket() error = %v, want cache full", err)
	}
	conn := &l3TunnelConn{conntrackMgr: manager}
	if err := conn.WritePacket(meta, "app", "group", []byte{0xff}); err != nil {
		t.Fatalf("WritePacket() returned fatal cache-full error: %v", err)
	}
	other := manager.getOrCreate("other", "app", "group")
	jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 1 {
		t.Fatalf("auth jobs = %d, want 1", len(jobs))
	}
	deadline := time.Unix(100, 0)
	for attempt := 1; attempt < defaultAuthMaxAttempts; attempt++ {
		manager.markAuthSent(ct.authID, deadline)
		if expired := manager.expireAuth(deadline, errL3TunnelAuthTimeout); expired != 0 {
			t.Fatalf("attempt %d expired auth count = %d, want 0", attempt, expired)
		}
		if manager.getByKey(ct.key) != ct {
			t.Fatalf("attempt %d removed retryable conntrack", attempt)
		}
		jobs, _ = manager.nextAuthBatch(defaultAuthBatchSize)
		if len(jobs) != 1 || jobs[0].conntrack != ct {
			t.Fatalf("attempt %d retry jobs = %v, want conntrack", attempt, jobs)
		}
	}
	manager.markAuthSent(ct.authID, deadline)
	if expired := manager.expireAuth(deadline, errL3TunnelAuthTimeout); expired != 1 {
		t.Fatalf("final expired auth count = %d, want 1", expired)
	}
	if manager.getByKey(ct.key) != nil {
		t.Fatal("timed out conntrack was not removed")
	}
	if manager.getByKey(other.key) != other {
		t.Fatal("auth timeout removed an unrelated conntrack")
	}
}

func TestAuthServerBusyWaitsBeforeRetry(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("flow", "app", "group")
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
	manager.markAuthSent(ct.authID, now.Add(defaultAuthTimeout))
	conn := &l3TunnelConn{closeCh: make(chan struct{}), authWake: make(chan struct{}, 1), conntrackMgr: manager}
	response, err := json.Marshal(authResponseIP{
		Data: authResponseIPData{ConntrackHash: ct.authID},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.handleAuthResp(authRetryStatusMin, response)

	jobs, _ = manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 0 {
		t.Fatalf("immediate retry jobs = %d, want 0", len(jobs))
	}
	now = now.Add(defaultAuthRetryWait)
	jobs, _ = manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 1 || jobs[0].conntrack != ct {
		t.Fatalf("delayed retry jobs = %v, want conntrack", jobs)
	}
}

func TestAuthStatus84RetriesImmediately(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("flow", "app", "group")
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 1 {
		t.Fatalf("initial auth jobs = %d, want 1", len(jobs))
	}
	manager.markAuthSent(ct.authID, now.Add(defaultAuthTimeout))
	conn := &l3TunnelConn{closeCh: make(chan struct{}), authWake: make(chan struct{}, 1), conntrackMgr: manager}
	response, err := json.Marshal(authResponseIP{
		Data: authResponseIPData{ConntrackHash: ct.authID},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.handleAuthResp(authImmediateRetryStatus, response)

	jobs, _ = manager.nextAuthBatch(defaultAuthBatchSize)
	if len(jobs) != 1 || jobs[0].conntrack != ct {
		t.Fatalf("immediate retry jobs = %v, want conntrack", jobs)
	}
	select {
	case <-conn.authWake:
	default:
		t.Fatal("immediate retry did not wake auth scheduler")
	}
}

func TestAuthServerRetriesDoNotConsumeTimeoutBudget(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("flow", "app", "group")
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, []byte{1}); err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < defaultAuthMaxAttempts+1; attempt++ {
		jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
		if len(jobs) != 1 || jobs[0].conntrack != ct {
			t.Fatalf("server retry %d jobs = %v, want conntrack", attempt, jobs)
		}
		manager.markAuthSent(ct.authID, now.Add(defaultAuthTimeout))
		if !manager.retryAuth(ct.authID, 0) {
			t.Fatalf("server retry %d exhausted timeout budget", attempt)
		}
	}
	if ct.authTimeouts != 0 {
		t.Fatalf("auth timeouts after server retries = %d, want 0", ct.authTimeouts)
	}
}

func TestAuthRetryStatusesRecoverAfterRepeatedBusyResponses(t *testing.T) {
	for status := byte(authRetryStatusMin); status <= authRetryStatusMax; status++ {
		t.Run(fmt.Sprintf("status_%02x", status), func(t *testing.T) {
			now := time.Unix(1000, 0)
			manager := newConntrackMgr()
			manager.now = func() time.Time { return now }
			ct := manager.getOrCreate("flow", "app", "group")
			packet := makeUDPPacket(12345, 53)
			if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, packet); err != nil {
				t.Fatal(err)
			}
			var frames [][]byte
			conn := &l3TunnelConn{
				closeCh:      make(chan struct{}),
				authWake:     make(chan struct{}, 1),
				conntrackMgr: manager,
				writeFrameHook: func(frame []byte) error {
					frames = append(frames, append([]byte(nil), frame...))
					return nil
				},
			}
			response, err := json.Marshal(authResponseIP{
				Data: authResponseIPData{ConntrackHash: ct.authID},
			})
			if err != nil {
				t.Fatal(err)
			}

			for attempt := 0; attempt < defaultAuthMaxAttempts+1; attempt++ {
				jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
				if len(jobs) != 1 || jobs[0].conntrack != ct {
					t.Fatalf("busy response %d auth jobs = %v, want conntrack", attempt, jobs)
				}
				manager.markAuthSent(ct.authID, now.Add(defaultAuthTimeout))
				conn.handleAuthResp(status, response)
				if jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize); len(jobs) != 0 {
					t.Fatalf("busy response %d retried before 10s: %v", attempt, jobs)
				}
				now = now.Add(defaultAuthRetryWait)
			}
			if ct.authTimeouts != 0 {
				t.Fatalf("busy responses consumed %d timeout attempts", ct.authTimeouts)
			}

			jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
			if len(jobs) != 1 || jobs[0].conntrack != ct {
				t.Fatalf("recovery auth jobs = %v, want conntrack", jobs)
			}
			manager.markAuthSent(ct.authID, now.Add(defaultAuthTimeout))
			success, err := json.Marshal(authResponseIP{
				Data: authResponseIPData{ConntrackHash: ct.authID, ConnectToken: "connect-token"},
			})
			if err != nil {
				t.Fatal(err)
			}
			conn.handleAuthResp(0, success)
			if len(frames) != 1 || !bytes.Contains(frames[0], []byte("connect-token")) || !bytes.HasSuffix(frames[0], packet) {
				t.Fatalf("recovery frames = % X, want cached packet with token", frames)
			}
		})
	}
}

func TestAuthServerRetryPreservesConsumedTimeoutBudget(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("flow", "app", "group")
	if _, err := manager.cachePacket(ct, packetMeta{key: ct.key}, []byte{1}); err != nil {
		t.Fatal(err)
	}

	jobs, _ := manager.nextAuthBatch(defaultAuthBatchSize)
	manager.markAuthSent(jobs[0].conntrack.authID, now)
	if expired := manager.expireAuth(now, errL3TunnelAuthTimeout); expired != 0 {
		t.Fatalf("first timeout expired conntrack count = %d, want 0", expired)
	}
	jobs, _ = manager.nextAuthBatch(defaultAuthBatchSize)
	manager.markAuthSent(jobs[0].conntrack.authID, now.Add(defaultAuthTimeout))
	if !manager.retryAuth(ct.authID, 0) {
		t.Fatal("server retry was rejected")
	}
	if ct.authTimeouts != 1 {
		t.Fatalf("auth timeouts after server retry = %d, want 1", ct.authTimeouts)
	}
}

func TestAuthBusyMessageWithoutBusyCodeIsNotRetried(t *testing.T) {
	resp := authResponseIP{Code: 1, Message: "server busy, try again"}
	if isRetryableAuthResponse(0, resp) {
		t.Fatal("free-form busy message was treated as retryable")
	}
	if isRetryableAuthResponse(0, authResponseIP{Code: authRetryStatusMin}) {
		t.Fatal("JSON code was treated as a framing status")
	}
	for status := byte(authRetryStatusMin); status <= authRetryStatusMax; status++ {
		if !isRetryableAuthResponse(status, authResponseIP{}) {
			t.Fatalf("outer retry status 0x%02x was not treated as retryable", status)
		}
	}
	if isRetryableAuthResponse(authRetryStatusMin-1, authResponseIP{}) ||
		isRetryableAuthResponse(authRetryStatusMax+1, authResponseIP{}) {
		t.Fatal("status outside the binary retry range was treated as retryable")
	}
}

func TestTCPConntrackUsesDirectionalStateTimeouts(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("tcp", "app", "group")

	manager.observePacket(ct.key, makeTCPPacketWithSeq(zctcpip.TCPSyn, 100, 0), false)
	if got := ct.expiresAt.Sub(now); got != tcpOutboundSynTTL {
		t.Fatalf("SYN timeout = %s, want %s", got, tcpOutboundSynTTL)
	}
	manager.observePacket(ct.key, makeTCPPacketWithSeq(zctcpip.TCPSyn|zctcpip.TCPAck, 200, 101), true)
	if got := ct.expiresAt.Sub(now); got != tcpSynAckTTL {
		t.Fatalf("SYN-ACK timeout = %s, want %s", got, tcpSynAckTTL)
	}
	manager.observePacket(ct.key, makeTCPPacketWithSeq(zctcpip.TCPAck, 101, 201), false)
	if got := ct.expiresAt.Sub(now); got != tcpEstablishedTTL {
		t.Fatalf("established timeout = %s, want %s", got, tcpEstablishedTTL)
	}
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPFin|zctcpip.TCPAck), false)
	if got := ct.expiresAt.Sub(now); got != tcpEstablishedTTL {
		t.Fatalf("first FIN timeout = %s, want %s", got, tcpEstablishedTTL)
	}
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPAck), true)
	if got := ct.expiresAt.Sub(now); got != tcpEstablishedTTL {
		t.Fatalf("FIN ACK timeout = %s, want %s", got, tcpEstablishedTTL)
	}
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPFin|zctcpip.TCPAck), true)
	if got := ct.expiresAt.Sub(now); got != tcpOutboundFirstClosedTTL {
		t.Fatalf("closed timeout = %s, want %s", got, tcpOutboundFirstClosedTTL)
	}
}

func TestTCPResetUsesCleanupTimeout(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("tcp", "app", "group")
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPRst), true)
	if manager.getByKey(ct.key) != ct {
		t.Fatal("RST removed conntrack before cleanup timeout")
	}
	if got := ct.expiresAt.Sub(now); got != tcpResetTTL {
		t.Fatalf("RST timeout = %s, want %s", got, tcpResetTTL)
	}
}

func TestInboundTCPHandshakeAndCloseTimeouts(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	ct := manager.getOrCreate("tcp", "app", "group")

	manager.observePacket(ct.key, makeTCPPacketWithSeq(zctcpip.TCPSyn, 300, 0), true)
	if got := ct.expiresAt.Sub(now); got != tcpInboundSynTTL {
		t.Fatalf("inbound SYN timeout = %s, want %s", got, tcpInboundSynTTL)
	}
	manager.observePacket(ct.key, makeTCPPacketWithSeq(zctcpip.TCPSyn|zctcpip.TCPAck, 400, 301), false)
	if got := ct.expiresAt.Sub(now); got != tcpEstablishedTTL {
		t.Fatalf("inbound established timeout = %s, want %s", got, tcpEstablishedTTL)
	}
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPFin|zctcpip.TCPAck), true)
	manager.observePacket(ct.key, makeTCPPacket(zctcpip.TCPFin|zctcpip.TCPAck), false)
	if got := ct.expiresAt.Sub(now); got != tcpInboundFirstClosedTTL {
		t.Fatalf("inbound-first close timeout = %s, want %s", got, tcpInboundFirstClosedTTL)
	}
}

func TestIncomingPacketRefreshesReverseConntrack(t *testing.T) {
	now := time.Unix(1000, 0)
	manager := newConntrackMgr()
	manager.now = func() time.Time { return now }
	outgoing := makeUDPPacket(12345, 53)
	meta, err := buildPacketMeta(outgoing)
	if err != nil {
		t.Fatal(err)
	}
	meta.key = connTrackKey(meta)
	ct := manager.getOrCreate(meta.key, "app", "group")
	now = now.Add(time.Minute)

	incoming := zctcpip.IPv4Packet(makeUDPPacket(53, 12345))
	incoming.SetSourceIP(meta.dstIP)
	incoming.SetDestinationIP(meta.srcIP)
	conn := &l3TunnelConn{conntrackMgr: manager}
	conn.refreshIncomingConntrack(incoming)

	manager.mu.Lock()
	lastSeen := ct.lastSeen
	manager.mu.Unlock()
	if !lastSeen.Equal(now) {
		t.Fatalf("lastSeen = %v, want %v", lastSeen, now)
	}
}

func TestConntrackKeyIncludesTransportProtocol(t *testing.T) {
	meta := packetMeta{
		atype: 4, proto: int(zctcpip.TCP),
		srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 1),
		srcPort: 12345, dstPort: 443,
	}
	tcpKey := connTrackKey(meta)
	meta.proto = int(zctcpip.UDP)
	udpKey := connTrackKey(meta)
	if tcpKey == udpKey {
		t.Fatalf("TCP and UDP conntrack keys collided: %q", tcpKey)
	}
}

func TestUpdateVIPAppliesIPv4ToTunnelAndClient(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.setIP(net.IPv4(192, 0, 2, 1))
	var applied net.IP
	client.SetIPUpdateHandler(func(ip net.IP) error {
		applied = append(net.IP(nil), ip...)
		return nil
	})
	tunnel := &L3Tunnel{client: client, ip: net.IPv4(192, 0, 2, 1)}
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.IPv4(198, 51, 100, 7)}

	tunnel.updateVIP(ips)
	ips[1][len(ips[1])-1] = 99

	got, err := client.IP()
	if err != nil {
		t.Fatal(err)
	}
	want := net.IPv4(198, 51, 100, 7)
	if !got.Equal(want) || !tunnel.ip.Equal(want) || !applied.Equal(want) {
		t.Fatalf("active VIP client=%s tunnel=%s, want %s", got, tunnel.ip, want)
	}
	if len(tunnel.vipList) != 2 || !tunnel.vipList[1].Equal(want) {
		t.Fatalf("stored VIPs = %v, want independent copy", tunnel.vipList)
	}
}

func TestUpdateVIPKeepsOldAddressWhenStackRejectsUpdate(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	oldIP := net.IPv4(192, 0, 2, 1)
	client.setIP(oldIP)
	client.SetIPUpdateHandler(func(net.IP) error { return errors.New("apply failed") })
	tunnel := &L3Tunnel{client: client, ip: oldIP}

	tunnel.updateVIP([]net.IP{net.IPv4(198, 51, 100, 7)})
	got, err := client.IP()
	if err != nil || !got.Equal(oldIP) || !tunnel.ip.Equal(oldIP) {
		t.Fatalf("rejected update changed client=%s tunnel=%s err=%v", got, tunnel.ip, err)
	}
}

func TestExtractVIPsUsesOnlyProtocolFields(t *testing.T) {
	payload := []byte(`{"code":0,"data":{"vip":"198.51.100.7","vip6":"2001:db8::7","gateway":"203.0.113.1"}}`)
	ips := extractVIPs(payload)
	if len(ips) != 2 || !ips[0].Equal(net.IPv4(198, 51, 100, 7)) || !ips[1].Equal(net.ParseIP("2001:db8::7")) {
		t.Fatalf("extractVIPs() = %v", ips)
	}
}

func TestInitialVIPHeaderValidation(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		length int
		ok     bool
	}{
		{name: "IPv4", header: []byte{l3Version, 0x00, 0x00, 0x01}, length: 6, ok: true},
		{name: "IPv6", header: []byte{l3Version, 0x00, 0x00, 0x04}, length: 18, ok: true},
		{name: "dual stack", header: []byte{l3Version, 0x00, 0x00, 0x05}, length: 22, ok: true},
		{name: "wrong version", header: []byte{0x04, 0x00, 0x00, 0x01}},
		{name: "failed status", header: []byte{l3Version, 0x05, 0x00, 0x01}},
		{name: "nonzero response flag", header: []byte{l3Version, 0x00, 0x01, 0x01}, length: 6, ok: true},
		{name: "unknown type", header: []byte{l3Version, 0x00, 0x00, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, err := parseInitialVIPHeader(tt.header)
			if (err == nil) != tt.ok || length != tt.length {
				t.Fatalf("parseInitialVIPHeader() = %d, %v", length, err)
			}
		})
	}
}

func makeTCPPacket(flags uint16) []byte {
	return makeTCPPacketWithSeq(flags, 0, 0)
}

func makeTCPPacketWithSeq(flags uint16, sequence, acknowledgment uint32) []byte {
	packet := make(zctcpip.IPv4Packet, zctcpip.IPv4HeaderSize+zctcpip.TCPHeaderSize)
	packet[0] = zctcpip.IPv4Version << 4
	packet.SetHeaderLen(zctcpip.IPv4HeaderSize)
	packet.SetTotalLength(uint16(len(packet)))
	packet.SetProtocol(zctcpip.TCP)
	tcpPacket := zctcpip.TCPPacket(packet.Payload())
	binary.BigEndian.PutUint32(tcpPacket[4:8], sequence)
	binary.BigEndian.PutUint32(tcpPacket[8:12], acknowledgment)
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
	closed     chan struct{}
	closeOnce  sync.Once
	deadlineMu sync.Mutex
	deadlines  []time.Time
}

func (*trackingNetConn) Read([]byte) (int, error)      { return 0, io.EOF }
func (c *trackingNetConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *trackingNetConn) Close() error                { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*trackingNetConn) LocalAddr() net.Addr           { return &net.TCPAddr{} }
func (*trackingNetConn) RemoteAddr() net.Addr          { return &net.TCPAddr{} }
func (c *trackingNetConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.deadlineMu.Unlock()
	return nil
}
func (*trackingNetConn) SetReadDeadline(time.Time) error  { return nil }
func (*trackingNetConn) SetWriteDeadline(time.Time) error { return nil }

func (c *trackingNetConn) recordedDeadlines() []time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}
