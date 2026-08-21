package atrust

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPTunnelTransportSupportsSequentialLogicalLeases(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	transport := &tcpTunnelTransport{
		conn: client, reader: bufio.NewReader(client), nodeAddr: "node.example:443", reusedAt: time.Now(),
	}
	pool := newTCPTunnelPool()
	pool.configure(true, 1, time.Minute)
	serverErr := make(chan error, 1)
	go func() {
		for range 2 {
			if _, err := server.Write([]byte{0x01, 0x01, 0x00, 0x00}); err != nil {
				serverErr <- err
				return
			}
			var closeFrame [4]byte
			if _, err := io.ReadFull(server, closeFrame[:]); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	for lease := 0; lease < 2; lease++ {
		if lease > 0 {
			if got := pool.acquire(transport.nodeAddr, time.Now()); got != transport {
				t.Fatalf("lease %d acquired transport %p, want %p", lease, got, transport)
			}
		}
		conn := &tcpTunnelConn{
			tlsConn: transport.conn, reader: transport.reader, reuse: true,
			transport: transport, pool: pool,
		}
		if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("lease %d Read() = (%d, %v), want logical EOF", lease, n, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("lease %d Close(): %v", lease, err)
		}
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	pool.close()
}

func TestTCPTunnelPoolExpiresIdleTransport(t *testing.T) {
	pool := newTCPTunnelPool()
	pool.configure(true, 1, time.Second)
	conn := &recordingConn{}
	now := time.Now()
	transport := &tcpTunnelTransport{
		conn: conn, reader: bufio.NewReader(conn), nodeAddr: "node.example:443", reusedAt: now,
	}
	if !pool.release(transport, now) {
		t.Fatal("release rejected clean transport")
	}
	if got := pool.acquire(transport.nodeAddr, now.Add(time.Second)); got != nil {
		t.Fatal("expired transport was returned")
	}
	if !conn.closed {
		t.Fatal("expired transport was not closed")
	}
}

func TestTCPTunnelPoolRejectsDeadTransportOnAcquire(t *testing.T) {
	pool := newTCPTunnelPool()
	pool.configure(true, 1, time.Minute)
	client, server := net.Pipe()
	now := time.Now()
	transport := &tcpTunnelTransport{
		conn: client, reader: bufio.NewReader(client), nodeAddr: "node.example:443", reusedAt: now,
	}
	if !pool.release(transport, now) {
		t.Fatal("release rejected live transport")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	transport.reusedAt = now.Add(-defaultTCPTunnelMinAlive)
	if got := pool.acquire(transport.nodeAddr, time.Now()); got != nil {
		t.Fatal("dead transport was returned")
	}
}

func TestTCPTunnelPoolRejectsDeadTransportOnRelease(t *testing.T) {
	pool := newTCPTunnelPool()
	pool.configure(true, 1, time.Minute)
	client, server := net.Pipe()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	transport := &tcpTunnelTransport{
		conn: client, reader: bufio.NewReader(client), nodeAddr: "node.example:443",
		reusedAt: time.Now().Add(-defaultTCPTunnelMinAlive),
	}
	if pool.release(transport, time.Now()) {
		t.Fatal("dead transport entered pool")
	}
	_ = client.Close()
}

func TestTCPTunnelPoolUsesBinaryDefaultsForZeroPolicyValues(t *testing.T) {
	pool := newTCPTunnelPool()
	pool.configure(true, 0, 0)

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if !pool.enabled {
		t.Fatal("zero max idle disabled the pool")
	}
	if pool.maxIdle != defaultTCPTunnelMaxIdle {
		t.Fatalf("maxIdle = %d, want %d", pool.maxIdle, defaultTCPTunnelMaxIdle)
	}
	if pool.idleTTL != defaultTCPTunnelIdleTTL {
		t.Fatalf("idleTTL = %s, want %s", pool.idleTTL, defaultTCPTunnelIdleTTL)
	}
}

func TestTCPTunnelPoolRejectsBufferedTransport(t *testing.T) {
	pool := newTCPTunnelPool()
	pool.configure(true, 1, time.Minute)
	reader := bufio.NewReaderSize(strings.NewReader("x"), 1)
	if _, err := reader.Peek(1); err != nil {
		t.Fatal(err)
	}
	transport := &tcpTunnelTransport{conn: &recordingConn{}, reader: reader, nodeAddr: "node.example:443"}
	if pool.release(transport, time.Now()) {
		t.Fatal("transport with buffered data entered pool")
	}
}
