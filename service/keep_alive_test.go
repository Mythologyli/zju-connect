package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPKeepAliveDrainsBodyAndReusesConnection(t *testing.T) {
	requests := make(chan struct{}, 2)
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
		requests <- struct{}{}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		runHTTPKeepAlive(ctx, server.Client(), server.URL, ticks)
		close(done)
	}()

	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("first keepalive request did not arrive")
	}
	ticks <- time.Now()
	select {
	case <-requests:
	case <-time.After(time.Second):
		t.Fatal("second keepalive request did not arrive")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive loop did not stop")
	}

	if got := connections.Load(); got != 1 {
		t.Fatalf("TCP connections for two keepalive requests = %d, want 1", got)
	}
}
