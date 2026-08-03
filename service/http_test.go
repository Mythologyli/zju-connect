package service

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/dial"
)

func TestHTTPConnectClosesTargetWhenClientDisconnects(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetListener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	proxy := httptest.NewServer(newHTTPHandler(dial.NewDialer(nil, nil, nil, false, "")))
	defer proxy.Close()

	clientConn, err := net.Dial("tcp", proxy.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetListener.Addr(), targetListener.Addr()); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	var targetConn net.Conn
	select {
	case targetConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy did not connect to target")
	}
	defer targetConn.Close()

	if err := clientConn.Close(); err != nil {
		t.Fatalf("close proxy client: %v", err)
	}
	if err := targetConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set target read deadline: %v", err)
	}
	var buf [1]byte
	if _, err := targetConn.Read(buf[:]); err == nil {
		t.Fatal("target connection remained readable after proxy client disconnected")
	} else if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
		t.Fatal("target connection was not closed after proxy client disconnected")
	}
}
