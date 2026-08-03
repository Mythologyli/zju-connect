package dial

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHTTPProxyConnectResponseHeaderBoundaries(t *testing.T) {
	for _, responseSize := range []int{255, 256, 257, 1024} {
		t.Run(fmt.Sprintf("bytes_%d", responseSize), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen proxy: %v", err)
			}
			defer listener.Close()

			go serveHTTPProxyResponse(t, listener, proxyResponseOfSize(t, responseSize))

			dialer := &Dialer{dialDirectHTTPProxy: listener.Addr().String()}
			result := make(chan error, 1)
			go func() {
				conn, dialErr := dialer.dialDirectWithHTTPProxy(context.Background(), "example.com:443")
				if conn != nil {
					_ = conn.Close()
				}
				result <- dialErr
			}()

			select {
			case err := <-result:
				if err != nil {
					t.Fatalf("CONNECT with %d-byte response: %v", responseSize, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("CONNECT with %d-byte response did not complete", responseSize)
			}
		})
	}
}

func TestHTTPProxyConnectRejectsOversizedResponseHeader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer listener.Close()
	go serveHTTPProxyResponse(t, listener, proxyResponseOfSize(t, maxHTTPProxyResponseHeader+1))

	dialer := &Dialer{dialDirectHTTPProxy: listener.Addr().String()}
	conn, err := dialer.dialDirectWithHTTPProxy(context.Background(), "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("oversized HTTP proxy response header was accepted")
	}
}

func TestHTTPProxyConnectHonorsContextWhileReadingResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer listener.Close()

	peerClosed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		close(peerClosed)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	dialer := &Dialer{dialDirectHTTPProxy: listener.Addr().String()}
	conn, err := dialer.dialDirectWithHTTPProxy(ctx, "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("silent HTTP proxy negotiation did not time out")
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("proxy connection was not closed after context timeout")
	}
}

func TestHTTPProxyConnectPreservesBufferedTunnelData(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	const tunnelData = "first tunneled bytes"
	go func() {
		_, _ = io.WriteString(serverConn, "HTTP/1.1 200 Connection Established\r\n\r\n"+tunnelData)
	}()

	conn, err := readHTTPProxyConnectResponse(clientConn)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	buf := make([]byte, len(tunnelData))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read buffered tunnel data: %v", err)
	}
	if got := string(buf); got != tunnelData {
		t.Fatalf("buffered tunnel data = %q, want %q", got, tunnelData)
	}
}

func proxyResponseOfSize(t *testing.T, size int) string {
	t.Helper()
	prefix := "HTTP/1.1 200 Connection Established\r\nX-Fill: "
	suffix := "\r\n\r\n"
	fillSize := size - len(prefix) - len(suffix)
	if fillSize < 0 {
		t.Fatalf("response size %d is too small", size)
	}
	return prefix + strings.Repeat("a", fillSize) + suffix
}

func serveHTTPProxyResponse(t *testing.T, listener net.Listener, response string) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = conn.Write([]byte(response))
}
