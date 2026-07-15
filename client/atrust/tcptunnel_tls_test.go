package atrust

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestNewATrustTLSClientUsesChromeFingerprint(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := newATrustTLSClient(clientConn, "vpn.example.com")
	if client.ClientHelloID.Client != utls.HelloChrome_Auto.Client ||
		client.ClientHelloID.Version != utls.HelloChrome_Auto.Version {
		t.Fatalf("aTrust ClientHello = %s/%s, want %s/%s",
			client.ClientHelloID.Client,
			client.ClientHelloID.Version,
			utls.HelloChrome_Auto.Client,
			utls.HelloChrome_Auto.Version,
		)
	}
}

func TestATrustTLSServerName(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{name: "hostname", addr: "vpn.example.com:441", want: "vpn.example.com"},
		{name: "ipv4", addr: "192.0.2.1:441", want: ""},
		{name: "ipv6", addr: "[2001:db8::1]:441", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := aTrustTLSServerName(tt.addr)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("server name for %q = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestDialATrustTLSUsesChromeFingerprint(t *testing.T) {
	addr, serverDone := startHandshakeServer(t, false)

	conn, err := dialATrustTLS(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*utls.UConn); !ok {
		t.Fatalf("connection type = %T, want *tls.UConn", conn)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialATrustTLSFallsBackToCryptoTLS(t *testing.T) {
	addr, serverDone := startHandshakeServer(t, true)

	conn, err := dialATrustTLS(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Fatalf("fallback connection type = %T, want *tls.Conn", conn)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func startHandshakeServer(t *testing.T, rejectFirst bool) (string, <-chan error) {
	t.Helper()

	template := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	serverConfig := &tls.Config{Certificates: template.TLS.Certificates}
	template.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan error, 1)
	go func() {
		defer listener.Close()
		if rejectFirst {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_ = conn.Close()
		}

		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- tls.Server(conn, serverConfig).Handshake()
	}()

	return listener.Addr().String(), done
}
