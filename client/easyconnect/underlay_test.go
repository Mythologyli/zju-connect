package easyconnect

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/internal/underlay"
)

func TestInjectedUnderlayUsesManualInterfaceForHTTP(t *testing.T) {
	dialer := newTestUnderlay(t, underlay.Options{InterfaceName: "manual-interface", AutoDetect: true})
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false, dialer)

	if got := client.underlayDialer.InterfaceName(); got != "manual-interface" {
		t.Fatalf("underlay interface = %q, want %q", got, "manual-interface")
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport has type %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("HTTP transport does not use the underlay dialer")
	}
}

func TestSetupRequiresUnderlayDialer(t *testing.T) {
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false, nil)
	if err := client.Setup(""); err == nil || !strings.Contains(err.Error(), "underlay dialer is required") {
		t.Fatalf("Setup error = %v, want missing underlay error", err)
	}
}

func TestCertificateTransportKeepsUnderlayDialer(t *testing.T) {
	dialer := newTestUnderlay(t, underlay.Options{AutoDetect: false})
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false, dialer)
	client.setHTTPTransport(&tls.Config{Renegotiation: tls.RenegotiateOnceAsClient})

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport has type %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("certificate HTTP transport does not use the underlay dialer")
	}
	if transport.TLSClientConfig.Renegotiation != tls.RenegotiateOnceAsClient {
		t.Fatal("certificate TLS configuration was not preserved")
	}
}

func TestHTTPClientHasBoundedNetworkTimeouts(t *testing.T) {
	dialer := newTestUnderlay(t, underlay.Options{AutoDetect: false})
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false, dialer)

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport has type %T, want *http.Transport", client.httpClient.Transport)
	}
	if client.httpClient.Timeout <= 0 {
		t.Fatal("HTTP client total timeout is not configured")
	}
	if transport.DialContext == nil {
		t.Fatal("HTTP transport dial context is not configured")
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("TLS handshake timeout is not configured")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("response header timeout is not configured")
	}
	if transport.IdleConnTimeout <= 0 {
		t.Fatal("idle connection timeout is not configured")
	}
}

func TestRequestTokenTimesOutDuringSilentTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	client := NewClient(listener.Addr().String(), "", "", "", tls.Certificate{}, "session-id", false, false, false, nil)
	client.rawRequestTimeout = 50 * time.Millisecond
	defer client.Close()

	result := make(chan error, 1)
	go func() {
		result <- client.requestToken()
	}()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("token request did not connect")
	}
	defer serverConn.Close()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("token request unexpectedly succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		_ = serverConn.Close()
		t.Fatal("token request did not time out during TLS handshake")
	}
}

func TestSetupHTTPRequestStopsWhenClientCloses(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewClient(strings.TrimPrefix(server.URL, "https://"), "", "", "", tls.Certificate{}, "session-id", false, false, false, nil)
	client.httpClient = server.Client()
	result := make(chan error, 1)
	go func() {
		_, err := client.requestConfig()
		result <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("setup HTTP request did not start")
	}
	client.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("setup HTTP request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("setup HTTP request did not stop after client close")
	}
}

func TestSessionKeepAliveSendsRequestForTick(t *testing.T) {
	requestReceived := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/por/update_session.csp" {
			t.Errorf("request path = %q, want /por/update_session.csp", r.URL.Path)
		}
		requestReceived <- struct{}{}
		_, _ = w.Write([]byte("<Auth><Message>success</Message><ErrorCode>1</ErrorCode></Auth>"))
	}))
	defer server.Close()

	client := NewClient(strings.TrimPrefix(server.URL, "https://"), "", "", "", tls.Certificate{}, "session-id", false, false, false, nil)
	client.httpClient = server.Client()
	defer client.Close()

	ticks := make(chan time.Time, 1)
	done := make(chan struct{})
	go func() {
		client.runSessionKeepAlive(ticks, time.Second)
		close(done)
	}()
	ticks <- time.Now()

	select {
	case <-requestReceived:
	case <-time.After(time.Second):
		t.Fatal("keepalive request did not reach server")
	}

	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive loop did not stop after client close")
	}
}

func newTestUnderlay(t *testing.T, options underlay.Options) *underlay.Dialer {
	t.Helper()
	dialer, err := underlay.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	return dialer
}
