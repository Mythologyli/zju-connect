package easyconnect

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestSetupUnderlayUsesManualInterfaceForHTTP(t *testing.T) {
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false)
	client.setupUnderlay("manual-interface", false)

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

func TestCertificateTransportKeepsUnderlayDialer(t *testing.T) {
	client := NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false)
	client.setupUnderlay("", true)
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
