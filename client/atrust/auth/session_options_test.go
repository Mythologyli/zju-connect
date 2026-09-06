package auth

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func sessionTransportTLSConfig(t *testing.T, session *Session) *tls.Config {
	t.Helper()
	transport, ok := session.client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("session transport does not expose TLS config")
	}
	return transport.TLSClientConfig
}

func TestNewSessionPreservesCompatibilityTLSDefault(t *testing.T) {
	got := sessionTransportTLSConfig(t, NewSession("vpn.example", nil))
	if !got.InsecureSkipVerify {
		t.Fatal("NewSession must preserve the existing insecure appliance-compatible default")
	}
}

func TestNewSessionWithOptionsClonesCallerTLSConfig(t *testing.T) {
	original := &tls.Config{ServerName: "vpn.example"}
	session := NewSessionWithOptions("vpn.example", SessionOptions{TLSConfig: original})
	original.ServerName = "mutated.example"
	got := sessionTransportTLSConfig(t, session)
	if got.ServerName != "vpn.example" {
		t.Fatalf("caller mutation leaked into session TLS config: %q", got.ServerName)
	}
	if got.InsecureSkipVerify {
		t.Fatal("caller TLS policy was overwritten by compatibility defaults")
	}
}
