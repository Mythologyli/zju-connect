package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sessionTLSConfig(t *testing.T, session *Session) *tls.Config {
	t.Helper()
	transport, ok := session.client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("session has no TLS config")
	}
	return transport.TLSClientConfig
}

func TestNewSessionTLSCompatibility(t *testing.T) {
	if !sessionTLSConfig(t, NewSession("vpn.example", nil)).InsecureSkipVerify {
		t.Fatal("old constructor must preserve appliance TLS behavior")
	}
	if !sessionTLSConfig(t, NewSessionContext(context.Background(), "vpn.example", nil)).InsecureSkipVerify {
		t.Fatal("context constructor must preserve appliance TLS behavior")
	}
}

func TestNewSessionWithOptionsUsesStrictTLSAndClones(t *testing.T) {
	original := &tls.Config{ServerName: "vpn.example"}
	session := NewSessionWithOptions(context.Background(), "vpn.example", SessionOptions{TLSConfig: original})
	original.ServerName = "mutated.example"
	got := sessionTLSConfig(t, session)
	if got.ServerName != "vpn.example" || got.InsecureSkipVerify {
		t.Fatalf("TLS configuration was modified unexpectedly: %+v", got)
	}
}

func TestNewSessionWithOptionsRejectsUntrustedServer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	session := NewSessionWithOptions(context.Background(), host, SessionOptions{TLSConfig: &tls.Config{}})
	response, err := session.client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected unknown authority rejection, got: %v", err)
	}
}

func TestNewSessionWithOptionsAcceptsExplicitTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	host := strings.TrimPrefix(server.URL, "https://")
	session := NewSessionWithOptions(context.Background(), host, SessionOptions{TLSConfig: &tls.Config{RootCAs: roots}})
	response, err := session.client.Get(server.URL)
	if err != nil {
		t.Fatalf("trusted local HTTPS should connect: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
}
