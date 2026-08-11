package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinnedServerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, err := session.accessCheck(); err != nil {
		t.Fatal(err)
	}
	if got := session.ServerCertificateSHA256(); len(got) != 64 {
		t.Fatalf("unexpected certificate fingerprint: %q", got)
	}
}

func TestPinnedServerCertificateMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	session := NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{ServerCertSHA256: strings.Repeat("00", 32)},
	)
	if _, err := session.accessCheck(); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
}

func TestInsecureSkipVerifyAcceptsSelfSignedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer server.Close()

	session := NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{InsecureSkipVerify: true},
	)
	if _, err := session.accessCheck(); err != nil {
		t.Fatal(err)
	}
	if got := session.ServerCertificateSHA256(); len(got) != 64 {
		t.Fatalf("unexpected certificate fingerprint: %q", got)
	}
}

func TestInsecureSkipVerifyOverridesPinnedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer server.Close()

	session := NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{
			ServerCertSHA256:   strings.Repeat("00", 32),
			InsecureSkipVerify: true,
		},
	)
	if _, err := session.accessCheck(); err != nil {
		t.Fatal(err)
	}
}
