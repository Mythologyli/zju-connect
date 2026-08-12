package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

func TestSangforCertificateDigest(t *testing.T) {
	rawDER := []byte{0x01, 0x02, 0x03}
	want := sha256.Sum256([]byte("AQID@~*&!()-"))
	if got := sangforCertificateDigest(rawDER); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("unexpected Sangfor certificate digest: %x", got)
	}
}

func TestAuthConfigAcceptsMatchingAntiMITMCertificate(t *testing.T) {
	var encodedCertificate string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":{"enable":1,"rsaCert":%q}}}`, encodedCertificate)
	}))
	defer server.Close()
	encodedCertificate = base64.StdEncoding.EncodeToString(server.Certificate().Raw)

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestAuthConfigRejectsMismatchedAntiMITMCertificate(t *testing.T) {
	encodedCertificate := base64.StdEncoding.EncodeToString([]byte("not the peer certificate"))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":{"enable":1,"sm2encCert":%q}}}`, encodedCertificate)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err == nil || !strings.Contains(err.Error(), "anti-MITM certificate mismatch") {
		t.Fatalf("expected anti-MITM mismatch, got %v", err)
	}
}

func TestAuthConfigDoesNotParseAdvertisedSM2Certificate(t *testing.T) {
	var encodedCertificate string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":{"enable":1,"rsaCert":%q,"sm2encCert":"not-base64"}}}`, encodedCertificate)
	}))
	defer server.Close()
	encodedCertificate = base64.StdEncoding.EncodeToString(server.Certificate().Raw)

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestAuthConfigIgnoresUnknownAntiMITMEnableValue(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"antiMITMAttackData":{"enable":2}}}`))
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestInsecureSkipVerifyDisablesAntiMITMCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{"antiMITMAttackData":{"enable":1}}}`))
	}))
	defer server.Close()

	session := NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{InsecureSkipVerify: true},
	)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}
