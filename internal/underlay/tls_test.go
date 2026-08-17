package underlay

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDialTLSContextUsesCallerKeyLogWriter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	dialer, err := New(Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	var keyLog bytes.Buffer
	base := &tls.Config{
		InsecureSkipVerify: true,
		KeyLogWriter:       &keyLog,
	}
	conn, err := dialer.DialTLSContext(t.Context(), "tcp", server.Listener.Addr().String(), base)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if base.ServerName != "" {
		t.Fatalf("DialTLSContext mutated caller config ServerName to %q", base.ServerName)
	}
	if !strings.Contains(keyLog.String(), "CLIENT_") {
		t.Fatalf("key log does not contain client secrets: %q", keyLog.String())
	}
}
