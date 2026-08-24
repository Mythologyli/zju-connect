package easyconnect

import (
	"crypto/tls"
	"reflect"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/underlay"
)

func TestNewClientMapsOptions(t *testing.T) {
	dialer := newTestUnderlay(t, underlay.Options{AutoDetect: false})
	certificate := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	var keyLogWriter strings.Builder

	c := NewClient(Options{
		Server: "vpn.example.com:443",
		Auth: AuthOptions{
			Username:      "user",
			Password:      "password",
			TOTPSecret:    "totp-secret",
			Certificate:   certificate,
			GraphCodeFile: "graph-code.txt",
		},
		SessionID:     "session-id",
		TestMultiLine: true,
		Resources: ResourceOptions{
			Fetch:          true,
			IncludeDomains: true,
		},
		UnderlayDialer:  dialer,
		TLSKeyLogWriter: &keyLogWriter,
	})
	t.Cleanup(c.Close)

	if c.server != "vpn.example.com:443" || c.username != "user" || c.password != "password" {
		t.Fatalf("basic options were not mapped: %+v", c)
	}
	if c.totpSecret != "totp-secret" || c.graphCodeFile != "graph-code.txt" {
		t.Fatal("authentication options were not mapped")
	}
	if !reflect.DeepEqual(c.tlsCert.Certificate, certificate.Certificate) {
		t.Fatal("certificate option was not mapped")
	}
	if c.twfID != "session-id" || !c.testMultiLine || !c.parseResource || !c.useDomainResource {
		t.Fatal("session or resource options were not mapped")
	}
	if c.underlayDialer != dialer || c.tlsKeyLogWriter != &keyLogWriter {
		t.Fatal("transport dependencies were not mapped")
	}
}

func TestResourceOptionsTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name           string
		fetch          bool
		includeDomains bool
	}{
		{name: "neither"},
		{name: "fetch only", fetch: true},
		{name: "domains only", includeDomains: true},
		{name: "both", fetch: true, includeDomains: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(Options{Resources: ResourceOptions{
				Fetch:          tt.fetch,
				IncludeDomains: tt.includeDomains,
			}})
			t.Cleanup(c.Close)
			if c.parseResource != tt.fetch || c.useDomainResource != tt.includeDomains {
				t.Fatalf("resource state = (%t, %t), want (%t, %t)",
					c.parseResource, c.useDomainResource, tt.fetch, tt.includeDomains)
			}
		})
	}
}
