package atrust

import (
	"crypto/tls"
	"testing"
)

func TestNodeTLSConfigDefaultsToOfficialClientPolicy(t *testing.T) {
	c := NewClient(ClientOptions{})
	got := c.nodeTLSConfigForDial(nil)
	if !got.InsecureSkipVerify || !got.SessionTicketsDisabled {
		t.Fatalf("unexpected default node TLS config: %+v", got)
	}
}

func TestNodeTLSConfigIsCloned(t *testing.T) {
	original := &tls.Config{InsecureSkipVerify: true, ServerName: "node.example"}
	c := NewClient(ClientOptions{NodeTLSConfig: original})
	original.ServerName = "mutated.example"
	first := c.nodeTLSConfigForDial(nil)
	if first.ServerName != "node.example" {
		t.Fatalf("caller mutation leaked: %q", first.ServerName)
	}
	first.ServerName = "returned.example"
	if got := c.nodeTLSConfigForDial(nil).ServerName; got != "node.example" {
		t.Fatalf("returned mutation leaked: %q", got)
	}
}
