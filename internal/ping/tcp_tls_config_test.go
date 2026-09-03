package ping

import (
	"crypto/tls"
	"testing"
)

func TestTCPingTLSConfigDefaultAndClone(t *testing.T) {
	p := NewTCPing()
	p.SetTarget(&Target{Host: "node.example"})
	if got := p.tlsConfigForTarget(); !got.InsecureSkipVerify || got.ServerName != "node.example" {
		t.Fatalf("unexpected default TLS config: %+v", got)
	}
	custom := &tls.Config{InsecureSkipVerify: true, ServerName: "pinned.example"}
	p.SetTLSConfig(custom)
	custom.ServerName = "mutated.example"
	if got := p.tlsConfigForTarget().ServerName; got != "pinned.example" {
		t.Fatalf("TLS config was not cloned: %q", got)
	}
}
