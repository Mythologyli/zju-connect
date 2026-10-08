package atrust

import (
	"crypto/tls"
	"testing"
)

func TestNewClientClonesAuthTLSConfig(t *testing.T) {
	original := &tls.Config{ServerName: "vpn.example"}
	c := NewClient(ClientOptions{AuthTLSConfig: original})
	defer c.Close()
	original.ServerName = "mutated.example"
	if c.authTLSConfig == nil || c.authTLSConfig.ServerName != "vpn.example" {
		t.Fatal("caller TLS config mutation leaked into aTrust client")
	}
	if c.authTLSConfig.InsecureSkipVerify {
		t.Fatal("explicit auth TLS policy should remain strict")
	}
	if NewClient(ClientOptions{}).authTLSConfig != nil {
		t.Fatal("nil TLS config should preserve legacy behavior")
	}
}
