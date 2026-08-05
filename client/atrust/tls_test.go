package atrust

import "testing"

func TestTunnelTLSConfigMatchesOfficialTransport(t *testing.T) {
	config := tunnelTLSConfig()

	if !config.InsecureSkipVerify {
		t.Fatal("tunnel certificate verification must be disabled")
	}
	if !config.SessionTicketsDisabled {
		t.Fatal("tunnel TLS session tickets must be disabled")
	}
	if config.VerifyConnection != nil || config.VerifyPeerCertificate != nil {
		t.Fatal("official tunnel transport does not install certificate verification callbacks")
	}
	if config.MinVersion != 0 || config.MaxVersion != 0 {
		t.Fatal("official tunnel transport does not override Go's TLS version defaults")
	}
}
