package atrust

import "crypto/tls"

// tunnelTLSConfig mirrors the official client's standard TLS transport.
func tunnelTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}
}
