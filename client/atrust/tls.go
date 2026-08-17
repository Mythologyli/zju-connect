package atrust

import (
	"crypto/tls"
	"io"
)

func tlsConfig(config *tls.Config, keyLogWriter io.Writer) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}
	if keyLogWriter != nil {
		config.KeyLogWriter = keyLogWriter
	}
	return config
}

// tunnelTLSConfig mirrors the official client's standard TLS transport.
func tunnelTLSConfig(keyLogWriter io.Writer) *tls.Config {
	return tlsConfig(&tls.Config{
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}, keyLogWriter)
}
