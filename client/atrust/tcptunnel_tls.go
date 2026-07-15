package atrust

import (
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

func newATrustTLSClient(conn net.Conn, serverName string) *utls.UConn {
	return utls.UClient(conn, &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}, utls.HelloChrome_Auto)
}

func aTrustTLSServerName(addr string) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("parse aTrust node address: %w", err)
	}
	if net.ParseIP(host) != nil {
		return "", nil
	}
	return host, nil
}

// Prefer a browser ClientHello for affected gateways while retaining the original TLS client as a fallback.
func dialATrustTLS(addr string) (net.Conn, error) {
	serverName, err := aTrustTLSServerName(addr)
	if err != nil {
		return nil, err
	}

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	conn := newATrustTLSClient(rawConn, serverName)
	chromeErr := conn.Handshake()
	if chromeErr == nil {
		return conn, nil
	}
	_ = rawConn.Close()

	fallback, fallbackErr := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if fallbackErr != nil {
		return nil, fmt.Errorf("aTrust TLS handshake failed with Chrome fingerprint: %v; crypto/tls fallback failed: %w", chromeErr, fallbackErr)
	}
	return fallback, nil
}
