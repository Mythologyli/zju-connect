package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
)

func newTLSTestSession(server *httptest.Server) *Session {
	digest := sha256.Sum256(server.Certificate().Raw)
	return NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{ServerCertSHA256: hex.EncodeToString(digest[:])},
	)
}
