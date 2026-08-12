package auth

import (
	"net/http/httptest"
	"strings"
)

func newTLSTestSession(server *httptest.Server) *Session {
	return NewSession(strings.TrimPrefix(server.URL, "https://"))
}
