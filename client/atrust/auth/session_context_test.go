package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type blockingRoundTripper struct{}

func (blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestNewSessionContextCancelsRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := NewSessionContext(ctx, "vpn.example", nil)
	session.client.Transport = blockingRoundTripper{}
	req, err := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := session.request(req)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not observe session cancellation")
	}
}

// Callers read the response body after the call returns, so binding the request
// to the session context must not tear down the body the moment it returns.
func TestRequestKeepsBodyReadableAfterReturn(t *testing.T) {
	const head, tail = `{"code":0,`, `"data":{}}`
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, head)
		w.(http.Flusher).Flush()
		<-release // the body is still in flight when request() returns
		_, _ = io.WriteString(w, tail)
	}))
	defer server.Close()

	session := NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, session.baseURL+"/passport/v1/public/authConfig", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := session.request(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	unblock()
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != head+tail {
		t.Fatalf("body = %q, want %q", body, head+tail)
	}
}
