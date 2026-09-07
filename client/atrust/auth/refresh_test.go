package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRefreshUsesLatestCookiesAndCSRF(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/passport/v1/public/authConfig" || r.URL.Query().Get("needTicket") != "0" || r.URL.Query().Has("mod") {
			t.Errorf("unexpected refresh request: %s %s", r.Method, r.URL)
		}
		cookie, err := r.Cookie("sid")
		if err != nil || cookie.Value != fmt.Sprintf("sid-%d", calls-1) {
			t.Errorf("cookie = %v, %v", cookie, err)
		}
		if got := r.Header.Get("x-csrf-token"); got != fmt.Sprintf("csrf-%d", calls-1) {
			t.Errorf("csrf = %q", got)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: fmt.Sprintf("sid-%d", calls), Path: "/"})
		fmt.Fprintf(w, `{"code":0,"data":{"isLogin":1,"security":{"csrfToken":"csrf-%d"}}}`, calls)
	}))
	defer server.Close()
	s := NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
	s.Restore("device", "sid-0", nil)
	s.csrfToken = "csrf-0"
	for i := 1; i <= 2; i++ {
		result, err := s.Refresh(context.Background())
		if err != nil || result.SID != fmt.Sprintf("sid-%d", i) {
			t.Fatalf("refresh %d = %+v, %v", i, result, err)
		}
		if len(result.Cookies) != 1 || result.Cookies[0].Value != result.SID {
			t.Fatalf("persisted cookies = %+v", result.Cookies)
		}
	}
}

func TestRefreshRejectsInvalidResponses(t *testing.T) {
	for _, tt := range []struct {
		name      string
		status    int
		body      string
		deleteSID bool
		invalid   bool
	}{
		{"logged out", 200, `{"code":0,"data":{"isLogin":0}}`, false, true},
		{"invalid SID", 200, `{"code":10000004}`, false, true},
		{"expired session", 200, `{"code":75500002}`, false, true},
		{"unauthorized", 401, `{}`, false, true},
		{"forbidden", 403, `{}`, false, true},
		{"server error", 503, `{"code":0,"data":{"isLogin":1}}`, false, false},
		{"business error", 200, `{"code":123,"data":{"isLogin":1}}`, false, false},
		{"missing code", 200, `{"data":{"isLogin":1}}`, false, false},
		{"missing login state", 200, `{"code":0,"data":{}}`, false, false},
		{"bad JSON", 200, `{`, false, false},
		{"deleted cookie", 200, `{"code":0,"data":{"isLogin":1}}`, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.deleteSID {
					http.SetCookie(w, &http.Cookie{Name: "sid", Path: "/", MaxAge: -1})
				}
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}))
			defer server.Close()
			s := NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
			s.Restore("device", "old", nil)
			result, err := s.Refresh(context.Background())
			if err == nil || result.SID != "" || errors.Is(err, ErrSessionInvalid) != tt.invalid {
				t.Fatalf("refresh = %+v, %v", result, err)
			}
		})
	}
}

func TestSnapshotAfterResourceResponseAndRestorePrecedence(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sid")
		if err != nil || cookie.Value != "explicit" {
			t.Errorf("cookie = %v, %v", cookie, err)
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "resource-sid", Path: "/"})
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	s := NewSession(host, nil)
	s.Restore("device", "explicit", []Cookie{{Host: host, Scheme: "https", Name: "sid", Value: "stale"}})
	if _, err := s.ClientResource(); err != nil {
		t.Fatal(err)
	}
	result, err := s.Snapshot()
	if err != nil || result.SID != "resource-sid" {
		t.Fatalf("snapshot = %+v, %v", result, err)
	}
}

func TestRefreshCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	s := NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
	s.Restore("device", "sid", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := s.Refresh(ctx); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not cancel")
	}
}
