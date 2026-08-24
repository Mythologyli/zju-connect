package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginReturnsRefreshedCookiesForExistingSession(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "stored-session-cookie" {
				t.Errorf("authConfig sid cookie = %#v, %v", cookie, err)
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "refreshed-session-cookie", Path: "/"})
			fmt.Fprint(w, "{\"data\":{\"isLogin\":1,\"csrfToken\":\"csrf\"}}")
		case "/passport/v1/user/onlineInfo":
			fmt.Fprint(w, "{\"code\":0,\"data\":{\"username\":\"student\"}}")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	session := NewSession(host, nil)
	result, err := session.Login(nil, LoginOptions{
		DeviceID: "0123456789abcdef0123456789abcdef",
		Cookies: []Cookie{{
			Host:   host,
			Scheme: "https",
			Name:   "sid",
			Value:  "stored-session-cookie",
		}},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.Username != "student" {
		t.Fatalf("Username = %q, want student", result.Username)
	}
	if result.SID != "refreshed-session-cookie" {
		t.Fatalf("SID = %q, want refreshed-session-cookie", result.SID)
	}

	var sid string
	for _, cookie := range result.Cookies {
		if cookie.Name == "sid" {
			sid = cookie.Value
			break
		}
	}
	if sid != "refreshed-session-cookie" {
		t.Fatalf("returned sid cookie = %q, want refreshed-session-cookie", sid)
	}
}
