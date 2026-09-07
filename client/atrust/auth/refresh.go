package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

var ErrSessionInvalid = errors.New("aTrust session is invalid; reauthentication required")

// Restore initializes the control-plane session when tunnel credentials were
// supplied directly. A supplied SID takes precedence over persisted cookies.
func (s *Session) Restore(deviceID, sid string, cookies []Cookie) {
	s.deviceID = deviceID
	env, _ := json.Marshal(map[string]string{"deviceId": deviceID})
	s.env = base64.StdEncoding.EncodeToString(env)
	for _, cookie := range cookies {
		s.client.Jar.SetCookies(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme}, []*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: "/"}})
	}
	if sid != "" {
		s.client.Jar.SetCookies(&url.URL{Host: s.baseHost, Scheme: "https"}, []*http.Cookie{{Name: "sid", Value: sid, Path: "/"}})
	}
}

// Snapshot must be taken after the last HTTP response, which may replace sid.
func (s *Session) Snapshot() (LoginResult, error) {
	sid, cookies := sessionCookies(s)
	if sid == "" {
		return LoginResult{}, ErrSessionInvalid
	}
	return LoginResult{SID: sid, Cookies: cookies}, nil
}

// Refresh maintains an existing session; it never starts an interactive login.
// Calls on the same Session must be serialized with login and other requests.
func (s *Session) Refresh(ctx context.Context) (LoginResult, error) {
	if _, _, err := s.authConfigContext(ctx, false, false, true); err != nil {
		return LoginResult{}, err
	}
	return s.Snapshot()
}
