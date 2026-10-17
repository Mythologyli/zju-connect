package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// restorePortalStub serves the four calls the restore path makes and records the
// order it was asked in, so a test can assert the shape the gateway verified.
type restorePortalStub struct {
	server *httptest.Server

	mu           sync.Mutex
	calls        []string
	exchangeBody string

	authConfigCalls int

	exchangeSID  string
	exchangeCode int
	exchangeMsg  string
	onlineBody   string
	ticketBody   string
}

func newRestorePortalStub(t *testing.T) *restorePortalStub {
	t.Helper()

	stub := &restorePortalStub{
		exchangeSID: "sid-from-exchange",
		onlineBody:  `{"code":0,"data":{"isOnline":true,"username":"student"}}`,
		ticketBody:  `{"code":0,"data":{"sidTicket":"` + strings.Repeat("s", 73) + `"}}`,
	}

	stub.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		stub.mu.Lock()
		stub.calls = append(stub.calls, r.URL.Path)
		exchangeSID, exchangeCode, exchangeMsg := stub.exchangeSID, stub.exchangeCode, stub.exchangeMsg
		onlineBody, ticketBody := stub.onlineBody, stub.ticketBody
		authConfigSID := ""
		if r.URL.Path == "/passport/v1/public/authConfig" {
			// Each authConfig re-issues the session cookies; a test needs to tell
			// which issue the session ends up holding.
			stub.authConfigCalls++
			authConfigSID = fmt.Sprintf("sid-from-authconfig-%d", stub.authConfigCalls)
		}
		if r.URL.Path == "/passport/v1/public/sessionIdExchange" {
			stub.exchangeBody = string(body)
		}
		stub.mu.Unlock()

		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			// The cookie family the exchange runs on comes from here.
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: authConfigSID, Path: "/"})
			_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":1,"csrfToken":"csrf-2","authServerInfoList":[]}}`))
		case "/passport/v1/public/sessionIdExchange":
			if cookie, err := r.Cookie("sid"); err != nil || cookie.Value != "sid-from-authconfig-1" {
				t.Errorf("sessionIdExchange cookie = %v, %v, want the sid the pre-flight authConfig issued", cookie, err)
			}
			// The pre-flight authConfig refreshed the token; the exchange has to
			// use the freshest one, not the persisted one.
			if got := r.Header.Get("x-csrf-token"); got != "csrf-2" {
				t.Errorf("sessionIdExchange csrf = %q, want the token from the last authConfig", got)
			}
			if exchangeCode != 0 {
				_, _ = w.Write([]byte(fmtCode(exchangeCode, exchangeMsg)))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: exchangeSID, Path: "/"})
			_, _ = w.Write([]byte(`{"code":0,"message":"成功","data":{"onlineInfo":{"isOnline":true,"username":"student"}}}`))
		case "/passport/v1/user/onlineInfo":
			_, _ = w.Write([]byte(onlineBody))
		case "/passport/v1/public/ticketExchange":
			_, _ = w.Write([]byte(ticketBody))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(stub.server.Close)

	return stub
}

func fmtCode(code int, message string) string {
	encoded, err := json.Marshal(map[string]any{"code": code, "message": message})
	if err != nil {
		return `{"code":0}`
	}
	return string(encoded)
}

func (p *restorePortalStub) setExchangeRefusal(code int, message string) {
	p.mu.Lock()
	p.exchangeCode, p.exchangeMsg = code, message
	p.mu.Unlock()
}

func (p *restorePortalStub) setOnline(body string) {
	p.mu.Lock()
	p.onlineBody = body
	p.mu.Unlock()
}

func (p *restorePortalStub) setTicket(body string) {
	p.mu.Lock()
	p.ticketBody = body
	p.mu.Unlock()
}

func (p *restorePortalStub) callList() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *restorePortalStub) exchangePayload() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exchangeBody
}

func (p *restorePortalStub) session(t *testing.T, csrf string) *Session {
	t.Helper()
	session := NewSession(strings.TrimPrefix(p.server.URL, "https://"), nil)
	session.csrfToken = csrf
	return session
}

func TestTicketExchangeReturnsTheSIDTicket(t *testing.T) {
	stub := newRestorePortalStub(t)
	session := stub.session(t, "csrf-1")

	ticket, err := session.TicketExchange(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ticket) != 73 {
		t.Fatalf("sidTicket length = %d, want the 73 characters the gateway returns", len(ticket))
	}
	if calls := stub.callList(); !slices.Equal(calls, []string{"/passport/v1/public/ticketExchange"}) {
		t.Fatalf("calls = %v, want just the ticket exchange", calls)
	}
}

func TestTicketExchangeRejectsAnAnswerWithoutATicket(t *testing.T) {
	stub := newRestorePortalStub(t)
	stub.setTicket(`{"code":0,"data":{}}`)

	if _, err := stub.session(t, "csrf-1").TicketExchange(context.Background()); !errors.Is(err, ErrRestoreNotConfirmed) {
		t.Fatalf("error = %v, want ErrRestoreNotConfirmed", err)
	}
}

func TestRestoreByTicketFollowsTheVerifiedOrder(t *testing.T) {
	stub := newRestorePortalStub(t)
	session := stub.session(t, "csrf-1")

	snapshot, err := session.RestoreByTicket(context.Background(), "ticket-from-elsewhere")
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"/passport/v1/public/authConfig",
		"/passport/v1/public/sessionIdExchange",
		"/passport/v1/public/authConfig",
		"/passport/v1/user/onlineInfo",
	}
	if calls := stub.callList(); !slices.Equal(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	// The session must end up on the newest issue, which is the last authConfig's
	// answer, not the exchange's.
	if snapshot.SID != "sid-from-authconfig-2" {
		t.Fatalf("restored SID = %q, want the cookie the last authConfig re-issued", snapshot.SID)
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(stub.exchangePayload()), &payload); err != nil {
		t.Fatalf("exchange payload %q: %v", stub.exchangePayload(), err)
	}
	if payload["sidTicket"] != "ticket-from-elsewhere" {
		t.Fatalf("exchange payload = %v, want the sidTicket", payload)
	}
}

func TestRestoreByTicketRejectsAnUnconfirmedSession(t *testing.T) {
	stub := newRestorePortalStub(t)
	// This is the silent no-op the gateway shows: code 0, nothing online.
	stub.setOnline(`{"code":0,"data":{"username":"student"}}`)

	if _, err := stub.session(t, "csrf-1").RestoreByTicket(context.Background(), "ticket"); !errors.Is(err, ErrRestoreNotConfirmed) {
		t.Fatalf("error = %v, want ErrRestoreNotConfirmed", err)
	}
}

func TestRestoreByTicketClassifiesRefusals(t *testing.T) {
	for _, tt := range []struct {
		name    string
		code    int
		message string
		wantErr error
	}{
		{"a dead session", 75500002, "会话无效", ErrSessionInvalid},
		{"an invalid SID", 10000004, "invalid SID", ErrSessionInvalid},
		{"a stale ticket", 75500304, "stale-ticket", ErrStaleTicket},
		{"a random check code that needs a live session", 75500307, "非法的随机校验码", ErrStaleTicket},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stub := newRestorePortalStub(t)
			stub.setExchangeRefusal(tt.code, tt.message)

			_, err := stub.session(t, "csrf-1").RestoreByTicket(context.Background(), "ticket")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
