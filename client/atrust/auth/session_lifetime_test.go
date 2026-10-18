package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// portalStub answers the renewal request and remembers what it was asked, so a
// test can tell "the call was born cancelled" from "the call reached the portal".
type portalStub struct {
	mu       sync.Mutex
	queries  []string
	response string
	server   *httptest.Server
}

func newPortalStub(t *testing.T, response string) *portalStub {
	t.Helper()

	stub := &portalStub{response: response}
	stub.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.queries = append(stub.queries, r.URL.RawQuery)
		body := stub.response
		stub.mu.Unlock()

		if !strings.HasSuffix(r.URL.Path, "/public/authConfig") {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sid-1", Path: "/"})
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(stub.server.Close)

	return stub
}

func (p *portalStub) host() string {
	return strings.TrimPrefix(p.server.URL, "https://")
}

func (p *portalStub) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.queries...)
}

func (p *portalStub) setResponse(response string) {
	p.mu.Lock()
	p.response = response
	p.mu.Unlock()
}

func authConfigBody(ticket string) string {
	return `{"code":0,"data":{"isLogin":1,"csrfToken":"csrf-1","ticket":"` + ticket + `","authServerInfoList":[]}}`
}

// TestRenewalDoesNotInheritTheSetupContext pins the failure this change fixes: a
// session built on the setup context is born cancelled, because setup cancels
// that context the moment it returns. Until the session is handed to the client,
// the renewal cannot even reach the portal.
func TestRenewalDoesNotInheritTheSetupContext(t *testing.T) {
	stub := newPortalStub(t, authConfigBody("ticket-1"))

	setupCtx, cancelSetup := context.WithCancel(context.Background())
	session := NewSessionContext(setupCtx, stub.host(), nil)
	cancelSetup()

	if _, err := session.Refresh(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("renewal on the setup context = %v, want context.Canceled", err)
	}
	if got := len(stub.requests()); got != 0 {
		t.Fatalf("the portal was reached %d time(s) on a cancelled setup context, want 0", got)
	}

	session.SetLifetime(context.Background())
	if _, err := session.Refresh(context.Background()); err != nil {
		t.Fatalf("renewal on the lifetime context: %v", err)
	}

	session.stateMu.Lock()
	ticket := session.ticket
	session.stateMu.Unlock()
	if ticket != "ticket-1" {
		t.Fatalf("renewal ticket = %q, want ticket-1", ticket)
	}
	queries := stub.requests()
	if len(queries) != 1 {
		t.Fatalf("renewal requests = %d, want 1", len(queries))
	}
	if !strings.Contains(queries[0], "needTicket=1") {
		t.Fatalf("renewal query %q does not ask the portal for a ticket", queries[0])
	}
}

// TestSessionLifetimeReplacesTheEarlierOne: the swap must be complete, not an
// extra link, otherwise closing the client would stop the renewal and cancelling
// setup would too.
func TestSessionLifetimeReplacesTheEarlierOne(t *testing.T) {
	stub := newPortalStub(t, authConfigBody("ticket-1"))

	setupCtx, cancelSetup := context.WithCancel(context.Background())
	session := NewSessionContext(setupCtx, stub.host(), nil)

	lifetime, cancelLifetime := context.WithCancel(context.Background())
	session.SetLifetime(lifetime)

	// Setup ends and takes its context with it; the session must not care.
	cancelSetup()
	if _, err := session.Refresh(context.Background()); err != nil {
		t.Fatalf("renewal after setup ended: %v", err)
	}

	// The client's own cancellation still reaches the session.
	cancelLifetime()
	if _, err := session.Refresh(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("renewal after the client stopped = %v, want context.Canceled", err)
	}
}

// TestRenewalKeepsTheTicketWhenAnAnswerOmitsIt: the renewal response is not
// documented to carry the ticket in every case, so an answer without one must not
// throw away the ticket the session already holds.
func TestRenewalKeepsTheTicketWhenAnAnswerOmitsIt(t *testing.T) {
	stub := newPortalStub(t, authConfigBody("ticket-1"))
	session := NewSessionContext(context.Background(), stub.host(), nil)

	if _, err := session.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	stub.setResponse(authConfigBody(""))
	if _, err := session.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	session.stateMu.Lock()
	ticket := session.ticket
	session.stateMu.Unlock()
	if ticket != "ticket-1" {
		t.Fatalf("ticket = %q, want the stored ticket-1", ticket)
	}
}
