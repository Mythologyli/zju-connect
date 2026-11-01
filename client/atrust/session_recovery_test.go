package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
)

// recoveryStub is the portal as the recovery ladder sees it: it can refuse the
// renewal, mint tickets, restore or refuse the restore, and it counts what it was
// asked so a test can tell "one ladder run" from "a request storm".
type recoveryStub struct {
	server *httptest.Server

	mu                 sync.Mutex
	ticketHits         int
	exchangeHits       int
	onlineHits         int
	clientResourceHits int

	// authConfigHits counts the calls; the first authConfigFailures of them are
	// refused, which is how a test says "the renewal starts the ladder" without
	// also refusing the authConfig the restore needs afterwards.
	authConfigHits     int
	authConfigFailures int
	// exchangeRefusals makes the first N session exchanges answer a stale-ticket
	// code, which is what the gateway did when the stored ticket was too old.
	exchangeRefusals    int
	exchangeRefusalCode int

	ticketBody   string
	exchangeBody string
	onlineBody   string
}

func newRecoveryStub(t *testing.T) *recoveryStub {
	t.Helper()

	stub := &recoveryStub{
		authConfigFailures: 1,
		ticketBody:         `{"code":0,"data":{"sidTicket":"` + strings.Repeat("t", 73) + `"}}`,
		exchangeBody:       `{"code":0,"message":"成功","data":{"onlineInfo":{"isOnline":true,"username":"student"}}}`,
		onlineBody:         `{"code":0,"data":{"isOnline":true,"username":"student"}}`,
	}

	stub.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		refuseAuthConfig := false
		refuseExchange := ""
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			stub.authConfigHits++
			refuseAuthConfig = stub.authConfigHits <= stub.authConfigFailures
		case "/passport/v1/public/ticketExchange":
			stub.ticketHits++
		case "/passport/v1/public/sessionIdExchange":
			stub.exchangeHits++
			if stub.exchangeHits <= stub.exchangeRefusals {
				code := stub.exchangeRefusalCode
				if code == 0 {
					code = 75500304 // stale-ticket
				}
				refuseExchange = fmt.Sprintf(`{"code":%d,"message":"stale-ticket"}`, code)
			}
		case "/passport/v1/user/onlineInfo":
			stub.onlineHits++
		case "/controller/v1/user/clientResource":
			stub.clientResourceHits++
		}
		body := ""
		switch r.URL.Path {
		case "/controller/v1/user/clientResource":
			body = `{"code":0,"data":{"appList":{"data":{"appInfo":[],"config":{"nodeGroupConf":{"majorNodeGroup":{"id":"group"},"nodeGroupList":[]}}}},"sdpPolicy":{"data":{}}}}`
		case "/passport/v1/public/authConfig":
			if refuseAuthConfig {
				body = `{"code":75500002,"message":"会话无效"}`
			} else {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "sid-recovered", Path: "/"})
				body = `{"code":0,"data":{"isLogin":1,"csrfToken":"csrf-restored","authServerInfoList":[]}}`
			}
		case "/passport/v1/public/ticketExchange":
			body = stub.ticketBody
		case "/passport/v1/public/sessionIdExchange":
			if refuseExchange != "" {
				body = refuseExchange
			} else {
				body = stub.exchangeBody
			}
		case "/passport/v1/user/onlineInfo":
			body = stub.onlineBody
		}
		stub.mu.Unlock()

		if body == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(stub.server.Close)

	return stub
}

func (p *recoveryStub) refuseEveryRenewal() {
	p.mu.Lock()
	p.authConfigFailures = 1 << 20
	p.mu.Unlock()
}

func (p *recoveryStub) refuseExchanges(count int) {
	p.mu.Lock()
	p.exchangeRefusals = count
	p.mu.Unlock()
}

func (p *recoveryStub) host() string { return strings.TrimPrefix(p.server.URL, "https://") }

func (p *recoveryStub) hits() (authConfig, ticket, exchange, online int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authConfigHits, p.ticketHits, p.exchangeHits, p.onlineHits
}

func (p *recoveryStub) clientResourceHitsCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientResourceHits
}

func (p *recoveryStub) authConfigHitsFor(t *testing.T) int {
	t.Helper()
	authConfig, _, _, _ := p.hits()
	return authConfig
}

func (p *recoveryStub) set(body string, target *string) {
	p.mu.Lock()
	*target = body
	p.mu.Unlock()
}

// recoveringClient is a client wired to the stub, with a session state that setup
// would have produced.
func recoveringClient(t *testing.T, stub *recoveryStub) *Client {
	t.Helper()

	c := NewClient(ClientOptions{Session: SessionOptions{SID: "sid", DeviceID: "device", SignKey: "key"}})
	t.Cleanup(c.Close)

	c.sessionMu.Lock()
	c.session = auth.NewSession(stub.host(), nil)
	c.sessionState = SessionOnline
	c.sessionMu.Unlock()

	return c
}

func waitForState(t *testing.T, c *Client, want SessionState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.currentSessionState() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("session state = %q, want %q", c.currentSessionState(), want)
}

// TestSessionInvalidDataPlaneAnswersDoNotExit pins the contract: a gateway answer
// that says the session is gone fails the request and unwraps to
// auth.ErrSessionInvalid, instead of taking the process down.
func TestSessionInvalidDataPlaneAnswersDoNotExit(t *testing.T) {
	for _, code := range []int{10000004, 75500001, 75500002} {
		payload := fmt.Sprintf(`{"code":%d,"message":"session rejected"}`, code)

		if err := parseTCPTunnelAuthResponse(payload); !errors.Is(err, auth.ErrSessionInvalid) {
			t.Fatalf("tcp tunnel code %d: error = %v, want auth.ErrSessionInvalid", code, err)
		}
		if err := parseIPAuthResponse([]byte(payload)); !errors.Is(err, auth.ErrSessionInvalid) {
			t.Fatalf("IP tunnel code %d: error = %v, want auth.ErrSessionInvalid", code, err)
		}

		var reported []int64
		conn := &l3TunnelConn{onSessionInvalid: func(code int64, _ string) { reported = append(reported, code) }}
		conn.handleAuthResp(authImmediateRetryStatus, []byte(payload))
		if len(reported) != 1 || reported[0] != int64(code) {
			t.Fatalf("l3 tunnel code %d: reported %v, want one report of that code", code, reported)
		}
	}
}

// TestTicketRestoreWithoutResourceFile: a ticket, the matching device id and the
// sign key are enough to establish the session; the resource list is fetched
// through the restored session instead of requiring -resource-file. This is the
// path the GUI takes, since it passes no resource file at all.
func TestTicketRestoreWithoutResourceFile(t *testing.T) {
	stub := newRecoveryStub(t)
	c := NewClient(ClientOptions{Session: SessionOptions{
		DeviceID:  "device",
		SignKey:   "key",
		SIDTicket: strings.Repeat("t", 73),
	}})
	t.Cleanup(c.Close)

	c.sessionMu.Lock()
	c.session = auth.NewSession(stub.host(), nil)
	c.sessionMu.Unlock()

	var clientAuthData auth.ClientAuthData
	established, err := c.establishSession(context.Background(), c.session, SetupOptions{}, &clientAuthData, nil)
	if err != nil {
		t.Fatalf("establishSession: %v", err)
	}
	if established.resumed || !established.restored {
		t.Fatalf("establishment = %+v, want a ticket restore", established)
	}
	if len(established.resourceData) == 0 {
		t.Fatal("the resource list was not fetched through the restored session")
	}
	if got := stub.clientResourceHitsCount(); got != 1 {
		t.Fatalf("clientResource calls = %d, want 1", got)
	}
	if sid, err := c.sessionSID(); err != nil || sid != "" {
		// establishSession does not publish the snapshot itself; the caller does.
		t.Fatalf("SID = %q, %v", sid, err)
	}
}

// TestDocumentedCombinationsReachOneDecision: the client owns the
// resume/restore/login decision, so the combinations main used to judge for
// itself all end in the login path (and a clear error when no method is
// configured), not in a nil-method call from a different predicate.
func TestDocumentedCombinationsReachOneDecision(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/passport/v1/public/authConfig" {
			_, _ = w.Write([]byte(`{"code":0,"data":{"isLogin":0,"authServerInfoList":[]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	for _, tt := range []struct {
		name       string
		options    SessionOptions
		resource   []byte
		wantResume bool
	}{
		{
			name:     "no stored material",
			options:  SessionOptions{},
			resource: nil,
		},
		{
			name:     "SID and resource without the sign key",
			options:  SessionOptions{SID: "sid", DeviceID: "device"},
			resource: []byte("resource"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(ClientOptions{Session: tt.options})
			t.Cleanup(c.Close)
			c.sessionMu.Lock()
			c.session = auth.NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
			c.sessionMu.Unlock()

			var data auth.ClientAuthData
			established, err := c.establishSession(context.Background(), c.session, SetupOptions{}, &data, tt.resource)
			if err == nil || !strings.Contains(err.Error(), "login method is nil") {
				t.Fatalf("error = %v, want a clear nil-login-method error", err)
			}
			if established.resumed || established.restored {
				t.Fatalf("establishment = %+v, want the login path", established)
			}
		})
	}
}

// TestSessionRecoveryRestoresAndWaitsForTraffic: the ladder renews, restores from
// a ticket, and does not call the session online until application traffic proves
// it (a VIP being allocated proves nothing).
func TestSessionRecoveryRestoresAndWaitsForTraffic(t *testing.T) {
	stub := newRecoveryStub(t)
	c := recoveringClient(t, stub)

	c.reportSessionInvalid(75500002, "test")
	waitForState(t, c, SessionRestoring)

	// Give the ladder time to finish the restore, then assert it did not claim
	// online on its own.
	time.Sleep(100 * time.Millisecond)
	if state := c.currentSessionState(); state != SessionRestoring {
		t.Fatalf("state = %q, want %q until traffic crosses the tunnel", state, SessionRestoring)
	}
	authConfigHits, ticketHits, exchangeHits, onlineHits := stub.hits()
	if ticketHits != 1 || exchangeHits != 1 || onlineHits != 1 {
		t.Fatalf("ladder calls = (authConfig %d, ticket %d, exchange %d, online %d), want one restore",
			authConfigHits, ticketHits, exchangeHits, onlineHits)
	}
	if sid, err := c.sessionSID(); sid != "sid-recovered" {
		t.Fatalf("SID = %q (%v), want the restored session", sid, err)
	}

	c.ObserveTunnelTraffic(true)
	waitForState(t, c, SessionOnline)
}

// TestSessionRecoveryReportsReloginWithoutHammering: with every avenue refused the
// ladder reports relogin-required once, and a second detector inside the cooldown
// window does not start a second run.
func TestSessionRecoveryReportsReloginWithoutHammering(t *testing.T) {
	stub := newRecoveryStub(t)
	stub.refuseEveryRenewal()
	stub.set(`{"code":500,"message":"no"}`, &stub.ticketBody)
	c := recoveringClient(t, stub)

	c.reportSessionInvalid(75500002, "first detector")
	waitForState(t, c, SessionReloginRequired)

	_, ticketHitsAfterFirstRun, exchangeHits, _ := stub.hits()
	if ticketHitsAfterFirstRun != 1 || exchangeHits != 0 {
		t.Fatalf("first run: ticket %d, exchange %d, want one mint and no exchange", ticketHitsAfterFirstRun, exchangeHits)
	}

	// A detector firing again inside the cooldown must not start another run.
	c.reportSessionInvalid(10000004, "second detector")
	time.Sleep(100 * time.Millisecond)
	_, ticketHitsAfterSecondKick, _, _ := stub.hits()
	if ticketHitsAfterSecondKick != ticketHitsAfterFirstRun {
		t.Fatalf("ticket requests = %d, want %d: the cooldown must hold",
			ticketHitsAfterSecondKick, ticketHitsAfterFirstRun)
	}

	// Even after the cooldown, relogin-required is terminal without an explicit
	// opt-in: a data-plane kick must not restart the ladder.
	c.sessionMu.Lock()
	c.lastRecovery = time.Now().Add(-2 * sessionRecoveryCooldown)
	c.sessionMu.Unlock()
	c.reportSessionInvalid(10000004, "late detector")
	time.Sleep(100 * time.Millisecond)
	_, ticketHitsAfterLateKick, _, _ := stub.hits()
	if ticketHitsAfterLateKick != ticketHitsAfterFirstRun {
		t.Fatalf("ticket requests = %d, want %d: relogin-required must be terminal",
			ticketHitsAfterLateKick, ticketHitsAfterFirstRun)
	}
}

// TestAutoReloginIsBoundedAfterANonRetryableFailure: with -auto-relogin on, the
// cooldown is the only retry clock, and a failure that means "wrong credentials"
// or "still online" stops further attempts rather than turning every cooldown
// into another login POST.
func TestAutoReloginIsBoundedAfterANonRetryableFailure(t *testing.T) {
	stub := newRecoveryStub(t)
	stub.refuseEveryRenewal()
	stub.set(`{"code":500,"message":"no"}`, &stub.ticketBody)
	c := recoveringClient(t, stub)

	c.sessionMu.Lock()
	c.autoRelogin = true
	c.loginMethod = auth.PasswordLogin{}
	c.loginOptions = auth.LoginOptions{DeviceID: "device"}
	c.sessionMu.Unlock()

	c.reportSessionInvalid(75500002, "detector")
	waitForState(t, c, SessionReloginRequired)

	c.sessionMu.RLock()
	blocked := c.reloginBlocked
	c.sessionMu.RUnlock()
	if !blocked {
		t.Fatal("a non-retryable login failure did not stop further attempts")
	}

	authConfigHitsBefore := stub.authConfigHitsFor(t)
	c.sessionMu.Lock()
	c.lastRecovery = time.Now().Add(-2 * sessionRecoveryCooldown)
	c.sessionMu.Unlock()
	c.reportSessionInvalid(75500002, "late detector")
	time.Sleep(100 * time.Millisecond)
	if got := stub.authConfigHitsFor(t); got != authConfigHitsBefore {
		t.Fatalf("authConfig calls = %d, want %d: a blocked re-login must not retry",
			got, authConfigHitsBefore)
	}
}

// TestReloginMakesOneAttempt: the ladder already has a cooldown, so a single
// relogin call must not stack immediate retries on top of it.
func TestReloginMakesOneAttempt(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	c := NewClient(ClientOptions{})
	t.Cleanup(c.Close)
	c.sessionMu.Lock()
	c.session = auth.NewSession(strings.TrimPrefix(server.URL, "https://"), nil)
	c.loginMethod = auth.PasswordLogin{}
	c.loginOptions = auth.LoginOptions{DeviceID: "device"}
	c.sessionMu.Unlock()

	if err := c.relogin(context.Background()); err == nil {
		t.Fatal("relogin succeeded against a 500")
	}
	if hits != 1 {
		t.Fatalf("login attempts = %d, want 1", hits)
	}
}

// TestRenewalFailureRunsTheLadderOnce: the renewal is the detector that runs on a
// schedule, so a refused renewal must start exactly one ladder run - and the loop
// must not pile further renewals onto a session that already needs a new login.
func TestRenewalFailureRunsTheLadderOnce(t *testing.T) {
	stub := newRecoveryStub(t)
	stub.refuseEveryRenewal()
	stub.set(`{"code":500,"message":"no"}`, &stub.ticketBody)
	c := recoveringClient(t, stub)

	c.sessionMu.Lock()
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device"}
	c.sessionMu.Unlock()
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) {
		return auth.LoginResult{}, fmt.Errorf("refresh rejected: %w", auth.ErrSessionInvalid)
	}, 5*time.Millisecond)

	waitForState(t, c, SessionReloginRequired)

	_, ticketHits, _, _ := stub.hits()
	authConfigHitsBefore := stub.authConfigHitsFor(t)
	time.Sleep(50 * time.Millisecond)
	_, ticketHitsAfter, _, _ := stub.hits()
	if ticketHitsAfter != ticketHits {
		t.Fatalf("ticket requests = %d, want %d: one ladder run", ticketHitsAfter, ticketHits)
	}
	if authConfigHitsAfter := stub.authConfigHitsFor(t); authConfigHitsAfter-authConfigHitsBefore > 1 {
		t.Fatalf("renewals after the ladder = %d, want at most one: the loop must pause",
			authConfigHitsAfter-authConfigHitsBefore)
	}
}

// TestPrepareRestoreTicketStoresOneWhileTheSessionIsAlive: the exchange needs a
// live session, so the ticket has to be taken before the session dies; without it
// the ladder has nothing to restore from.
func TestPrepareRestoreTicketStoresOneWhileTheSessionIsAlive(t *testing.T) {
	stub := newRecoveryStub(t)
	c := recoveringClient(t, stub)

	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	c.prepareRestoreTicket(context.Background(), session)

	if got := c.sidTicket(); len(got) != 73 {
		t.Fatalf("sidTicket length = %d, want the 73 characters the gateway returns", len(got))
	}
	if _, ticketHits, _, _ := stub.hits(); ticketHits != 1 {
		t.Fatalf("ticket exchanges = %d, want 1", ticketHits)
	}

	// Holding one is enough: a second call must not spend another exchange.
	c.prepareRestoreTicket(context.Background(), session)
	if _, ticketHits, _, _ := stub.hits(); ticketHits != 1 {
		t.Fatalf("ticket exchanges after the second call = %d, want 1", ticketHits)
	}
}

func TestPrepareRestoreTicketSurvivesARefusal(t *testing.T) {
	stub := newRecoveryStub(t)
	stub.set(`{"code":500,"message":"no"}`, &stub.ticketBody)
	c := recoveringClient(t, stub)

	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	// Best effort: a portal that will not hand out a ticket must not break setup.
	c.prepareRestoreTicket(context.Background(), session)

	if got := c.sidTicket(); got != "" {
		t.Fatalf("sidTicket = %q, want nothing stored", got)
	}
}

// TestRenewalPausesOnlyWhileALoginIsPending: a restore that is waiting for tunnel
// traffic must not stop the renewals - if nothing ever confirms the restore, the
// renewal is the only thing left that would notice the session dying again.
func TestRenewalPausesOnlyWhileALoginIsPending(t *testing.T) {
	stub := newRecoveryStub(t)
	c := recoveringClient(t, stub)

	c.sessionMu.Lock()
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device"}
	c.sessionMu.Unlock()

	renewals := make(chan struct{}, 16)
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) {
		select {
		case renewals <- struct{}{}:
		default:
		}
		return auth.LoginResult{SID: "new", Cookies: []auth.Cookie{{Name: "sid", Value: "new"}}}, nil
	}, 5*time.Millisecond)
	defer c.Close()

	awaitRenewal := func(what string) {
		t.Helper()
		select {
		case <-renewals:
		case <-time.After(2 * time.Second):
			t.Fatalf("no renewal happened while %s", what)
		}
	}

	awaitRenewal("the session is online")

	c.setSessionState(SessionRestoring, "test", 0)
	awaitRenewal("a restore is waiting for tunnel traffic")

	c.setSessionState(SessionReloginRequired, "test", 0)
	time.Sleep(50 * time.Millisecond)
	select {
	case <-renewals:
		t.Fatal("renewals continued while a re-login is pending")
	default:
	}
}

// TestMintedTicketIsPersistedForRestarts is the regression for the live find of
// 2026-10-17: the ticket was minted and held in memory, but never written to the
// record - so a restart lost it and the ladder had nothing to restore from.
func TestMintedTicketIsPersistedForRestarts(t *testing.T) {
	stub := newRecoveryStub(t)
	c := recoveringClient(t, stub)

	var saved []byte
	c.sessionMu.Lock()
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device"}
	c.saveClientData = func(data []byte) error {
		saved = append([]byte(nil), data...)
		return nil
	}
	c.sessionMu.Unlock()

	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	c.prepareRestoreTicket(context.Background(), session)
	if len(saved) == 0 {
		t.Fatal("nothing was persisted")
	}

	var record auth.ClientAuthData
	if err := json.Unmarshal(saved, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.SIDTicket) != 73 {
		t.Fatalf("persisted sid_ticket length = %d, want 73: a restart would lose the ticket", len(record.SIDTicket))
	}
}

// TestStaleTicketIsReplacedOnce: the gateway refused the stored ticket when the
// session had died, so the ladder asks for a fresh one - and only once.
func TestStaleTicketIsReplacedOnce(t *testing.T) {
	stub := newRecoveryStub(t)
	// The first renewal is refused (that is the detector), the restore's own calls
	// are answered; the first session exchange refuses the stored ticket.
	stub.refuseExchanges(1)
	c := recoveringClient(t, stub)

	c.sessionMu.Lock()
	c.SIDTicket = strings.Repeat("s", 73)
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device"}
	c.sessionMu.Unlock()

	c.reportSessionInvalid(75500002, "test")
	waitForState(t, c, SessionRestoring)
	time.Sleep(100 * time.Millisecond)

	_, ticketHits, exchangeHits, _ := stub.hits()
	if ticketHits != 1 {
		t.Fatalf("ticket mints = %d, want exactly one after a stale refusal", ticketHits)
	}
	if exchangeHits != 2 {
		t.Fatalf("session exchanges = %d, want the refused one and the retry", exchangeHits)
	}
	if state := c.currentSessionState(); state != SessionRestoring {
		t.Fatalf("state = %q, want %q until traffic confirms the restore", state, SessionRestoring)
	}
}

func TestRetryableReloginError(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want bool
	}{
		{"a temporary network error", errors.New("dial tcp: connection refused"), true},
		{"still online server-side", &auth.PortalCodeError{Op: "login", Code: 75500006, Message: "当前账号已在线"}, false},
		{"a stale random check code", &auth.PortalCodeError{Op: "login", Code: 75500307}, false},
		{"a refused ticket", &auth.PortalCodeError{Op: "login", Code: 75500304}, false},
		{"a dead session", auth.ErrSessionInvalid, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryableReloginError(tt.err); got != tt.want {
				t.Fatalf("retryableReloginError(%v) = %t, want %t", tt.err, got, tt.want)
			}
		})
	}
}

func TestSessionCodeFromError(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want int64
	}{
		{&auth.PortalCodeError{Op: "authConfig", Code: 75500002}, 75500002},
		{&auth.PortalCodeError{Op: "sessionIdExchange", Code: 10000004}, 10000004},
		{errors.New("no code here"), 0},
		{nil, 0},
	} {
		if got := sessionCodeFromError(tt.err); got != tt.want {
			t.Fatalf("sessionCodeFromError(%v) = %d, want %d", tt.err, got, tt.want)
		}
	}
}
