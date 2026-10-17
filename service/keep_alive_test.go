package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/dial"
)

// fakeDialer stands in for the tunnel. The keep-alive only opens connections
// through it, so a test can make it fail the way the gateway does.
type fakeDialer struct {
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d fakeDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dial == nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	return d.dial(ctx, network, address)
}

func keepAliveClientFor(dialer KeepAliveDialer) *http.Client {
	return &http.Client{
		Transport: &http.Transport{DialContext: dialer.Dial, DisableKeepAlives: true},
	}
}

// shrinkRetryBudget keeps the retry budget but removes the wait, so a test does
// not spend seconds proving that a retry happens.
func shrinkRetryBudget(t *testing.T) {
	t.Helper()
	attempts, delay := keepAliveAttempts, keepAliveRetryDelay
	keepAliveRetryDelay = time.Millisecond
	t.Cleanup(func() {
		keepAliveAttempts, keepAliveRetryDelay = attempts, delay
	})
}

// TestKeepAliveClassifiesADeadSession covers the outcome the ladder has to act
// on: the tunnel is up, the session behind it is not. The error text is what the
// gateway answered through the tunnel when the session was gone (observed on the gateway).
func TestKeepAliveClassifiesADeadSession(t *testing.T) {
	shrinkRetryBudget(t)

	dialer := fakeDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 10.0.0.1:80: tcp tunnel authentication failed " +
			"(code 10000030): sig or deviceId verify failed")
	}}

	result := keepAliveRound(context.Background(), keepAliveClientFor(dialer), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: "http://10.0.0.1/", Named: true}},
	}, "")

	if result.Category != KeepAliveSession {
		t.Fatalf("category = %q, want %q (err=%v)", result.Category, KeepAliveSession, result.Err)
	}
	if result.Code != 10000030 {
		t.Fatalf("code = %d, want 10000030", result.Code)
	}
}

func TestClassifyKeepAliveError(t *testing.T) {
	for _, tt := range []struct {
		name         string
		err          error
		wantCategory KeepAliveCategory
		wantCode     int
	}{
		{"invalid sid on the data path", errors.New("10000004 invalid SID"), KeepAliveSession, 10000004},
		{"expired session", errors.New("server answered code 75500002"), KeepAliveSession, 75500002},
		{"session message without a code", errors.New("session timeout"), KeepAliveSession, 0},
		{"acl denied", fmt.Errorf("dial: %w", dial.ErrACLDenied), KeepAliveTargetFailure, 0},
		{"our own timeout", context.DeadlineExceeded, KeepAliveTransport, 0},
		{"a reset connection", errors.New("read tcp: connection reset by peer"), KeepAliveTransport, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			category, code := classifyKeepAliveError(tt.err)
			if category != tt.wantCategory || code != tt.wantCode {
				t.Fatalf("classify(%v) = (%q, %d), want (%q, %d)",
					tt.err, category, code, tt.wantCategory, tt.wantCode)
			}
		})
	}
}

// TestKeepAliveRoundRetriesANamedTarget: the userspace netstack drops an
// occasional connection on its own, so a single failed attempt must not be
// reported as a failure of the round.
func TestKeepAliveRoundRetriesANamedTarget(t *testing.T) {
	shrinkRetryBudget(t)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count := requests.Add(1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: server.URL, Named: true}},
	}, "")

	if result.Category != KeepAliveOK {
		t.Fatalf("category = %q, want %q (err=%v)", result.Category, KeepAliveOK, result.Err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 (the round must use its whole retry budget)", got)
	}
}

func TestKeepAliveRoundReportsANonAnsweringTarget(t *testing.T) {
	shrinkRetryBudget(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	result := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: server.URL, Named: true}},
	}, "")

	if result.Category != KeepAliveTargetFailure {
		t.Fatalf("category = %q, want %q", result.Category, KeepAliveTargetFailure)
	}
	if result.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", result.Status, http.StatusNotFound)
	}
}

func TestKeepAliveReportsRouting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: server.URL}},
		Routing: func(context.Context, string) (string, error) { return string(dial.RoutingTunnel), nil },
	}, "")

	if result.Category != KeepAliveOK {
		t.Fatalf("category = %q, want %q", result.Category, KeepAliveOK)
	}
	if result.Routing != string(dial.RoutingTunnel) {
		t.Fatalf("routing = %q, want %q", result.Routing, dial.RoutingTunnel)
	}

	// A target reached over the underlay answers, but it proves nothing about the
	// tunnel: the round still succeeds and the routing says why it was useless.
	direct := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: server.URL}},
		Routing: func(context.Context, string) (string, error) { return string(dial.RoutingDirect), nil },
	}, "")

	if direct.Category != KeepAliveOK || direct.Routing != string(dial.RoutingDirect) {
		t.Fatalf("direct round = (%q, %q), want (%q, %q)",
			direct.Category, direct.Routing, KeepAliveOK, dial.RoutingDirect)
	}
}

// TestKeepAliveRefusesADeniedTarget: an address outside the granted resources
// would make the gateway shut the L3 tunnel down, so it is a configuration
// problem and must never be dialled.
func TestKeepAliveRefusesADeniedTarget(t *testing.T) {
	shrinkRetryBudget(t)

	var dialled bool
	dialer := fakeDialer{dial: func(context.Context, string, string) (net.Conn, error) {
		dialled = true
		return nil, errors.New("must not be dialled")
	}}

	result := keepAliveRound(context.Background(), keepAliveClientFor(dialer), KeepAliveOptions{
		Targets: []KeepAliveTarget{{URL: "http://192.0.2.9/", Named: true}},
		Routing: func(context.Context, string) (string, error) { return string(dial.RoutingDenied), nil },
	}, "")

	if result.Category != KeepAliveTargetFailure {
		t.Fatalf("category = %q, want %q", result.Category, KeepAliveTargetFailure)
	}
	if dialled {
		t.Fatal("a denied target was dialled")
	}
}

// TestKeepAliveOpensAFreshConnectionPerProbe pins the deliberate choice of one
// connection per probe: an idle tunnel connection between probes buys nothing,
// hides routing changes and is dropped by the userspace netstack anyway.
func TestKeepAliveOpensAFreshConnectionPerProbe(t *testing.T) {
	type connIDKey struct{}

	var nextID atomic.Int64
	ids := make(chan int64, 4)

	server := httptest.NewUnstartedServer(nil)
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connIDKey{}, nextID.Add(1))
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := r.Context().Value(connIDKey{}).(int64); ok {
			select {
			case ids <- id:
			default:
			}
		}
		_, _ = w.Write([]byte("ok"))
	})
	server.Start()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		KeepAlive(ctx, nil, fakeDialer{}, KeepAliveOptions{
			Targets:  []KeepAliveTarget{{URL: server.URL, Named: true}},
			Interval: 20 * time.Millisecond,
		})
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	seen := make([]int64, 0, 2)
	for len(seen) < 2 {
		select {
		case id := <-ids:
			seen = append(seen, id)
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d keepalive requests arrived", len(seen))
		}
	}
	if seen[0] == seen[1] {
		t.Fatalf("both probes arrived on connection %d; each probe must open its own", seen[0])
	}
}

// TestKeepAliveReportsAFailureStreakAndItsRecovery drives the loop, not just a
// round: the session dies for one round, comes back in the next, and the handler
// has to see both.
func TestKeepAliveReportsAFailureStreakAndItsRecovery(t *testing.T) {
	shrinkRetryBudget(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	var calls int64
	dialer := fakeDialer{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		calls++
		if calls <= int64(keepAliveAttempts) {
			return nil, errors.New("tcp tunnel authentication failed (code 10000030): sig or deviceId verify failed")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}

	var mu sync.Mutex
	var results []KeepAliveResult
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		KeepAlive(ctx, nil, dialer, KeepAliveOptions{
			Targets:  []KeepAliveTarget{{URL: server.URL, Named: true}},
			Interval: 20 * time.Millisecond,
			Handler: func(result KeepAliveResult) {
				mu.Lock()
				defer mu.Unlock()
				if len(results) < 2 {
					results = append(results, result)
				}
			},
		})
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := len(results)
		mu.Unlock()
		if got >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(results) != 2 {
		t.Fatalf("handler calls = %d, want 2 (the failure and the recovery)", len(results))
	}
	if results[0].Category != KeepAliveSession || results[0].ConsecutiveFailures != 1 {
		t.Fatalf("first report = (%q, %d failures), want (%q, 1)",
			results[0].Category, results[0].ConsecutiveFailures, KeepAliveSession)
	}
	if results[1].Category != KeepAliveOK || results[1].ConsecutiveFailures != 1 {
		t.Fatalf("second report = (%q, %d failures), want (%q, 1)",
			results[1].Category, results[1].ConsecutiveFailures, KeepAliveOK)
	}
}

type fakeRouter struct {
	addresses []string
}

func (r *fakeRouter) TargetRouting(_ context.Context, network, address string) (dial.Routing, error) {
	r.addresses = append(r.addresses, network+" "+address)
	return dial.RoutingTunnel, nil
}

// TestKeepAliveRoutingDerivesThePort: the routing label is only as good as the
// address it asks about, and the URL scheme decides the default port.
func TestKeepAliveRoutingDerivesThePort(t *testing.T) {
	router := &fakeRouter{}
	routing := KeepAliveRouting(router)

	for _, tt := range []struct {
		target      string
		wantAddress string
	}{
		{"http://10.0.0.1/", "10.0.0.1:80"},
		{"http://10.0.0.1:8080/app", "10.0.0.1:8080"},
		{"https://app.example.com/", "app.example.com:443"},
	} {
		got, err := routing(context.Background(), tt.target)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(dial.RoutingTunnel) {
			t.Fatalf("routing(%s) = %q, want %q", tt.target, got, dial.RoutingTunnel)
		}
		if last := router.addresses[len(router.addresses)-1]; last != "tcp "+tt.wantAddress {
			t.Fatalf("asked about %q, want %q", last, "tcp "+tt.wantAddress)
		}
	}
}

func TestKeepAliveOrderPutsTheWorkingTargetFirst(t *testing.T) {
	targets := []KeepAliveTarget{
		{URL: "http://a/", Named: true},
		{URL: "http://b/", Named: true},
		{URL: "http://c/"},
		{URL: "http://d/"},
	}

	ordered := keepAliveOrder(targets, "http://c/")
	want := []string{"http://c/", "http://a/", "http://b/", "http://d/"}
	for i, target := range ordered {
		if target.URL != want[i] {
			t.Fatalf("order = %v, want %v", urls(ordered), want)
		}
	}
}

func urls(targets []KeepAliveTarget) []string {
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.URL)
	}
	return out
}
