package service

import (
	"bytes"
	"context"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/resolve"
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

// TestKeepAliveRoundUsesTheFirstAnsweringTarget: each target is tried once, in
// preference order; a failed target is not retried, because the next round is
// the retry.
func TestKeepAliveRoundUsesTheFirstAnsweringTarget(t *testing.T) {
	var firstRequests atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstRequests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer second.Close()

	target, ok := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), []KeepAliveTarget{
		{URL: first.URL, Named: true},
		{URL: second.URL, Named: true},
	}, "")
	if !ok || target != second.URL {
		t.Fatalf("round = (%q, %t), want (%q, true)", target, ok, second.URL)
	}
	if got := firstRequests.Load(); got != 1 {
		t.Fatalf("first target requests = %d, want 1 (no within-round retry)", got)
	}
}

func TestKeepAliveRoundReportsWhenNoTargetAnswers(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	target, ok := keepAliveRound(context.Background(), keepAliveClientFor(fakeDialer{}), []KeepAliveTarget{
		{URL: server.URL, Named: true},
	}, "")
	if ok || target != "" {
		t.Fatalf("round = (%q, %t), want no target", target, ok)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
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

// TestKeepAliveFallsBackToRemoteDNSWithALabel: a name lookup is not application
// traffic, and the fallback line has to say so.
func TestKeepAliveFallsBackToRemoteDNSWithALabel(t *testing.T) {
	oldOutput := stdlog.Writer()
	var output bytes.Buffer
	stdlog.SetOutput(&output)
	t.Cleanup(func() { stdlog.SetOutput(oldOutput) })

	// A zero resolver has no remote resolvers, so the fallback logs and returns.
	KeepAlive(context.Background(), &resolve.Resolver{}, fakeDialer{}, KeepAliveOptions{})

	got := output.String()
	if !strings.Contains(got, "not application traffic") {
		t.Fatalf("fallback log does not label the probe: %q", got)
	}
	if !strings.Contains(got, "No remote resolver available") {
		t.Fatalf("fallback log does not explain the missing resolver: %q", got)
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
