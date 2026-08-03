package resolve

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
)

func TestResolverReleasesCoordinationEntry(t *testing.T) {
	failing := failingNetResolver()
	resolver := &Resolver{
		remoteUDPResolver: failing,
		remoteTCPResolver: failing,
		secondaryResolver: failing,
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	_, _, _ = resolver.Resolve(context.Background(), "missing.example")
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("coordination entries after Resolve = %d, want 0", entries)
	}
}

func TestResolverWaitingCallerHonorsContext(t *testing.T) {
	started := make(chan struct{}, 1)
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	resolver := &Resolver{
		remoteUDPResolver: blocking,
		remoteTCPResolver: blocking,
		secondaryResolver: failingNetResolver(),
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		_, _, _ = resolver.Resolve(leaderCtx, "blocked.example")
		close(leaderDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader DNS lookup did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	result := make(chan error, 1)
	go func() {
		_, _, err := resolver.Resolve(waiterCtx, "blocked.example")
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting Resolve error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiting Resolve did not stop after context cancellation")
	}

	cancelLeader()
	select {
	case <-leaderDone:
	case <-time.After(time.Second):
		t.Fatal("leader Resolve did not stop after context cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for resolver.coordinationEntryCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("active coordination entries after cancellation = %d after timeout, want 0", entries)
	}
}

func failingNetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS unavailable")
		},
	}
}
