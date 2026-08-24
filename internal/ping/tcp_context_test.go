package ping

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTCPingStartContextStopsBlockedDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	tcping := NewTCPing()
	tcping.SetTarget(&Target{
		Protocol: TCP,
		Host:     "node.example.test",
		Port:     443,
		Counter:  1,
		Interval: time.Millisecond,
		Timeout:  time.Minute,
	})
	tcping.SetDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	done := tcping.StartContext(ctx)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe never started its dial")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not stop after context cancellation")
	}
	if result := tcping.Result(); result.Counter != 0 || result.SuccessCounter != 0 {
		t.Fatalf("cancelled probe result = %+v, want no completed attempt", result)
	}
}

func TestTCPingStopInterruptsBlockedDial(t *testing.T) {
	started := make(chan struct{})
	dialCancelled := make(chan error, 1)
	tcping := NewTCPing()
	tcping.SetTarget(&Target{
		Protocol: TCP,
		Host:     "node.example.test",
		Port:     443,
		Counter:  1,
		Interval: time.Millisecond,
		Timeout:  time.Minute,
	})
	tcping.SetDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		dialCancelled <- ctx.Err()
		return nil, ctx.Err()
	})

	done := tcping.Start()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe never started its dial")
	}
	tcping.Stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe did not stop")
	}
	if result := tcping.Result(); result.Counter != 0 || result.SuccessCounter != 0 {
		t.Fatalf("stopped probe result = %+v, want no completed attempt", result)
	}
	select {
	case err := <-dialCancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial context error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked dial did not observe Stop cancellation")
	}
}
