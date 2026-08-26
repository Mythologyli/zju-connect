package atrust

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type blockingUnderlayDialer struct{}

func (blockingUnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingUnderlayDialer) ExcludeIP(net.IP) {}

func TestSetupContextCancellationReachesManifestDial(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(ctx, SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetupContext did not cancel in-flight manifest dial")
	}
}

func TestClientCloseCancelsSetupContext(t *testing.T) {
	client := NewClient(ClientOptions{UnderlayDialer: blockingUnderlayDialer{}})
	done := make(chan error, 1)
	go func() {
		_, err := client.SetupContext(context.Background(), SetupOptions{ServerAddress: "vpn.example", ServerPort: 443})
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not cancel in-flight setup")
	}
}
