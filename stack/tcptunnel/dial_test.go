package tcptunnel

import (
	"context"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/resolve"
)

func TestDialTCPAllowsTCPPrefL3FallbackInTCPOnlyMode(t *testing.T) {
	resource := client.IPResource{EnableTCPPrefL3: true}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyIPResource, resource)
	client := &fallbackCapturingClient{}
	stack := &Stack{client: client}

	if _, err := stack.DialTCP(ctx, &net.TCPAddr{IP: net.IPv4(192, 0, 2, 120), Port: 2222}); err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	if !client.ignoreTCPPrefL3 {
		t.Fatal("TCP-only stack did not allow TCP fallback for a TCP-prefers-L3 resource")
	}
}

type fallbackCapturingClient struct {
	client.Client
	ignoreTCPPrefL3 bool
}

func (*fallbackCapturingClient) CanUseTCPTunnel() bool { return true }
func (c *fallbackCapturingClient) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	c.ignoreTCPPrefL3 = resolve.IgnoreTCPPrefL3(ctx)
	return nil, nil
}
