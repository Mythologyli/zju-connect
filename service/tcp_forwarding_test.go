package service

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/resolve"
)

func TestHandleTCPForwardingRequestUsesResourceAwareDialer(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	var gotNetwork, gotAddress string
	dialErr := errors.New("dial failed")
	handleTCPForwardingRequest(func(_ context.Context, network, address string) (net.Conn, error) {
		gotNetwork = network
		gotAddress = address
		return nil, dialErr
	}, server, "10.1.0.1:22")

	if gotNetwork != "tcp" || gotAddress != "10.1.0.1:22" {
		t.Fatalf("dial = (%q, %q), want (tcp, 10.1.0.1:22)", gotNetwork, gotAddress)
	}

	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("client connection read error = %v, want closed connection", err)
	}
}

func TestTCPForwardingCarriesMatchingL3ResourceToStack(t *testing.T) {
	resource := client.IPResource{
		IPMin:           net.IPv4(192, 0, 2, 1),
		IPMax:           net.IPv4(192, 0, 2, 254),
		PortMin:         1,
		PortMax:         65535,
		Protocol:        "tcp",
		AppID:           "test-l3-app",
		NodeGroupID:     "test-node-group",
		EnableTCPPrefL3: true,
	}
	stack := &forwardingCapturingStack{}
	dialer := dial.NewDialer(stack, nil, []client.IPResource{resource}, false, "")
	server, localClient := net.Pipe()
	defer localClient.Close()

	handleTCPForwardingRequest(dialer.Dial, server, "192.0.2.120:2222")

	if stack.address == nil || !stack.address.IP.Equal(net.IPv4(192, 0, 2, 120)) || stack.address.Port != 2222 {
		t.Fatalf("stack address = %v, want 192.0.2.120:2222", stack.address)
	}
	if stack.resource.AppID != resource.AppID || stack.resource.NodeGroupID != resource.NodeGroupID {
		t.Fatalf("stack resource = %#v, want app %q and node group %q", stack.resource, resource.AppID, resource.NodeGroupID)
	}
	if !stack.prefersL3 {
		t.Fatal("stack context does not mark the matched resource as TCP-prefers-L3")
	}
}

type forwardingCapturingStack struct {
	address   *net.TCPAddr
	resource  client.IPResource
	prefersL3 bool
}

func (*forwardingCapturingStack) Run()                                                {}
func (*forwardingCapturingStack) SetupResolve(zcdns.LocalServer)                      {}
func (*forwardingCapturingStack) SetupIPPool(*ippool.IPPool[[]client.DomainResource]) {}
func (s *forwardingCapturingStack) DialTCP(ctx context.Context, address *net.TCPAddr) (net.Conn, error) {
	s.address = address
	s.resource, _ = ctx.Value(resolve.ContextKeyIPResource).(client.IPResource)
	s.prefersL3 = resolve.TCPPrefersL3(ctx)
	return nil, errors.New("stop after capturing stack call")
}
func (*forwardingCapturingStack) DialUDP(context.Context, *net.UDPAddr) (net.Conn, error) {
	return nil, errors.New("unexpected UDP dial")
}
