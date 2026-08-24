package client_test

import (
	"context"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/underlay"
)

type externalUnderlay struct{}

func (externalUnderlay) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (externalUnderlay) ExcludeIP(net.IP) {}

var (
	_ client.UnderlayDialer = externalUnderlay{}
	_ client.UnderlayDialer = (*underlay.Dialer)(nil)
)

func TestPublicClientsAcceptExternalUnderlay(t *testing.T) {
	var dialer client.UnderlayDialer = externalUnderlay{}

	easyClient := easyconnect.NewClient(easyconnect.Options{
		Server:         "vpn.example.com:443",
		UnderlayDialer: dialer,
	})
	if easyClient == nil {
		t.Fatal("easyconnect.NewClient returned nil")
	}
	easyClient.Close()

	aTrustClient := atrust.NewClient(atrust.ClientOptions{UnderlayDialer: dialer})
	if aTrustClient == nil {
		t.Fatal("atrust.NewClient returned nil")
	}
	aTrustClient.Close()
}
