package client_test

import (
	"context"
	"crypto/tls"
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

	easyClient := easyconnect.NewClient("vpn.example.com:443", "", "", "", tls.Certificate{}, "", false, false, false, dialer, nil)
	if easyClient == nil {
		t.Fatal("easyconnect.NewClient returned nil")
	}
	easyClient.Close()

	aTrustClient := atrust.NewClient("", "", "", "", dialer, nil)
	if aTrustClient == nil {
		t.Fatal("atrust.NewClient returned nil")
	}
	aTrustClient.Close()
}
