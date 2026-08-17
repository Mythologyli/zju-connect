package mobile

import (
	"crypto/tls"
	"sync"

	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/internal/underlay"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack/tun"
)

var vpnClient *easyconnect.Client
var vpnUnderlay *underlay.Dialer
var vpnClientMu sync.Mutex
var loginMu sync.Mutex

func Login(server string, username string, password string) string {
	log.Init()

	return login(server, username, password)
}

func DebugLogin(server string, username string, password string) string {
	log.Init()
	log.EnableDebug()

	return login(server, username, password)
}

func Logout() {
	vpnClientMu.Lock()
	defer vpnClientMu.Unlock()

	if vpnClient != nil {
		vpnClient.Close()
		vpnClient = nil
	}
	if vpnUnderlay != nil {
		_ = vpnUnderlay.Close()
		vpnUnderlay = nil
	}
}

func login(server string, username string, password string) string {
	loginMu.Lock()
	defer loginMu.Unlock()

	newUnderlay, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		return ""
	}
	newClient := easyconnect.NewClient(
		server,
		username,
		password,
		"",
		tls.Certificate{},
		"",
		false,
		false,
		false,
		newUnderlay,
		nil,
	)

	// Close the old client and clear vpnClient to nil during setup so that
	// concurrent StartStack calls see nil and return early rather than
	// operating on an uninitialized client.
	vpnClientMu.Lock()
	old := vpnClient
	oldUnderlay := vpnUnderlay
	vpnClient = nil
	vpnUnderlay = nil
	vpnClientMu.Unlock()
	if old != nil {
		old.Close()
	}
	if oldUnderlay != nil {
		_ = oldUnderlay.Close()
	}

	err = newClient.Setup("")
	if err != nil {
		newClient.Close()
		_ = newUnderlay.Close()
		return ""
	}

	log.Printf("EasyConnect client started")

	clientIP, err := newClient.IP()
	if err != nil {
		newClient.Close()
		_ = newUnderlay.Close()
		return ""
	}

	vpnClientMu.Lock()
	vpnClient = newClient
	vpnUnderlay = newUnderlay
	vpnClientMu.Unlock()

	return clientIP.String()
}

func StartStack(fd int) {
	vpnClientMu.Lock()
	client := vpnClient
	vpnClientMu.Unlock()
	if client == nil {
		return
	}

	vpnTUNStack, err := tun.NewStack(client, false, false, nil)
	if err != nil {
		return
	}

	vpnTUNStack.SetupTun(fd)
	vpnTUNStack.Run()
}
