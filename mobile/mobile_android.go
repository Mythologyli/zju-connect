package mobile

import (
	"crypto/tls"
	"sync"

	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack/tun"
)

var vpnClient *easyconnect.Client
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
}

func login(server string, username string, password string) string {
	loginMu.Lock()
	defer loginMu.Unlock()

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
	)

	// Close the old client and clear vpnClient to nil during setup so that
	// concurrent StartStack calls see nil and return early rather than
	// operating on an uninitialized client.
	vpnClientMu.Lock()
	old := vpnClient
	vpnClient = nil
	vpnClientMu.Unlock()
	if old != nil {
		old.Close()
	}

	err := newClient.Setup("", "", false)
	if err != nil {
		newClient.Close()
		return ""
	}

	log.Printf("EasyConnect client started")

	clientIP, err := newClient.IP()
	if err != nil {
		newClient.Close()
		return ""
	}

	vpnClientMu.Lock()
	vpnClient = newClient
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

	vpnTUNStack, err := tun.NewStack(client)
	if err != nil {
		return
	}

	vpnTUNStack.SetupTun(fd)
	vpnTUNStack.Run()
}
