package mobile

import (
	"crypto/tls"
	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack/tun"
)

var vpnClient *easyconnect.Client

func Login(server string, username string, password string) string {
	log.Init()

	vpnClient = easyconnect.NewClient(
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
	err := vpnClient.Setup()
	if err != nil {
		return ""
	}

	log.Printf("EasyConnect client started")

	clientIP, err := vpnClient.IP()
	if err != nil {
		return ""
	}

	return clientIP.String()
}

func DebugLogin(server string, username string, password string) string {
	log.Init()
	log.EnableDebug()

	vpnClient = easyconnect.NewClient(
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
	err := vpnClient.Setup()
	if err != nil {
		return ""
	}

	log.Printf("EasyConnect client started")

	clientIP, err := vpnClient.IP()
	if err != nil {
		return ""
	}

	return clientIP.String()
}

func StartStack(fd int) {
	vpnTUNStack, err := tun.NewStack(vpnClient)
	if err != nil {
		return
	}

	vpnTUNStack.SetupTun(fd)
	vpnTUNStack.Run()
}
