package main

import (
	"flag"
	"fmt"
	"github.com/mythologyli/zju-connect/core"
	"os"
)

func main() {
	// CLI args
	host, port, username, password, disableServerConfig, disableZjuConfig, disableZjuDns, twfId := "", 0, "", "", false, false, false, ""
	flag.StringVar(&host, "server", "rvpn.zju.edu.cn", "EasyConnect server address")
	flag.IntVar(&port, "port", 443, "EasyConnect port address")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&disableServerConfig, "disable-server-config", false, "Don't parse server config")
	flag.BoolVar(&disableZjuConfig, "disable-zju-config", false, "Don't use ZJU config")
	flag.BoolVar(&disableZjuDns, "disable-zju-dns", false, "Use local DNS instead of ZJU DNS")
	flag.BoolVar(&core.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The address SOCKS5 server listens on (e.g. 127.0.0.1:1080)")
	flag.StringVar(&core.SocksUser, "socks-user", "", "SOCKS5 username, default is don't use auth")
	flag.StringVar(&core.SocksPasswd, "socks-passwd", "", "SOCKS5 password, default is don't use auth")
	flag.StringVar(&core.HttpBind, "http-bind", ":1081", "The address HTTP server listens on (e.g. 127.0.0.1:1081)")
	flag.Uint64Var(&core.DnsTTL, "dns-ttl", 3600, "DNS record time to live, unit is second")
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")

	flag.Parse()

	if disableServerConfig {
		core.ParseServConfig = false
	} else {
		core.ParseServConfig = true
	}

	if disableZjuConfig {
		core.ParseZjuConfig = false
	} else {
		core.ParseZjuConfig = true
	}

	if disableZjuDns {
		core.UseZjuDns = false
	} else {
		core.UseZjuDns = true
	}

	if host == "" || ((username == "" || password == "") && twfId == "") {
		fmt.Println("ZJU Connect")
		fmt.Println("Please see: https://github.com/mythologyli/zju-connect")
		fmt.Printf("\nUsage: %s -username <username> -password <password>\n", os.Args[0])
		fmt.Println("\nFull usage:")
		flag.PrintDefaults()
	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
