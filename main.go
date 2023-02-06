package main

import (
	"ZJUConnect/core"
	"flag"
	"fmt"
	"os"
)

func main() {
	// CLI args
	host, port, username, password, twfId := "", 0, "", "", ""
	flag.StringVar(&host, "server", "rvpn.zju.edu.cn", "EasyConnect server address")
	flag.IntVar(&port, "port", 443, "EasyConnect port address")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&core.ParseServConfig, "parse", false, "Parse server config. Typically set")
	flag.BoolVar(&core.ParseZjuConfig, "parse-zju", false, "Parse ZJU config. Typically set")
	flag.BoolVar(&core.UseZjuDns, "use-zju-dns", false, "Use ZJU DNS. Typically set")
	flag.BoolVar(&core.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The address SOCKS5 server listens on (e.g. 127.0.0.1:1080)")
	flag.StringVar(&core.SocksUser, "socks-user", "", "SOCKS5 username, default is don't use auth")
	flag.StringVar(&core.SocksPasswd, "socks-passwd", "", "SOCKS5 password, default is don't use auth")
	flag.StringVar(&core.HttpBind, "http-bind", ":1081", "The address HTTP server listens on (e.g. 127.0.0.1:1081)")
	flag.Uint64Var(&core.DnsTTL, "dns-ttl", 3600, "DNS record time to live, unit is second")
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")

	flag.Parse()

	if host == "" || ((username == "" || password == "") && twfId == "") {
		fmt.Println("ZJU Connect")
		fmt.Println("Please see: https://github.com/Mythologyli/ZJU-Connect")
		fmt.Printf("\nUsage: %s -username <username> -password <password> -parse -parse-zju -use-zju-dns\n", os.Args[0])
		fmt.Println("\nFull usage:")
		flag.PrintDefaults()
	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
