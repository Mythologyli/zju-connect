package main

import (
	"flag"
	"log"

	"ZJUConnect/core"
	"ZJUConnect/listener"
)

func main() {
	// CLI args
	host, port, username, password, twfId := "", 0, "", "", ""
	flag.StringVar(&host, "server", "", "EasyConnect server address (e.g. rvpn.zju.edu.cn)")
	flag.IntVar(&port, "port", 443, "EasyConnect port address (e.g. 443)")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&core.ParseServConfig, "parse", false, "Parse server config. Typically set")
	flag.BoolVar(&core.ParseZjuConfig, "parse-zju", false, "Parse ZJU config. Typically set")
	flag.BoolVar(&core.UseZjuDns, "use-zju-dns", false, "Use ZJU DNS. Typically set")
	flag.BoolVar(&core.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The address SOCKS5 server listens on (e.g. 0.0.0.0:1080)")
	flag.StringVar(&core.SocksUser, "socks-user", "", "SOCKS5 username, default is don't use auth")
	flag.StringVar(&core.SocksPasswd, "socks-passwd", "", "SOCKS5 password, default is don't use auth")
	flag.StringVar(&core.HttpBind, "http-bind", ":1081", "The address HTTP server listens on (e.g. 0.0.0.0:1081)")
	flag.Uint64Var(&core.DnsTTL, "dns-ttl", 3600, "DNS record time to live, unit is second")
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")

	flag.Parse()

	if host == "" || ((username == "" || password == "") && twfId == "") {
		log.Printf("Starting as ECAgent mode. For more infomations: `ZJUConnect --help`.\n")
		listener.StartECAgent()
	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
