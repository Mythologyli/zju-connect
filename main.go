package main

import (
	"EasierConnect/core"
	"EasierConnect/listener"
	"flag"
	"log"
)

func main() {
	// CLI args
	host, port, username, password, twfId := "", 0, "", "", ""
	flag.StringVar(&host, "server", "", "EasyConnect server address (e.g. vpn.nju.edu.cn, sslvpn.sysu.edu.cn)")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The addr socks5 server listens on (e.g. 0.0.0.0:1080)")
	flag.StringVar(&core.HttpBind, "http-bind", ":1081", "The addr http server listens on (e.g. 0.0.0.0:1081)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.IntVar(&port, "port", 443, "EasyConnect port address (e.g. 443)")
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.BoolVar(&core.ParseServConfig, "parse", false, "Parse server config")
	flag.BoolVar(&core.ParseZjuConfig, "parse-zju", false, "Parse ZJU config")
	flag.BoolVar(&core.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.BoolVar(&core.UseZjuDns, "use-zju-dns", false, "Use ZJU DNS")
	flag.Parse()

	if host == "" || ((username == "" || password == "") && twfId == "") {
		log.Printf("Starting as ECAgent mode. For more infomations: `EasierConnect --help`.\n")
		listener.StartECAgent()
	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
