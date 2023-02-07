package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/mythologyli/zju-connect/core"
)

type (
	Config struct {
		ServerAddress       string
		ServerPort          int
		Username            string
		Password            string
		DisableServerConfig bool
		DisableZjuConfig    bool
		DisableZjuDns       bool
		DisableMultiLine    bool
		ProxyAll            bool
		SocksBind           string
		SocksUser           string
		SocksPasswd         string
		HttpBind            string
		DnsTTL              uint64
		DebugDump           bool
		PortForwarding      []core.SingleForwarding
	}
)

func main() {
	// CLI args
	host, port, username, password, disableServerConfig, disableZjuConfig, disableZjuDns, disableMultiLine, twfId, configFile := "", 0, "", "", false, false, false, false, "", ""
	flag.StringVar(&host, "server", "rvpn.zju.edu.cn", "EasyConnect server address")
	flag.IntVar(&port, "port", 443, "EasyConnect port address")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&disableServerConfig, "disable-server-config", false, "Don't parse server config")
	flag.BoolVar(&disableZjuConfig, "disable-zju-config", false, "Don't use ZJU config")
	flag.BoolVar(&disableZjuDns, "disable-zju-dns", false, "Use local DNS instead of ZJU DNS")
	flag.BoolVar(&disableMultiLine, "disable-multi-line", false, "Disable multi line auto select")
	flag.BoolVar(&core.ProxyAll, "proxy-all", false, "Proxy all IPv4 traffic")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The address SOCKS5 server listens on (e.g. 127.0.0.1:1080)")
	flag.StringVar(&core.SocksUser, "socks-user", "", "SOCKS5 username, default is don't use auth")
	flag.StringVar(&core.SocksPasswd, "socks-passwd", "", "SOCKS5 password, default is don't use auth")
	flag.StringVar(&core.HttpBind, "http-bind", ":1081", "The address HTTP server listens on (e.g. 127.0.0.1:1081)")
	flag.Uint64Var(&core.DnsTTL, "dns-ttl", 3600, "DNS record time to live, unit is second")
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.StringVar(&configFile, "config", "", "Config file")

	flag.Parse()

	if configFile != "" {
		var conf Config
		if _, err := toml.DecodeFile(configFile, &conf); err != nil {
			fmt.Println("ZJU Connect: error parsing the config file")
			return
		}

		host = conf.ServerAddress
		port = conf.ServerPort
		username = conf.Username
		password = conf.Password
		core.ParseServConfig = !conf.DisableServerConfig
		core.ParseZjuConfig = !conf.DisableZjuConfig
		core.UseZjuDns = !conf.DisableZjuDns
		core.TestMultiLine = !conf.DisableMultiLine
		core.ProxyAll = conf.ProxyAll
		core.SocksBind = conf.SocksBind
		core.SocksUser = conf.SocksUser
		core.SocksPasswd = conf.SocksPasswd
		core.HttpBind = conf.HttpBind
		core.DnsTTL = conf.DnsTTL
		core.DebugDump = conf.DebugDump
		core.PortForwarding = conf.PortForwarding

		if host == "" || (username == "" || password == "") {
			fmt.Println("ZJU Connect: host, username and password are required in config file")

			return
		}
	} else {
		core.ParseServConfig = !disableServerConfig
		core.ParseZjuConfig = !disableZjuConfig
		core.UseZjuDns = !disableZjuDns
		core.TestMultiLine = !disableMultiLine

		if host == "" || ((username == "" || password == "") && twfId == "") {
			fmt.Println("ZJU Connect")
			fmt.Println("Please see: https://github.com/mythologyli/zju-connect")
			fmt.Printf("\nUsage: %s -username <username> -password <password>\n", os.Args[0])
			fmt.Println("\nFull usage:")
			flag.PrintDefaults()

			return
		}

	}

	core.StartClient(host, port, username, password, twfId)
}
