package main

import (
	"ZJUConnect/core"
	"flag"
	"fmt"
	"os"
    "github.com/BurntSushi/toml"
)

type Config struct {
    Username string
    Password string
    Server string
    ServerPort int
    Parse bool
    ParseZju bool
    UseZJUDns bool
    ProxyAll bool
    SocksBind string
    SocksUser string
    SocksPasswd string
    HTTPBind string
    DnsTTL uint64
    DebugDump bool
}

func main() {
	// CLI args
	host, port, username, password, twfId, config_file := "", 0, "", "", "", ""
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
    flag.StringVar(&config_file, "config", "", "Config file for ZJUConnect")

	flag.Parse()
	
	if config_file != "" {
        var conf Config
        if _, err := toml.DecodeFile(config_file, &conf); err != nil {
            fmt.Println("ZJU Connect: error parsing the configuration file\n")
            os.Exit(1)
        }
        core.ParseServConfig = conf.Parse
        core.ParseZjuConfig = conf.ParseZju
        core.UseZjuDns = conf.UseZJUDns
        core.ProxyAll = conf.ProxyAll
        core.SocksBind = conf.SocksBind
        core.SocksUser = conf.SocksUser
        core.SocksPasswd = conf.SocksPasswd
        core.HttpBind = conf.HTTPBind
        core.DnsTTL = conf.DnsTTL
        core.DebugDump = conf.DebugDump
        host = conf.Server
        port = conf.ServerPort
        username = conf.Username
        password = conf.Password
        core.StartClient(host, port, username, password, twfId)
        
	} else if host == "" || ((username == "" || password == "") && twfId == "") {
		fmt.Println("ZJU Connect")
		fmt.Println("Please see: https://github.com/Mythologyli/ZJU-Connect")
		fmt.Printf("\nUsage: %s -username <username> -password <password> -parse -parse-zju -use-zju-dns\n", os.Args[0])
		fmt.Println("\nFull usage:")
		flag.PrintDefaults()

	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
