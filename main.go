package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/mythologyli/zju-connect/core"
)

type (
	Config struct {
		ServerAddress       *string                `toml:"server_address"`
		ServerPort          *int                   `toml:"server_port"`
		Username            *string                `toml:"username"`
		Password            *string                `toml:"password"`
		DisableServerConfig *bool                  `toml:"disable_server_config"`
		DisableZjuConfig    *bool                  `toml:"disable_zju_config"`
		DisableZjuDns       *bool                  `toml:"disable_zju_dns"`
		DisableMultiLine    *bool                  `toml:"disable_multi_line"`
		ProxyAll            *bool                  `toml:"proxy_all"`
		SocksBind           *string                `toml:"socks_bind"`
		SocksUser           *string                `toml:"socks_user"`
		SocksPasswd         *string                `toml:"socks_passwd"`
		HttpBind            *string                `toml:"http_bind"`
		DnsTTL              *uint64                `toml:"dns_ttl"`
		DebugDump           *bool                  `toml:"debug_dump"`
		PortForwarding      []SinglePortForwarding `toml:"port_forwarding"`
	}

	SinglePortForwarding struct {
		NetworkType   *string `toml:"network_type"`
		BindAddress   *string `toml:"bind_address"`
		RemoteAddress *string `toml:"remote_address"`
	}
)

func getTomlVal[T int | uint64 | string | bool](valPointer *T, defaultVal T) T {
	if valPointer == nil {
		return defaultVal
	} else {
		return *valPointer
	}
}

func main() {
	// CLI args
	host, port, username, password := "", 0, "", ""
	disableServerConfig, disableZjuConfig, disableZjuDns, disableMultiLine := false, false, false, false
	twfId, configFile, tcpPortForwarding, udpPortForwarding := "", "", "", ""

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
	flag.StringVar(&tcpPortForwarding, "tcp-port-forwarding", "", "TCP port forwarding (e.g. 0.0.0.0:9898-10.10.98.98:80,127.0.0.1:9899-10.10.98.98:80)")
	flag.StringVar(&udpPortForwarding, "udp-port-forwarding", "", "UDP port forwarding (e.g. 127.0.0.1:53-10.10.0.21:53)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.StringVar(&configFile, "config", "", "Config file")

	flag.Parse()

	if configFile != "" {
		var conf Config
		_, err := toml.DecodeFile(configFile, &conf)
		if err != nil {
			fmt.Println("ZJU Connect: error parsing the config file")
			return
		}

		host = getTomlVal(conf.ServerAddress, "rvpn.zju.edu.cn")
		port = getTomlVal(conf.ServerPort, 443)
		username = getTomlVal(conf.Username, "")
		password = getTomlVal(conf.Password, "")
		core.ParseServConfig = !getTomlVal(conf.DisableServerConfig, false)
		core.ParseZjuConfig = !getTomlVal(conf.DisableZjuConfig, false)
		core.UseZjuDns = !getTomlVal(conf.DisableZjuDns, false)
		core.TestMultiLine = getTomlVal(conf.DisableMultiLine, false)
		core.ProxyAll = getTomlVal(conf.ProxyAll, false)
		core.SocksBind = getTomlVal(conf.SocksBind, ":1080")
		core.SocksUser = getTomlVal(conf.SocksUser, "")
		core.SocksPasswd = getTomlVal(conf.SocksPasswd, "")
		core.HttpBind = getTomlVal(conf.HttpBind, ":1081")
		core.DnsTTL = getTomlVal(conf.DnsTTL, uint64(3600))
		core.DebugDump = getTomlVal(conf.DebugDump, false)

		if conf.Username != nil {
			username = *conf.Username
		} else {
			fmt.Println("ZJU Connect: username is not set")
			return
		}

		if conf.Password != nil {
			password = *conf.Password
		} else {
			fmt.Println("ZJU Connect: password is not set")
			return
		}

		for _, singlePortForwarding := range conf.PortForwarding {
			if singlePortForwarding.NetworkType == nil {
				fmt.Println("ZJU Connect: network type is not set")
				return
			}

			if singlePortForwarding.BindAddress == nil {
				fmt.Println("ZJU Connect: bind address is not set")
				return
			}

			if singlePortForwarding.RemoteAddress == nil {
				fmt.Println("ZJU Connect: remote address is not set")
				return
			}

			core.ForwardingList = append(core.ForwardingList, core.Forwarding{
				NetworkType:   *singlePortForwarding.NetworkType,
				BindAddress:   *singlePortForwarding.BindAddress,
				RemoteAddress: *singlePortForwarding.RemoteAddress,
			})
		}

		if host == "" || (username == "" || password == "") {
			fmt.Println("ZJU Connect: host, username and password can not be empty")
			return
		}
	} else {
		core.ParseServConfig = !disableServerConfig
		core.ParseZjuConfig = !disableZjuConfig
		core.UseZjuDns = !disableZjuDns
		core.TestMultiLine = !disableMultiLine

		if tcpPortForwarding != "" {
			forwardingStringList := strings.Split(tcpPortForwarding, ",")
			for _, forwardingString := range forwardingStringList {
				addressStringList := strings.Split(forwardingString, "-")
				if len(addressStringList) != 2 {
					fmt.Println("ZJU Connect: wrong tcp port forwarding format")
					return
				}

				core.ForwardingList = append(core.ForwardingList, core.Forwarding{
					NetworkType:   "tcp",
					BindAddress:   addressStringList[0],
					RemoteAddress: addressStringList[1],
				})
			}
		}

		if udpPortForwarding != "" {
			forwardingStringList := strings.Split(udpPortForwarding, ",")
			for _, forwardingString := range forwardingStringList {
				addressStringList := strings.Split(forwardingString, "-")
				if len(addressStringList) != 2 {
					fmt.Println("ZJU Connect: wrong udp port forwarding format")
					return
				}

				core.ForwardingList = append(core.ForwardingList, core.Forwarding{
					NetworkType:   "udp",
					BindAddress:   addressStringList[0],
					RemoteAddress: addressStringList[1],
				})
			}
		}

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
