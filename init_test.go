package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigSourcePrecedence(t *testing.T) {
	configFile := writeConfig(t, `
protocol = "atrust"
server_address = "file.example.com"
server_port = 444
username = "file-user"
tun_mode = true
`)

	options, _, err := loadStartupOptions([]string{
		"--config", configFile,
		"--server", "cli.example.com",
		"--tun-mode=false",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_SERVER_ADDRESS=env.example.com",
			"ZJU_CONNECT_SERVER_PORT=555",
			"ZJU_CONNECT_USERNAME=env-user",
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := options.Config
	if cfg.ServerAddress != "cli.example.com" {
		t.Fatalf("ServerAddress = %q, want CLI value", cfg.ServerAddress)
	}
	if cfg.ServerPort != 555 {
		t.Fatalf("ServerPort = %d, want environment value", cfg.ServerPort)
	}
	if cfg.Username != "env-user" {
		t.Fatalf("Username = %q, want environment value", cfg.Username)
	}
	if cfg.Protocol != "atrust" {
		t.Fatalf("Protocol = %q, want TOML value", cfg.Protocol)
	}
	if cfg.TUNMode {
		t.Fatal("TUNMode = true, want explicit CLI false")
	}
}

func TestLegacySingleDashFlagsRemainSupported(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"-protocol", "atrust",
		"-server=legacy.example.com",
		"-tun-mode",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.Protocol != "atrust" ||
		options.Config.ServerAddress != "legacy.example.com" ||
		!options.Config.TUNMode {
		t.Fatalf("legacy flags were not applied: %+v", options.Config)
	}
}

func TestLegacyArgumentNormalizationDoesNotRewriteValues(t *testing.T) {
	for _, passwordFlag := range []string{"-password", "--password"} {
		options, _, err := loadStartupOptions([]string{
			"-username", "user",
			passwordFlag, "-server",
		}, func() []string { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if options.Config.Password != "-server" {
			t.Fatalf("%s value = %q, want unchanged flag-like value", passwordFlag, options.Config.Password)
		}
	}
}

func TestUnchangedCLIValuesDoNotOverrideConfig(t *testing.T) {
	configFile := writeConfig(t, `
server_port = 8443
socks_bind = "127.0.0.1:2080"
`)

	options, _, err := loadStartupOptions([]string{"--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.ServerPort != 8443 {
		t.Fatalf("ServerPort = %d, want 8443", options.Config.ServerPort)
	}
	if options.Config.SocksBind != "127.0.0.1:2080" {
		t.Fatalf("SocksBind = %q, want TOML value", options.Config.SocksBind)
	}
}

func TestEnvironmentConfigPathAndAuthInfo(t *testing.T) {
	configFile := writeConfig(t, `
protocol = "atrust"
server_address = "vpn.example.com"
`)

	options, _, err := loadStartupOptions([]string{"--auth-info"}, func() []string {
		return []string{"ZJU_CONNECT_CONFIG=" + configFile}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !options.AuthInfo {
		t.Fatal("AuthInfo = false")
	}
	if options.Config.Protocol != "atrust" || options.Config.ServerAddress != "vpn.example.com" {
		t.Fatalf("config not loaded before auth-info: %+v", options.Config)
	}
}

func TestProtocolServerWorkaround(t *testing.T) {
	for _, tt := range []struct {
		name     string
		protocol string
		server   string
		want     string
	}{
		{name: "empty server remains empty", protocol: "atrust"},
		{name: "aTrust rewrites EasyConnect server", protocol: "atrust", server: "rvpn.zju.edu.cn", want: "vpn.zju.edu.cn"},
		{name: "EasyConnect rewrites aTrust server", protocol: "easyconnect", server: "vpn.zju.edu.cn", want: "rvpn.zju.edu.cn"},
		{name: "aTrust server remains unchanged", protocol: "atrust", server: "vpn.zju.edu.cn", want: "vpn.zju.edu.cn"},
		{name: "EasyConnect server remains unchanged", protocol: "easyconnect", server: "rvpn.zju.edu.cn", want: "rvpn.zju.edu.cn"},
		{name: "custom server remains unchanged", protocol: "atrust", server: "vpn.example.com", want: "vpn.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"--protocol", tt.protocol}
			if tt.server != "" {
				args = append(args, "--server", tt.server)
			}

			options, _, err := loadStartupOptions(args, func() []string { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if options.Config.ServerAddress != tt.want {
				t.Fatalf("ServerAddress = %q, want %q", options.Config.ServerAddress, tt.want)
			}
		})
	}
}

func TestCollectionCLIReplacesConfig(t *testing.T) {
	configFile := writeConfig(t, `
port_forwarding = [
  { network_type = "tcp", bind_address = "127.0.0.1:1", remote_address = "10.0.0.1:1" }
]
custom_proxy_domain = ["file.example.com"]
`)

	options, _, err := loadStartupOptions([]string{
		"--config", configFile,
		"--tcp-port-forwarding", "127.0.0.1:2-10.0.0.2:2",
		"--udp-port-forwarding", "127.0.0.1:3-10.0.0.3:3",
		"--custom-proxy-domain", "cli.example.com",
	}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Config.PortForwardingList) != 2 {
		t.Fatalf("PortForwardingList = %+v", options.Config.PortForwardingList)
	}
	if got := options.Config.CustomProxyDomain; len(got) != 1 || got[0] != "cli.example.com" {
		t.Fatalf("CustomProxyDomain = %v", got)
	}
}

func TestUnknownConfigurationKeyIsRejected(t *testing.T) {
	configFile := writeConfig(t, "server_adress = \"typo.example.com\"\n")
	if _, _, err := loadStartupOptions([]string{"--config", configFile}, func() []string { return nil }); err == nil {
		t.Fatal("unknown TOML key was accepted")
	}

	if _, _, err := loadStartupOptions(nil, func() []string {
		return []string{"ZJU_CONNECT_SERVER_ADRESS=typo.example.com"}
	}); err == nil {
		t.Fatal("unknown environment key was accepted")
	}
}

func TestLegacyRemoteDNSNamesRemainSupported(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		args    []string
		environ []string
		wantDNS string
	}{
		{
			name:    "TOML",
			config:  "disable_zju_dns = true\nzju_dns_server = \"192.0.2.1\"\n",
			wantDNS: "192.0.2.1",
		},
		{
			name: "environment",
			environ: []string{
				"ZJU_CONNECT_DISABLE_ZJU_DNS=true",
				"ZJU_CONNECT_ZJU_DNS_SERVER=192.0.2.2",
			},
			wantDNS: "192.0.2.2",
		},
		{
			name: "command line",
			args: []string{
				"--disable-zju-dns",
				"--zju-dns-server", "192.0.2.3",
			},
			wantDNS: "192.0.2.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := test.args
			if test.config != "" {
				args = append([]string{"--config", writeConfig(t, test.config)}, args...)
			}
			options, _, err := loadStartupOptions(args, func() []string { return test.environ })
			if err != nil {
				t.Fatal(err)
			}
			if !options.Config.DisableRemoteDNS {
				t.Fatal("DisableRemoteDNS = false, want true")
			}
			if options.Config.RemoteDNSServer != test.wantDNS {
				t.Fatalf("RemoteDNSServer = %q, want %q", options.Config.RemoteDNSServer, test.wantDNS)
			}
		})
	}
}

func TestCanonicalRemoteDNSConfigNames(t *testing.T) {
	configFile := writeConfig(t, `
disable_remote_dns = true
remote_dns_server = "192.0.2.4"
`)

	options, _, err := loadStartupOptions([]string{"--config", configFile}, func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !options.Config.DisableRemoteDNS || options.Config.RemoteDNSServer != "192.0.2.4" {
		t.Fatalf("canonical remote DNS configuration was not applied: %+v", options.Config)
	}
}

func TestRemoteDNSAliasesPreserveSourcePrecedence(t *testing.T) {
	configFile := writeConfig(t, `
disable_zju_dns = true
zju_dns_server = "192.0.2.1"
`)

	options, _, err := loadStartupOptions([]string{
		"--config", configFile,
		"--disable-zju-dns=false",
		"--remote-dns-server", "192.0.2.3",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_DISABLE_REMOTE_DNS=true",
			"ZJU_CONNECT_ZJU_DNS_SERVER=192.0.2.2",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Config.DisableRemoteDNS {
		t.Fatal("DisableRemoteDNS = true, want explicit CLI false")
	}
	if options.Config.RemoteDNSServer != "192.0.2.3" {
		t.Fatalf("RemoteDNSServer = %q, want CLI value", options.Config.RemoteDNSServer)
	}
}

func TestEnvironmentCollectionsUseCLISyntax(t *testing.T) {
	options, _, err := loadStartupOptions(nil, func() []string {
		return []string{
			"ZJU_CONNECT_TCP_PORT_FORWARDING=127.0.0.1:2-10.0.0.2:2",
			"ZJU_CONNECT_UDP_PORT_FORWARDING=127.0.0.1:3-10.0.0.3:3",
			"ZJU_CONNECT_CUSTOM_PROXY_DOMAIN=one.example.com,two.example.com",
			"ZJU_CONNECT_CUSTOM_DNS=host.example.com:192.0.2.1",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Config.CustomProxyDomain) != 2 {
		t.Fatalf("CustomProxyDomain = %v", options.Config.CustomProxyDomain)
	}
	if len(options.Config.PortForwardingList) != 2 {
		t.Fatalf("PortForwardingList = %+v", options.Config.PortForwardingList)
	}
	if len(options.Config.CustomDNSList) != 1 || options.Config.CustomDNSList[0].IP != "192.0.2.1" {
		t.Fatalf("CustomDNSList = %+v", options.Config.CustomDNSList)
	}
}

func TestCLICollectionsOverrideEnvironmentCollections(t *testing.T) {
	options, _, err := loadStartupOptions([]string{
		"--tcp-port-forwarding", "127.0.0.1:4-10.0.0.4:4",
		"--custom-proxy-domain", "cli.example.com",
	}, func() []string {
		return []string{
			"ZJU_CONNECT_TCP_PORT_FORWARDING=127.0.0.1:2-10.0.0.2:2",
			"ZJU_CONNECT_UDP_PORT_FORWARDING=127.0.0.1:3-10.0.0.3:3",
			"ZJU_CONNECT_CUSTOM_PROXY_DOMAIN=env.example.com",
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := options.Config.PortForwardingList; len(got) != 1 || got[0].RemoteAddress != "10.0.0.4:4" {
		t.Fatalf("PortForwardingList = %+v", got)
	}
	if got := options.Config.CustomProxyDomain; len(got) != 1 || got[0] != "cli.example.com" {
		t.Fatalf("CustomProxyDomain = %v", got)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
