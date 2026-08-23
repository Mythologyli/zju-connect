package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/spf13/pflag"
)

const envPrefix = "ZJU_CONNECT_"

var (
	zjuConnectVersion = "dev"
	CommitID          string
	domainPattern     = regexp.MustCompile(`^[a-zA-Z\d-]+(\.[a-zA-Z\d-]+)*\.[a-zA-Z]{2,}$`)
)

type startupOptions struct {
	Config        configs.Config
	ShowVersion   bool
	AuthInfo      bool
	TrustDevice   bool
	UntrustDevice bool
}

type collectionKey string

const (
	collectionTCPPortForwarding collectionKey = "tcp_port_forwarding"
	collectionUDPPortForwarding collectionKey = "udp_port_forwarding"
	collectionCustomDNS         collectionKey = "custom_dns"
	collectionProxyDomain       collectionKey = "custom_proxy_domain"
)

type collectionSpec struct {
	Key      collectionKey
	FlagName string
	EnvName  string
	Help     string
}

var collectionSpecs = []collectionSpec{
	{collectionTCPPortForwarding, "tcp-port-forwarding", "TCP_PORT_FORWARDING", "TCP port forwarding"},
	{collectionUDPPortForwarding, "udp-port-forwarding", "UDP_PORT_FORWARDING", "UDP port forwarding"},
	{collectionCustomDNS, "custom-dns", "CUSTOM_DNS", "Custom DNS lookup entries"},
	{collectionProxyDomain, "custom-proxy-domain", "CUSTOM_PROXY_DOMAIN", "Domains which force use of the RVPN proxy"},
}

func zjuConnectVersionString() string {
	if CommitID != "" {
		return zjuConnectVersion + "-" + CommitID
	}
	return zjuConnectVersion
}

func newFlagSet(defaults configs.Config) *pflag.FlagSet {
	flags := pflag.NewFlagSet("zju-connect", pflag.ContinueOnError)
	flags.String("protocol", defaults.Protocol, "Protocol (easyconnect, atrust)")
	flags.String("server", defaults.ServerAddress, "EasyConnect/aTrust server address")
	flags.Int("port", defaults.ServerPort, "EasyConnect/aTrust port address")
	flags.String("username", defaults.Username, "Your username")
	flags.String("password", defaults.Password, "Your password")
	flags.String("totp-secret", defaults.TOTPSecret, "TOTP secret")
	flags.String("cert-file", defaults.CertFile, "Client certificate p12 file path for certificate login")
	flags.String("cert-password", defaults.CertPassword, "Client certificate password")
	flags.Bool("disable-server-config", defaults.DisableServerConfig, "Don't parse server config")
	flags.Bool("skip-domain-resource", defaults.SkipDomainResource, "Don't use server domain resource to decide whether to use RVPN")
	flags.Bool("disable-zju-config", defaults.DisableZJUConfig, "Don't use ZJU config (for easyconnect protocol only)")
	flags.Bool("disable-zju-dns", defaults.DisableRemoteDNS, "Use local DNS instead of remote DNS")
	flags.Bool("disable-multi-line", defaults.DisableMultiLine, "Disable multi line auto select")
	flags.Bool("proxy-all", defaults.ProxyAll, "Proxy all traffic (only for debug usage)")
	flags.String("socks-bind", defaults.SocksBind, "The address SOCKS5 server listens on")
	flags.String("socks-user", defaults.SocksUser, "SOCKS5 username")
	flags.String("socks-passwd", defaults.SocksPasswd, "SOCKS5 password")
	flags.String("http-bind", defaults.HTTPBind, "The address HTTP server listens on")
	flags.String("shadowsocks-url", defaults.ShadowsocksURL, "The address Shadowsocks server listens on")
	flags.String("dial-direct-proxy", defaults.DialDirectProxy, "Dial with proxy when a connection doesn't match RVPN rules")
	flags.Bool("tcp-tunnel-mode", defaults.TCPTunnelMode, "Use TCP tunnel only and disable L3 tunnel")
	flags.Bool("tun-mode", defaults.TUNMode, "Enable TUN mode (experimental)")
	flags.Bool("add-route", defaults.AddRoute, "Add route from rules for TUN interface")
	flags.Uint64("dns-ttl", defaults.DNSTTL, "DNS record time to live in seconds")
	flags.Bool("debug-dump", defaults.DebugDump, "Enable traffic debug dump")
	flags.String("debug-pcap-file", defaults.DebugPCAPFile, "Save reconstructed VPN traffic to a PCAP file")
	flags.String("debug-tls-log-file", defaults.DebugTLSLogFile, "Save TLS session secrets in NSS key log format")
	flags.Bool("disable-keep-alive", defaults.DisableKeepAlive, "Disable keep alive")
	flags.String("keep-alive-url", defaults.KeepAliveURL, "Keep alive URL")
	flags.String("zju-dns-server", defaults.RemoteDNSServer, "Remote DNS server address")
	flags.String("secondary-dns-server", defaults.SecondaryDNSServer, "Secondary DNS server address")
	flags.String("dns-server-bind", defaults.DNSServerBind, "The address DNS server listens on")
	flags.String("local-dns-server", defaults.LocalDNSServer, "DNS server used to resolve the VPN server hostname")
	flags.Bool("dns-hijack", defaults.DNSHijack, "Hijack DNS queries to ZJU Connect")
	flags.Bool("fake-ip", defaults.FakeIP, "Enable Fake IP for DNS hijack")
	flags.String("graph-code-file", defaults.GraphCodeFile, "Graph Check Code File")
	flags.String("bind-interface", defaults.BindInterface, "Bind VPN underlay connections to this network interface")
	flags.Bool("auto-detect-interface", defaults.AutoDetectInterface, "Automatically detect and bind the VPN underlay interface")
	flags.String("twf-id", defaults.TwfID, "Login using captured twfID")
	flags.String("auth-type", defaults.AuthType, "aTrust authentication type")
	flags.String("phone", defaults.Phone, "Phone number with country code for aTrust SMS login")
	flags.String("login-domain", defaults.LoginDomain, "aTrust login domain")
	flags.String("client-data-file", defaults.ClientDataFile, "aTrust Client Data File")
	flags.String("cas-ticket", defaults.CasTicket, "aTrust CAS Ticket")
	flags.String("oauth2-code", defaults.OAuth2Code, "aTrust OAuth2 code")
	flags.String("sid", defaults.SID, "aTrust SID")
	flags.String("device-id", defaults.DeviceID, "aTrust Device ID")
	flags.String("sign-key", defaults.SignKey, "aTrust Sign Key")
	flags.String("resource-file", defaults.ResourceFile, "aTrust Resource File")
	flags.Int("update-best-nodes-interval", defaults.UpdateBestNodesInterval, "Interval to update best nodes in seconds")

	for _, spec := range collectionSpecs {
		flags.String(spec.FlagName, "", spec.Help)
	}

	flags.String("config", "", "Config file (can also be set with ZJU_CONNECT_CONFIG)")
	flags.Bool("version", false, "Show version")
	flags.Bool("auth-info", false, "Fetch aTrust authentication information, but do not login")
	flags.Bool("trust-device", false, "Trust the current device for aTrust, but do not connect")
	flags.Bool("untrust-device", false, "Untrust the current device for aTrust, but do not connect")
	return flags
}

func loadStartupOptions(args []string, environ func() []string) (startupOptions, *pflag.FlagSet, error) {
	defaults := configs.Default()
	flags := newFlagSet(defaults)
	if err := flags.Parse(normalizeLegacyArgs(flags, args)); err != nil {
		return startupOptions{}, flags, err
	}

	showVersion, _ := flags.GetBool("version")
	authInfo, _ := flags.GetBool("auth-info")
	trustDevice, _ := flags.GetBool("trust-device")
	untrustDevice, _ := flags.GetBool("untrust-device")
	configFile, _ := flags.GetString("config")
	options := startupOptions{
		ShowVersion:   showVersion,
		AuthInfo:      authInfo,
		TrustDevice:   trustDevice,
		UntrustDevice: untrustDevice,
	}
	if options.ShowVersion {
		normalizeConfig(&defaults)
		options.Config = defaults
		return options, flags, nil
	}

	envValues := environ()
	if !flags.Lookup("config").Changed {
		if path, ok := lookupEnvironment(envValues, envPrefix+"CONFIG"); ok {
			configFile = path
		}
	}

	k := koanf.New(".")
	if err := k.Load(structs.Provider(defaults, "koanf"), nil); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load config defaults: %w", err)
	}

	allowedKeys := make(map[string]struct{}, len(k.Keys()))
	for _, key := range k.Keys() {
		allowedKeys[key] = struct{}{}
	}

	if configFile != "" {
		if err := k.Load(file.Provider(configFile), toml.Parser()); err != nil {
			return startupOptions{}, flags, fmt.Errorf("parse config %q: %w", configFile, err)
		}
		if err := rejectUnknownKeys(k, allowedKeys); err != nil {
			return startupOptions{}, flags, fmt.Errorf("parse config %q: %w", configFile, err)
		}
	}

	envProvider := env.Provider(".", env.Opt{
		Prefix:      envPrefix,
		EnvironFunc: func() []string { return envValues },
		TransformFunc: func(key, value string) (string, any) {
			key = strings.ToLower(strings.TrimPrefix(key, envPrefix))
			if key == "config" || isCollectionEnvKey(key) {
				return "", nil
			}
			return key, value
		},
	})
	if err := k.Load(envProvider, nil); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load environment: %w", err)
	}
	if err := rejectUnknownKeys(k, allowedKeys); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load environment: %w", err)
	}
	if err := applyCollectionValues(k, collectionValuesFromEnvironment(envValues)); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load environment: %w", err)
	}

	cliProvider := posflag.ProviderWithFlag(flags, ".", k, func(flag *pflag.Flag) (string, any) {
		key, ok := configKeyForFlag(flag.Name)
		if !ok {
			return "", nil
		}
		return key, posflag.FlagVal(flags, flag)
	})
	if err := k.Load(cliProvider, nil); err != nil {
		return startupOptions{}, flags, fmt.Errorf("load command line: %w", err)
	}

	if err := applyCollectionValues(k, collectionValuesFromFlags(flags)); err != nil {
		return startupOptions{}, flags, err
	}

	var cfg configs.Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return startupOptions{}, flags, fmt.Errorf("decode merged configuration: %w", err)
	}
	normalizeConfig(&cfg)
	if err := validateConfig(cfg); err != nil {
		return startupOptions{}, flags, err
	}

	options.Config = cfg
	return options, flags, nil
}

func normalizeLegacyArgs(flags *pflag.FlagSet, args []string) []string {
	normalized := append([]string(nil), args...)
	expectValue := false
	stopParsing := false
	for i, arg := range normalized {
		if stopParsing {
			continue
		}
		if expectValue {
			expectValue = false
			continue
		}
		if arg == "--" {
			stopParsing = true
			continue
		}
		if arg == "-h" {
			normalized[i] = "--help"
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		hasValue := false
		if index := strings.IndexByte(name, '='); index >= 0 {
			name = name[:index]
			hasValue = true
		}
		flag := flags.Lookup(name)
		if flag != nil && !strings.HasPrefix(arg, "--") {
			normalized[i] = "-" + arg
		}
		if flag != nil && flag.NoOptDefVal == "" && !hasValue {
			expectValue = true
		}
	}
	return normalized
}

func lookupEnvironment(environ []string, name string) (string, bool) {
	prefix := name + "="
	for _, item := range environ {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix), true
		}
	}
	return "", false
}

func rejectUnknownKeys(k *koanf.Koanf, allowed map[string]struct{}) error {
	for _, key := range k.Keys() {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown configuration key %q", key)
		}
	}
	return nil
}

func isCollectionEnvKey(key string) bool {
	for _, spec := range collectionSpecs {
		if string(spec.Key) == key {
			return true
		}
	}
	return false
}

func configKeyForFlag(name string) (string, bool) {
	switch name {
	case "config", "version", "auth-info", "trust-device", "untrust-device":
		return "", false
	case "server":
		return "server_address", true
	case "port":
		return "server_port", true
	}
	for _, spec := range collectionSpecs {
		if spec.FlagName == name {
			return "", false
		}
	}
	return strings.ReplaceAll(name, "-", "_"), true
}

type collectionValue struct {
	Value string
	Set   bool
}

type collectionValues map[collectionKey]collectionValue

func collectionValuesFromEnvironment(environ []string) collectionValues {
	values := make(collectionValues, len(collectionSpecs))
	for _, spec := range collectionSpecs {
		value, set := lookupEnvironment(environ, envPrefix+spec.EnvName)
		values[spec.Key] = collectionValue{Value: value, Set: set}
	}
	return values
}

func collectionValuesFromFlags(flags *pflag.FlagSet) collectionValues {
	values := make(collectionValues, len(collectionSpecs))
	for _, spec := range collectionSpecs {
		flag := flags.Lookup(spec.FlagName)
		values[spec.Key] = collectionValue{Value: flag.Value.String(), Set: flag.Changed}
	}
	return values
}

func applyCollectionValues(k *koanf.Koanf, values collectionValues) error {
	tcp := values[collectionTCPPortForwarding]
	udp := values[collectionUDPPortForwarding]
	if tcp.Set || udp.Set {
		var entries []configs.SinglePortForwarding
		for _, item := range []struct {
			value   collectionValue
			network string
		}{
			{tcp, "tcp"},
			{udp, "udp"},
		} {
			parsed, err := parsePortForwarding(item.network, item.value.Value)
			if err != nil {
				return err
			}
			entries = append(entries, parsed...)
		}
		if err := k.Set("port_forwarding", entries); err != nil {
			return err
		}
	}

	customDNS := values[collectionCustomDNS]
	if customDNS.Set {
		entries, err := parseCustomDNS(customDNS.Value)
		if err != nil {
			return err
		}
		if err := k.Set("custom_dns", entries); err != nil {
			return err
		}
	}

	proxyDomains := values[collectionProxyDomain]
	if proxyDomains.Set {
		entries := parseProxyDomains(proxyDomains.Value)
		if err := k.Set("custom_proxy_domain", entries); err != nil {
			return err
		}
	}
	return nil
}

func parsePortForwarding(network, value string) ([]configs.SinglePortForwarding, error) {
	if value == "" {
		return nil, nil
	}
	var entries []configs.SinglePortForwarding
	for _, forwarding := range strings.Split(value, ",") {
		addresses := strings.SplitN(forwarding, "-", 2)
		if len(addresses) != 2 || addresses[0] == "" || addresses[1] == "" {
			return nil, fmt.Errorf("ZJU Connect: wrong %s port forwarding format", network)
		}
		entries = append(entries, configs.SinglePortForwarding{
			NetworkType:   network,
			BindAddress:   addresses[0],
			RemoteAddress: addresses[1],
		})
	}
	return entries, nil
}

func parseCustomDNS(value string) ([]configs.SingleCustomDNS, error) {
	if value == "" {
		return nil, nil
	}
	var entries []configs.SingleCustomDNS
	for _, entry := range strings.Split(value, ",") {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, errors.New("ZJU Connect: wrong custom dns format")
		}
		entries = append(entries, configs.SingleCustomDNS{HostName: parts[0], IP: parts[1]})
	}
	return entries, nil
}

func parseProxyDomains(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func normalizeConfig(cfg *configs.Config) {
	if cfg.ServerAddress != "" {
		return
	}
	if cfg.Protocol == "atrust" {
		cfg.ServerAddress = "vpn.zju.edu.cn"
	} else {
		cfg.ServerAddress = "rvpn.zju.edu.cn"
	}
}

func validateConfig(cfg configs.Config) error {
	if cfg.Protocol != "easyconnect" && cfg.Protocol != "atrust" {
		return fmt.Errorf("unsupported VPN protocol: %s", cfg.Protocol)
	}
	if cfg.ServerPort < 1 || cfg.ServerPort > 65535 {
		return fmt.Errorf("invalid VPN server port: %d", cfg.ServerPort)
	}
	for _, forwarding := range cfg.PortForwardingList {
		if forwarding.NetworkType == "" {
			return errors.New("ZJU Connect: network type is not set")
		}
		if forwarding.BindAddress == "" {
			return errors.New("ZJU Connect: bind address is not set")
		}
		if forwarding.RemoteAddress == "" {
			return errors.New("ZJU Connect: remote address is not set")
		}
	}
	for _, entry := range cfg.CustomDNSList {
		if entry.HostName == "" {
			return errors.New("ZJU Connect: host name is not set")
		}
		if entry.IP == "" {
			return errors.New("ZJU Connect: IP is not set")
		}
	}
	for _, domain := range cfg.CustomProxyDomain {
		if !domainPattern.MatchString(domain) {
			return fmt.Errorf("ZJU Connect: %s is not a valid domain", domain)
		}
	}
	return nil
}

func validateConnectConfig(cfg configs.Config) error {
	if cfg.Protocol == "easyconnect" {
		if (cfg.Username == "" || cfg.Password == "") && cfg.TwfID == "" {
			return errors.New("ZJU Connect: missing required arguments")
		}
		return nil
	}

	var primaryCredentialsPresent bool
	switch cfg.AuthType {
	case "auth/psw":
		primaryCredentialsPresent = cfg.Username != "" && cfg.Password != ""
	case "auth/smsCheckCode":
		primaryCredentialsPresent = cfg.Phone != ""
	default:
		return nil
	}
	debugCredentialsPresent := cfg.SID != "" && cfg.DeviceID != "" && cfg.ResourceFile != ""
	if !primaryCredentialsPresent && !debugCredentialsPresent {
		return errors.New("ZJU Connect: missing required arguments")
	}
	return nil
}

func initialize(args []string) int {
	options, flags, err := loadStartupOptions(args, os.Environ)
	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if options.ShowVersion {
		fmt.Printf("ZJU Connect %s\n", zjuConnectVersionString())
		return 0
	}

	conf = options.Config
	if options.AuthInfo {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Auth info is only supported by the atrust protocol")
			return 1
		}
		log.SetOutput(io.Discard)
		info, err := atrust.GetAuthInfoList(conf.ServerAddress, conf.ServerPort, conf.BindInterface, conf.AutoDetectInterface, conf.LocalDNSServer, conf.DebugTLSLogFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Get auth info list error:", err)
			return 1
		}
		jsonInfo, err := json.Marshal(info)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error marshaling auth info:", err)
			return 1
		}
		fmt.Println(string(jsonInfo))
		return 0
	}

	if options.TrustDevice || options.UntrustDevice {
		if conf.Protocol != "atrust" {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device is only supported by the atrust protocol")
			return 1
		}
		if conf.ClientDataFile == "" {
			fmt.Fprintln(os.Stderr, "Client data file is required for trust/untrust device")
			return 1
		}
		clientData, err := os.ReadFile(conf.ClientDataFile)
		if err != nil {
			log.Printf("Read client data file error: %s", err)
			return 1
		}
		if err := atrust.SetTrusted(conf.ServerAddress, conf.ServerPort, clientData, options.TrustDevice, conf.BindInterface, conf.AutoDetectInterface, conf.LocalDNSServer, conf.DebugTLSLogFile); err != nil {
			fmt.Fprintln(os.Stderr, "Trust/Untrust device error:", err)
			return 1
		}
		if options.TrustDevice {
			log.Println("Device trusted successfully")
		} else {
			log.Println("Device untrusted successfully")
		}
		return 0
	}

	if err := validateConnectConfig(conf); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "Please see: https://github.com/mythologyli/zju-connect")
		fmt.Fprintln(os.Stderr, "\nUsage:")
		flags.PrintDefaults()
		return 1
	}
	return -1
}
