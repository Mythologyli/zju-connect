package configs

type Config struct {
	// Common fields
	Protocol            string                 `koanf:"protocol"`
	ServerAddress       string                 `koanf:"server_address"`
	ServerPort          int                    `koanf:"server_port"`
	Username            string                 `koanf:"username"`
	Password            string                 `koanf:"password"`
	TOTPSecret          string                 `koanf:"totp_secret"`
	SocksBind           string                 `koanf:"socks_bind"`
	SocksUser           string                 `koanf:"socks_user"`
	SocksPasswd         string                 `koanf:"socks_passwd"`
	HTTPBind            string                 `koanf:"http_bind"`
	PortForwardingList  []SinglePortForwarding `koanf:"port_forwarding"`
	ShadowsocksURL      string                 `koanf:"shadowsocks_url"`
	DialDirectProxy     string                 `koanf:"dial_direct_proxy"`
	DisableServerConfig bool                   `koanf:"disable_server_config"`
	DisableRemoteDNS    bool                   `koanf:"disable_zju_dns"`
	DNSTTL              uint64                 `koanf:"dns_ttl"`
	RemoteDNSServer     string                 `koanf:"zju_dns_server"`
	SecondaryDNSServer  string                 `koanf:"secondary_dns_server"`
	DNSServerBind       string                 `koanf:"dns_server_bind"`
	LocalDNSServer      string                 `koanf:"local_dns_server"`
	CustomDNSList       []SingleCustomDNS      `koanf:"custom_dns"`
	DisableKeepAlive    bool                   `koanf:"disable_keep_alive"`
	KeepAliveURL        string                 `koanf:"keep_alive_url"`
	TCPTunnelMode       bool                   `koanf:"tcp_tunnel_mode"`
	TUNMode             bool                   `koanf:"tun_mode"`
	AddRoute            bool                   `koanf:"add_route"`
	DNSHijack           bool                   `koanf:"dns_hijack"`
	ProxyAll            bool                   `koanf:"proxy_all"`
	FakeIP              bool                   `koanf:"fake_ip"`
	GraphCodeFile       string                 `koanf:"graph_code_file"`
	DebugDump           bool                   `koanf:"debug_dump"`
	DebugPCAPFile       string                 `koanf:"debug_pcap_file"`
	DebugTLSLogFile     string                 `koanf:"debug_tls_log_file"`
	BindInterface       string                 `koanf:"bind_interface"`
	AutoDetectInterface bool                   `koanf:"auto_detect_interface"`

	// EasyConnect fields
	CertFile           string   `koanf:"cert_file"`
	CertPassword       string   `koanf:"cert_password"`
	DisableZJUConfig   bool     `koanf:"disable_zju_config"`
	SkipDomainResource bool     `koanf:"skip_domain_resource"`
	DisableMultiLine   bool     `koanf:"disable_multi_line"`
	CustomProxyDomain  []string `koanf:"custom_proxy_domain"`
	TwfID              string   `koanf:"twf_id"`

	// aTrust fields
	AuthType                string `koanf:"auth_type"`
	Phone                   string `koanf:"phone"`
	LoginDomain             string `koanf:"login_domain"`
	ClientDataFile          string `koanf:"client_data_file"`
	CasTicket               string `koanf:"cas_ticket"`
	OAuth2Code              string `koanf:"oauth2_code"`
	SID                     string `koanf:"sid"`
	DeviceID                string `koanf:"device_id"`
	SignKey                 string `koanf:"sign_key"`
	ResourceFile            string `koanf:"resource_file"`
	UpdateBestNodesInterval int    `koanf:"update_best_nodes_interval"`
}

type SinglePortForwarding struct {
	NetworkType   string `koanf:"network_type"`
	BindAddress   string `koanf:"bind_address"`
	RemoteAddress string `koanf:"remote_address"`
}

type SingleCustomDNS struct {
	HostName string `koanf:"host_name"`
	IP       string `koanf:"ip"`
}

func Default() Config {
	return Config{
		Protocol:                "easyconnect",
		ServerPort:              443,
		SocksBind:               ":1080",
		HTTPBind:                ":1081",
		DNSTTL:                  3600,
		RemoteDNSServer:         "auto",
		SecondaryDNSServer:      "auto",
		LoginDomain:             "Radius",
		UpdateBestNodesInterval: 300,
	}
}
