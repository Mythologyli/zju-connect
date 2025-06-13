package configs

type (
	Config struct {
		// Common fields
		Protocol           string // "easyconnect" or "atrust"
		ServerAddress      string
		ServerPort         int
		Username           string
		Password           string
		SocksBind          string
		SocksUser          string
		SocksPasswd        string
		HTTPBind           string
		PortForwardingList []SinglePortForwarding
		ShadowsocksURL     string
		DialDirectProxy    string
		DisableZJUConfig   bool
		DisableZJUDNS      bool
		DNSTTL             uint64
		ZJUDNSServer       string
		SecondaryDNSServer string
		DNSServerBind      string
		CustomDNSList      []SingleCustomDNS
		DisableKeepAlive   bool
		DebugDump          bool

		// EasyConnect fields
		TOTPSecret          string
		CertFile            string
		CertPassword        string
		DisableServerConfig bool
		SkipDomainResource  bool
		DisableMultiLine    bool
		ProxyAll            bool
		CustomProxyDomain   []string
		TUNMode             bool
		AddRoute            bool
		DNSHijack           bool
		TwfID               string

		// aTrust fields
		SID          string
		DeviceID     string
		SignKey      string
		ResourceFile string
	}

	SinglePortForwarding struct {
		NetworkType   string
		BindAddress   string
		RemoteAddress string
	}

	SingleCustomDNS struct {
		HostName string `toml:"host_name"`
		IP       string `toml:"ip"`
	}
)

type (
	ConfigTOML struct {
		Protocol            *string                    `toml:"protocol"`
		ServerAddress       *string                    `toml:"server_address"`
		ServerPort          *int                       `toml:"server_port"`
		Username            *string                    `toml:"username"`
		Password            *string                    `toml:"password"`
		TOTPSecret          *string                    `toml:"totp_secret"`
		CertFile            *string                    `toml:"cert_file"`
		CertPassword        *string                    `toml:"cert_password"`
		DisableServerConfig *bool                      `toml:"disable_server_config"`
		SkipDomainResource  *bool                      `toml:"skip_domain_resource"`
		DisableZJUConfig    *bool                      `toml:"disable_zju_config"`
		DisableZJUDNS       *bool                      `toml:"disable_zju_dns"`
		DisableMultiLine    *bool                      `toml:"disable_multi_line"`
		ProxyAll            *bool                      `toml:"proxy_all"`
		SocksBind           *string                    `toml:"socks_bind"`
		SocksUser           *string                    `toml:"socks_user"`
		SocksPasswd         *string                    `toml:"socks_passwd"`
		HTTPBind            *string                    `toml:"http_bind"`
		ShadowsocksURL      *string                    `toml:"shadowsocks_url"`
		DialDirectProxy     *string                    `toml:"dial_direct_proxy"`
		TUNMode             *bool                      `toml:"tun_mode"`
		AddRoute            *bool                      `toml:"add_route"`
		DNSTTL              *uint64                    `toml:"dns_ttl"`
		DisableKeepAlive    *bool                      `toml:"disable_keep_alive"`
		ZJUDNSServer        *string                    `toml:"zju_dns_server"`
		SecondaryDNSServer  *string                    `toml:"secondary_dns_server"`
		DNSServerBind       *string                    `toml:"dns_server_bind"`
		DNSHijack           *bool                      `toml:"dns_hijack"`
		DebugDump           *bool                      `toml:"debug_dump"`
		PortForwarding      []SinglePortForwardingTOML `toml:"port_forwarding"`
		CustomDNS           []SingleCustomDNSTOML      `toml:"custom_dns"`
		CustomProxyDomain   []string                   `toml:"custom_proxy_domain"`
		SID                 *string                    `toml:"sid"`
		DeviceID            *string                    `toml:"device_id"`
		SignKey             *string                    `toml:"sign_key"`
		ResourceFile        *string                    `toml:"resource_file"`
	}

	SinglePortForwardingTOML struct {
		NetworkType   *string `toml:"network_type"`
		BindAddress   *string `toml:"bind_address"`
		RemoteAddress *string `toml:"remote_address"`
	}

	SingleCustomDNSTOML struct {
		HostName *string `toml:"host_name"`
		IP       *string `toml:"ip"`
	}
)
