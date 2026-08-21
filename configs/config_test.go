package configs

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestConfigTOMLDebugFiles(t *testing.T) {
	var config ConfigTOML
	if _, err := toml.Decode("debug_pcap_file = \"capture.pcap\"\ndebug_tls_log_file = \"tls-keys.log\"\nlocal_dns_server = \"223.5.5.5\"\n", &config); err != nil {
		t.Fatal(err)
	}
	if config.DebugPCAPFile == nil || *config.DebugPCAPFile != "capture.pcap" {
		t.Fatalf("DebugPCAPFile = %v, want capture.pcap", config.DebugPCAPFile)
	}
	if config.DebugTLSLogFile == nil || *config.DebugTLSLogFile != "tls-keys.log" {
		t.Fatalf("DebugTLSLogFile = %v, want tls-keys.log", config.DebugTLSLogFile)
	}
	if config.LocalDNSServer == nil || *config.LocalDNSServer != "223.5.5.5" {
		t.Fatalf("LocalDNSServer = %v, want 223.5.5.5", config.LocalDNSServer)
	}
}

func TestConfigTOMLDisableTCPTunnelPool(t *testing.T) {
	var config ConfigTOML
	if _, err := toml.Decode("disable_tcp_tunnel_pool = true\n", &config); err != nil {
		t.Fatal(err)
	}
	if config.DisableTCPTunnelPool == nil || !*config.DisableTCPTunnelPool {
		t.Fatalf("DisableTCPTunnelPool = %v, want true", config.DisableTCPTunnelPool)
	}
}
