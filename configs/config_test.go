package configs

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestConfigTOMLDebugPCAPFile(t *testing.T) {
	var config ConfigTOML
	if _, err := toml.Decode("debug_pcap_file = \"capture.pcap\"\nlocal_dns_server = \"223.5.5.5\"\n", &config); err != nil {
		t.Fatal(err)
	}
	if config.DebugPCAPFile == nil || *config.DebugPCAPFile != "capture.pcap" {
		t.Fatalf("DebugPCAPFile = %v, want capture.pcap", config.DebugPCAPFile)
	}
	if config.LocalDNSServer == nil || *config.LocalDNSServer != "223.5.5.5" {
		t.Fatalf("LocalDNSServer = %v, want 223.5.5.5", config.LocalDNSServer)
	}
}
