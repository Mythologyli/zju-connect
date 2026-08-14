package configs

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestConfigTOMLDebugPCAPFile(t *testing.T) {
	var config ConfigTOML
	if _, err := toml.Decode("debug_pcap_file = \"capture.pcap\"\n", &config); err != nil {
		t.Fatal(err)
	}
	if config.DebugPCAPFile == nil || *config.DebugPCAPFile != "capture.pcap" {
		t.Fatalf("DebugPCAPFile = %v, want capture.pcap", config.DebugPCAPFile)
	}
}
