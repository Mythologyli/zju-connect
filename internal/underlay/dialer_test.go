package underlay

import "testing"

func TestNewManualInterfaceTakesPrecedence(t *testing.T) {
	dialer := New("invalid.invalid:443", Options{
		InterfaceName: "manual-interface",
		AutoDetect:    true,
	})
	if got := dialer.InterfaceName(); got != "manual-interface" {
		t.Fatalf("InterfaceName() = %q, want %q", got, "manual-interface")
	}
}

func TestNewAutoDetectDisabled(t *testing.T) {
	dialer := New("invalid.invalid:443", Options{AutoDetect: false})
	if got := dialer.InterfaceName(); got != "" {
		t.Fatalf("InterfaceName() = %q, want empty", got)
	}
}
