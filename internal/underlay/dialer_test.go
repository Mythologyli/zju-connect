package underlay

import (
	"context"
	"errors"
	"net"
	"testing"
)

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

func TestDialContextRedetectsAndRetriesOnNewInterface(t *testing.T) {
	originalFind := findDefaultInterface
	originalDial := dialOnInterface
	t.Cleanup(func() {
		findDefaultInterface = originalFind
		dialOnInterface = originalDial
	})

	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	newInterface := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			newInterface = iface.Name
			break
		}
	}
	if newInterface == "" {
		t.Skip("no usable network interface")
	}

	findDefaultInterface = func() string { return newInterface }
	firstErr := errors.New("old interface disappeared")
	var attempts []string
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	dialOnInterface = func(_ context.Context, _, _, interfaceName string) (net.Conn, error) {
		attempts = append(attempts, interfaceName)
		if interfaceName == "old-interface" {
			return nil, firstErr
		}
		return client, nil
	}

	dialer := &Dialer{interfaceName: "old-interface", autoDetect: true}
	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if conn != client {
		t.Fatal("DialContext returned the wrong connection")
	}
	if len(attempts) != 2 || attempts[0] != "old-interface" || attempts[1] != newInterface {
		t.Fatalf("dial attempts = %q, want [old-interface %s]", attempts, newInterface)
	}
	if got := dialer.InterfaceName(); got != newInterface {
		t.Fatalf("InterfaceName() = %q, want %q", got, newInterface)
	}
}

func TestDialContextDoesNotReplaceManualInterface(t *testing.T) {
	originalFind := findDefaultInterface
	originalDial := dialOnInterface
	t.Cleanup(func() {
		findDefaultInterface = originalFind
		dialOnInterface = originalDial
	})

	findCalled := false
	findDefaultInterface = func() string {
		findCalled = true
		return "new-interface"
	}
	wantErr := errors.New("manual interface failed")
	dialOnInterface = func(_ context.Context, _, _, _ string) (net.Conn, error) {
		return nil, wantErr
	}

	dialer := New("invalid.invalid:443", Options{InterfaceName: "manual-interface", AutoDetect: true})
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
	if findCalled {
		t.Fatal("manual interface triggered automatic re-detection")
	}
}
