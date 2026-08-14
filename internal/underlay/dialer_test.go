package underlay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewManualInterfaceTakesPrecedence(t *testing.T) {
	dialer, err := New(Options{
		InterfaceName: "manual-interface",
		AutoDetect:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := dialer.InterfaceName(); got != "manual-interface" {
		t.Fatalf("InterfaceName() = %q, want %q", got, "manual-interface")
	}
}

func TestNewAutoDetectDisabled(t *testing.T) {
	dialer, err := New(Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	if got := dialer.InterfaceName(); got != "" {
		t.Fatalf("InterfaceName() = %q, want empty", got)
	}
}

func TestAutoDetectionIsDeferredAndSharedByConcurrentFirstDials(t *testing.T) {
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
	interfaceName := ""
	for _, iface := range interfaces {
		if usableInterface(iface.Name, nil) {
			interfaceName = iface.Name
			break
		}
	}
	if interfaceName == "" {
		t.Skip("no usable network interface")
	}

	var detectCalls atomic.Int32
	findDefaultInterface = func() string {
		detectCalls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return interfaceName
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	dialOnInterface = func(_ context.Context, _, _, gotInterface string) (net.Conn, error) {
		if gotInterface != interfaceName {
			return nil, errors.New("dial did not use detected interface")
		}
		return client, nil
	}

	dialer, err := New(Options{AutoDetect: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := detectCalls.Load(); got != 0 {
		t.Fatalf("New triggered %d interface detections, want 0", got)
	}
	if got := dialer.InterfaceName(); got != "" {
		t.Fatalf("InterfaceName before first dial = %q, want empty", got)
	}

	const callers = 8
	var wait sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, dialErr := dialer.DialContext(context.Background(), "tcp", "vpn.example.com:443")
			errs <- dialErr
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := detectCalls.Load(); got != 1 {
		t.Fatalf("interface detection calls = %d, want 1", got)
	}
	if got := dialer.InterfaceName(); got != interfaceName {
		t.Fatalf("InterfaceName after first dial = %q, want %q", got, interfaceName)
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

	dialer, err := New(Options{InterfaceName: "manual-interface", AutoDetect: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
	if findCalled {
		t.Fatal("manual interface triggered automatic re-detection")
	}
}
