package underlay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
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
	dialOnInterface = func(_ context.Context, _, _, gotInterface, _ string) (net.Conn, error) {
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
	dialOnInterface = func(_ context.Context, _, _, interfaceName, _ string) (net.Conn, error) {
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
	dialOnInterface = func(_ context.Context, _, _, _, _ string) (net.Conn, error) {
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

func TestNormalizeLocalDNSServer(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: "", want: ""},
		{input: "223.5.5.5", want: "223.5.5.5:53"},
		{input: "223.5.5.5:5353", want: "223.5.5.5:5353"},
		{input: "2001:4860:4860::8888", want: "[2001:4860:4860::8888]:53"},
		{input: "[2001:4860:4860::8888]:5353", want: "[2001:4860:4860::8888]:5353"},
		{input: "dns.example.com", wantErr: true},
		{input: "223.5.5.5:0", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := normalizeLocalDNSServer(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("normalizeLocalDNSServer(%q) error = %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("normalizeLocalDNSServer(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.53:53", "[::1]:53"} {
		if !isLoopbackAddress(address) {
			t.Fatalf("isLoopbackAddress(%q) = false, want true", address)
		}
	}
	if isLoopbackAddress("223.5.5.5:53") {
		t.Fatal("public DNS address reported as loopback")
	}
}

func TestUnderlayResolverUsesConfiguredLocalDNSServer(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	resolver := newUnderlayResolver("", listener.LocalAddr().String())
	conn, err := resolver.Dial(t.Context(), "udp4", "192.0.2.53:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != listener.LocalAddr().String() {
		t.Fatalf("DNS remote address = %q, want %q", got, listener.LocalAddr())
	}
}

func TestDialContextPassesConfiguredLocalDNSServer(t *testing.T) {
	originalDial := dialOnInterface
	t.Cleanup(func() { dialOnInterface = originalDial })

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	dialOnInterface = func(_ context.Context, _, _, _, localDNSServer string) (net.Conn, error) {
		if localDNSServer != "223.5.5.5:53" {
			return nil, fmt.Errorf("local DNS server = %q", localDNSServer)
		}
		return client, nil
	}

	dialer, err := New(Options{AutoDetect: false, LocalDNSServer: "223.5.5.5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.DialContext(t.Context(), "tcp", "vpn.example.com:443"); err != nil {
		t.Fatal(err)
	}
}

func TestDialContextResolvesThroughConfiguredLocalDNSServer(t *testing.T) {
	dnsConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsServer := &dns.Server{
		PacketConn: dnsConn,
		Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			response := new(dns.Msg)
			response.SetReply(request)
			for _, question := range request.Question {
				if question.Qtype == dns.TypeA {
					response.Answer = append(response.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("127.0.0.1"),
					})
				}
			}
			_ = writer.WriteMsg(response)
		}),
	}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	conn, err := dialContextOnInterface(
		t.Context(),
		"tcp",
		net.JoinHostPort("vpn-underlay.test", strconv.Itoa(port)),
		"",
		dnsConn.LocalAddr().String(),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
