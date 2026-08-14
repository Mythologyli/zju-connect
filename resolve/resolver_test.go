package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/patrickmn/go-cache"
)

var domainResourceMatchSink bool

func TestTCPPrefersL3UsesSelectedResource(t *testing.T) {
	if TCPPrefersL3(context.Background()) {
		t.Fatal("empty context unexpectedly prefers L3")
	}
	domainCtx := context.WithValue(context.Background(), ContextKeyDomainResource, client.DomainResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(domainCtx) {
		t.Fatal("domain resource preference was ignored")
	}
	ipCtx := context.WithValue(context.Background(), ContextKeyIPResource, client.IPResource{EnableTCPPrefL3: true})
	if !TCPPrefersL3(ipCtx) {
		t.Fatal("IP resource preference was ignored")
	}
}

func TestMatchDomainResourcePreservesNormalizedSuffixMatching(t *testing.T) {
	want := client.DomainResource{AppID: "vpn-app"}
	index := newDomainResourceIndex(client.DomainResources{".Example.COM.": {want}})
	domain, got, ok := matchDomainResource(index, "service.example.com")
	if !ok {
		t.Fatal("matchDomainResource() did not find normalized suffix")
	}
	if domain != ".Example.COM." || len(got) != 1 || got[0] != want {
		t.Fatalf("matchDomainResource() = (%q, %#v), want original domain and %#v", domain, got, want)
	}
}

func TestDomainResourceMatchRequiresLabelBoundary(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"example.com": {{AppID: "vpn"}}})
	for _, host := range []string{"example.com", "service.example.com"} {
		if _, _, ok := index.Match(host); !ok {
			t.Fatalf("expected %s to match", host)
		}
	}
	if _, _, ok := index.Match("notexample.com"); ok {
		t.Fatal("partial label suffix matched domain resource")
	}
}

func TestWildcardDomainResourceRequiresSubdomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{"*.example.com": {{AppID: "vpn"}}})
	if _, _, ok := index.Match("service.example.com"); !ok {
		t.Fatal("wildcard did not match subdomain")
	}
	if _, _, ok := index.Match("example.com"); ok {
		t.Fatal("wildcard unexpectedly matched apex domain")
	}
}

func BenchmarkDomainResourceMatch(b *testing.B) {
	resources := make(client.DomainResources, 1000)
	for i := 0; i < 1000; i++ {
		resources[fmt.Sprintf(".resource-%04d.example", i)] = []client.DomainResource{{}}
	}
	index := newDomainResourceIndex(resources)
	const host = "missing.example.com"

	b.Run("index", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _, domainResourceMatchSink = index.Match(host)
		}
	})
	b.Run("linear", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			matched := false
			for domain := range resources {
				if strings.HasSuffix(host, normalizeHostname(domain)) {
					matched = true
					break
				}
			}
			domainResourceMatchSink = matched
		}
	})
}

func TestDomainResourceMatchPrefersMostSpecificDomain(t *testing.T) {
	index := newDomainResourceIndex(client.DomainResources{
		".cnki.net":    {{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "wildcard"}},
		"www.cnki.net": {{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "exact"}},
	})

	domain, resources, ok := index.Match("www.cnki.net")
	if !ok || domain != "www.cnki.net" || len(resources) != 2 || resources[0].AppID != "exact" {
		t.Fatalf("Match() = (%q, %#v, %v), want exact domain resource", domain, resources, ok)
	}
	if resource, matched := client.MatchDomainResource(resources, "tcp", 443); !matched || resource.AppID != "wildcard" {
		t.Fatalf("443 match = (%#v, %v), want wildcard fallback", resource, matched)
	}
}

func TestResolverReleasesCoordinationEntry(t *testing.T) {
	failing := failingNetResolver()
	resolver := &Resolver{
		remoteUDPResolver: failing,
		remoteTCPResolver: failing,
		secondaryResolver: failing,
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	_, _, _ = resolver.Resolve(context.Background(), "missing.example")
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("coordination entries after Resolve = %d, want 0", entries)
	}
}

func TestResolverRotatesConfiguredDNSAddresses(t *testing.T) {
	first := net.ParseIP("192.0.2.1")
	second := net.ParseIP("192.0.2.2")
	resolver := &Resolver{
		domainIndex: newDomainResourceIndex(nil),
		dnsResource: map[string][]net.IP{"service.example": {first, second}},
		dnsCache:    cache.New(time.Minute, 0),
	}

	_, gotFirst, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	_, gotSecond, err := resolver.Resolve(context.Background(), "service.example")
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if !gotFirst.Equal(first) || !gotSecond.Equal(second) {
		t.Fatalf("rotated addresses = %s, %s, want %s, %s", gotFirst, gotSecond, first, second)
	}
}

func TestResolverWaitingCallerHonorsContext(t *testing.T) {
	started := make(chan struct{}, 1)
	blocking := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	resolver := &Resolver{
		remoteUDPResolver: blocking,
		remoteTCPResolver: blocking,
		secondaryResolver: failingNetResolver(),
		dnsCache:          cache.New(time.Minute, 0),
		useRemoteDNS:      true,
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		_, _, _ = resolver.Resolve(leaderCtx, "blocked.example")
		close(leaderDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("leader DNS lookup did not start")
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	result := make(chan error, 1)
	go func() {
		_, _, err := resolver.Resolve(waiterCtx, "blocked.example")
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting Resolve error = %v, want context.Canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waiting Resolve did not stop after context cancellation")
	}

	cancelLeader()
	select {
	case <-leaderDone:
	case <-time.After(time.Second):
		t.Fatal("leader Resolve did not stop after context cancellation")
	}
	deadline := time.Now().Add(time.Second)
	for resolver.coordinationEntryCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entries := resolver.coordinationEntryCount(); entries != 0 {
		t.Fatalf("active coordination entries after cancellation = %d after timeout, want 0", entries)
	}
}

func TestResolverLeaderCancellationDoesNotCancelWaiter(t *testing.T) {
	resolver := &Resolver{}
	started := make(chan struct{})
	release := make(chan struct{})
	want := net.ParseIP("192.0.2.20")
	lookup := func(ctx context.Context) (net.IP, error) {
		close(started)
		select {
		case <-release:
			return want, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderResult := make(chan error, 1)
	go func() {
		_, err := resolver.resolveCoordinated(leaderCtx, "shared.example", lookup)
		leaderResult <- err
	}()
	<-started

	waiterResult := make(chan struct {
		ip  net.IP
		err error
	}, 1)
	unexpectedLookup := make(chan struct{}, 1)
	go func() {
		ip, err := resolver.resolveCoordinated(context.Background(), "shared.example", func(context.Context) (net.IP, error) {
			unexpectedLookup <- struct{}{}
			return nil, errors.New("waiter unexpectedly started a second lookup")
		})
		waiterResult <- struct {
			ip  net.IP
			err error
		}{ip: ip, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		resolver.resolutionMu.Lock()
		waiters := resolver.resolutions["shared.example"].waiters
		resolver.resolutionMu.Unlock()
		if waiters == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not join the shared lookup")
		}
		time.Sleep(time.Millisecond)
	}

	cancelLeader()
	if err := <-leaderResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	close(release)
	result := <-waiterResult
	if result.err != nil || !result.ip.Equal(want) {
		t.Fatalf("waiter result = %s, %v, want %s, nil", result.ip, result.err, want)
	}
	select {
	case <-unexpectedLookup:
		t.Fatal("waiter unexpectedly started a second lookup")
	default:
	}
}

func TestLookupIPWithTCPFallbackHedgesSlowUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.10")
	udpCanceled := make(chan struct{})
	udp := func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		close(udpCanceled)
		return nil, ctx.Err()
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	started := time.Now()
	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "slow.example", udp, tcp, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("lookupIPWithTCPFallback() error = %v", err)
	}
	if udpFailed {
		t.Fatal("slow UDP was hedged, not proven failed")
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, want %s", ips, want)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("hedged lookup took %s", elapsed)
	}
	select {
	case <-udpCanceled:
	case <-time.After(time.Second):
		t.Fatal("losing UDP lookup was not canceled")
	}
}

func TestLookupIPWithTCPFallbackKeepsFastUDP(t *testing.T) {
	want := net.ParseIP("192.0.2.11")
	tcpCalled := make(chan struct{}, 1)
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		tcpCalled <- struct{}{}
		return nil, errors.New("unexpected TCP lookup")
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "fast.example", udp, tcp, time.Second)
	if err != nil || udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
	select {
	case <-tcpCalled:
		t.Fatal("TCP lookup started for a fast UDP response")
	default:
	}
}

func TestLookupIPWithTCPFallbackMarksUDPFailure(t *testing.T) {
	want := net.ParseIP("192.0.2.12")
	udp := func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("UDP unavailable")
	}
	tcp := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{want}, nil
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(context.Background(), "failed.example", udp, tcp, time.Second)
	if err != nil || !udpFailed || len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("lookup result = %v, udpFailed=%v, err=%v", ips, udpFailed, err)
	}
}

func failingNetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS unavailable")
		},
	}
}
