package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

const (
	keepAliveRequestTimeout = 10 * time.Second
	keepAliveDrainLimit     = 32 << 10

	// candidateKeepAliveTimeout is the short leash a derived candidate gets: it is
	// a guess, and the round moves on to the next candidate on a miss.
	candidateKeepAliveTimeout = 3 * time.Second
)

// KeepAliveTarget is one address to probe. Named targets come from
// -keep-alive-url, everything else is derived from the granted resources.
type KeepAliveTarget struct {
	URL   string
	Named bool
}

// KeepAliveDialer is the part of dial.Dialer the keep-alive needs, so a test can
// substitute its own.
type KeepAliveDialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// KeepAliveOptions carries what the loop needs from its caller.
type KeepAliveOptions struct {
	// Targets to probe, in preference order.
	Targets []KeepAliveTarget
	// Interval between rounds.
	Interval time.Duration
}

// KeepAlive keeps the session open by sending real application traffic through
// the tunnel: on this deployment a periodic session check does not extend the
// session at all, only an HTTP request to a granted application does.
//
// With no target at all it falls back to the older remote-DNS probe and says so,
// because a name lookup is not application traffic and does not hold the session.
func KeepAlive(ctx context.Context, resolver *resolve.Resolver, dialer KeepAliveDialer, options KeepAliveOptions) {
	if len(options.Targets) == 0 {
		log.Println("KeepAlive: no application target, falling back to the remote-DNS probe " +
			"(this is not application traffic and does not hold the session open; " +
			"pass -keep-alive-url or grant the account an HTTP application)")
		keepAliveWithRemoteDNS(ctx, resolver, options.Interval)
		return
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.Dial,
			ResponseHeaderTimeout: keepAliveRequestTimeout,
			// Each probe opens its own connection: an idle tunnel connection
			// between probes buys nothing and hides routing changes, and the
			// userspace netstack drops idle connections by itself anyway.
			DisableKeepAlives: true,
		},
	}
	defer client.CloseIdleConnections()

	active := ""
	for {
		if target, ok := keepAliveRound(ctx, client, options.Targets, active); ok {
			active = target
		}
		if !sleep(ctx, options.Interval) {
			return
		}
	}
}

// keepAliveRound tries each target once, in preference order, and returns the
// first one that answered. A target that fails is not retried: the next round is
// the retry, and logging one honest line per attempt is all the caller needs.
func keepAliveRound(
	ctx context.Context,
	client *http.Client,
	targets []KeepAliveTarget,
	active string,
) (string, bool) {
	for _, target := range keepAliveOrder(targets, active) {
		timeout := candidateKeepAliveTimeout
		if target.Named {
			timeout = keepAliveRequestTimeout
		}
		if keepAliveAttempt(ctx, client, target, timeout) {
			return target.URL, true
		}
	}
	return "", false
}

func keepAliveAttempt(
	ctx context.Context,
	client *http.Client,
	target KeepAliveTarget,
	timeout time.Duration,
) bool {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		log.Printf("KeepAlive: target=%s err=%v", target.URL, err)
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("KeepAlive: target=%s err=%v", target.URL, err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, keepAliveDrainLimit+1))

	if resp.StatusCode >= http.StatusBadRequest {
		log.Printf("KeepAlive: target=%s status=%d", target.URL, resp.StatusCode)
		return false
	}

	log.Printf("KeepAlive: OK status=%d target=%s", resp.StatusCode, target.URL)
	return true
}

func sleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// keepAliveWithRemoteDNS is the fallback when no application target exists. It
// keeps the historical behaviour and its log lines; it is deliberately labelled
// as not being application traffic.
func keepAliveWithRemoteDNS(ctx context.Context, resolver *resolve.Resolver, interval time.Duration) {
	remoteUDPResolver, err := resolver.RemoteUDPResolver()
	if err != nil {
		log.Printf("KeepAlive: %s", err)
	}

	remoteTCPResolver, err := resolver.RemoteTCPResolver()
	if err != nil {
		log.Printf("KeepAlive: %s", err)
	}

	if remoteUDPResolver == nil && remoteTCPResolver == nil {
		log.Printf("KeepAlive: No remote resolver available")
		return
	}

	for {
		useTCP := false
		requestCtx, cancel := context.WithTimeout(ctx, keepAliveRequestTimeout)

		if remoteUDPResolver != nil {
			_, err := remoteUDPResolver.LookupIP(requestCtx, "ip4", "www.baidu.com")
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					log.DebugPrintf("KeepAlive using UDP error: %s", err)
				}
				useTCP = true
			} else {
				log.Printf("KeepAlive using UDP: OK")
			}
		}

		if useTCP && remoteTCPResolver != nil {
			_, err := remoteTCPResolver.LookupIP(requestCtx, "ip4", "www.baidu.com")
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					log.Printf("KeepAlive using TCP error: %s", err)
				}
			} else {
				log.Printf("KeepAlive using TCP: OK")
			}
		}
		cancel()

		if !sleep(ctx, interval) {
			return
		}
	}
}
