package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

const (
	keepAliveRequestTimeout = 10 * time.Second
	keepAliveDrainLimit     = 32 << 10

	// candidateKeepAliveTimeout is the short leash a derived candidate gets: it is
	// a guess, and the round moves on to the next candidate on a miss.
	candidateKeepAliveTimeout = 3 * time.Second
	// keepAliveJitter spreads the interval by ±10 %.
	keepAliveJitter = 0.1
	// keepAliveMinimumInterval is used when no interval is configured.
	keepAliveMinimumInterval = 10 * time.Second
)

// The retry budget of a named target before the round gives up on it. The
// client's userspace netstack drops an occasional connection on its own, so one
// failed attempt is not evidence that a target is gone. These are variables so a
// test can shrink the budget; nothing in production writes them.
var (
	keepAliveAttempts   = 3
	keepAliveRetryDelay = 2 * time.Second
)

// KeepAliveCategory says what a keep-alive round learned.
type KeepAliveCategory string

const (
	KeepAliveOK            KeepAliveCategory = "ok"
	KeepAliveTransport     KeepAliveCategory = "transport"
	KeepAliveSession       KeepAliveCategory = "session"
	KeepAliveTargetFailure KeepAliveCategory = "target"
)

// KeepAliveResult is one attempt's outcome. The category is what the caller acts
// on: a session failure means the tunnel carries nothing and has to be recovered,
// a target failure means the probe itself is wrong, and a transport failure is
// the network.
type KeepAliveResult struct {
	Category            KeepAliveCategory
	Target              string
	Status              int
	Code                int
	Routing             string
	Err                 error
	ConsecutiveFailures int
}

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
	// Routing reports where an attempt to a target would go (tunnel, direct or
	// denied); it may be nil, and a nil answer is reported as unknown.
	Routing func(ctx context.Context, target string) (string, error)
	// Handler is called for every failed round and for the round that recovers
	// from a failure streak, so the session machinery can react.
	Handler func(KeepAliveResult)
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

	failures := 0
	active := ""
	for {
		result := keepAliveRound(ctx, client, options, active)
		if result.Category == KeepAliveOK {
			active = result.Target
			if failures > 0 && options.Handler != nil {
				result.ConsecutiveFailures = failures
				options.Handler(result)
			}
			failures = 0
		} else {
			failures++
			result.ConsecutiveFailures = failures
			if options.Handler != nil {
				options.Handler(result)
			}
		}

		if !sleepKeepAlive(ctx, options.Interval) {
			return
		}
	}
}

func keepAliveRound(
	ctx context.Context,
	client *http.Client,
	options KeepAliveOptions,
	active string,
) KeepAliveResult {
	var worst KeepAliveResult
	for _, target := range keepAliveOrder(options.Targets, active) {
		attempts := 1
		timeout := candidateKeepAliveTimeout
		if target.Named {
			attempts = keepAliveAttempts
			timeout = keepAliveRequestTimeout
		}

		for attempt := 1; attempt <= attempts; attempt++ {
			result := keepAliveAttempt(ctx, client, options, target, timeout)
			if result.Category == KeepAliveOK {
				return result
			}
			if moreSevere(result.Category, worst.Category) {
				worst = result
			}
			if attempt < attempts && !sleep(ctx, keepAliveRetryDelay) {
				return worst
			}
		}
	}
	return worst
}

func keepAliveAttempt(
	ctx context.Context,
	client *http.Client,
	options KeepAliveOptions,
	target KeepAliveTarget,
	timeout time.Duration,
) KeepAliveResult {
	result := KeepAliveResult{Target: target.URL, Routing: "unknown"}

	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if options.Routing != nil {
		if routing, err := options.Routing(requestCtx, target.URL); err == nil {
			result.Routing = routing
		}
	}
	if result.Routing == string(dial.RoutingDenied) {
		result.Category = KeepAliveTargetFailure
		result.Err = errors.New("not in the granted resources, the tunnel refuses it")
		log.Printf("KeepAlive: target failure target=%s routed=denied err=%v", target.URL, result.Err)
		return result
	}

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		result.Category = KeepAliveTargetFailure
		result.Err = err
		log.Printf("KeepAlive: target failure target=%s routed=%s err=%v", target.URL, result.Routing, err)
		return result
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Category, result.Code = classifyKeepAliveError(err)
		result.Err = err
		log.Printf("KeepAlive: %s failure target=%s routed=%s%s err=%v",
			result.Category, target.URL, result.Routing, keepAliveCodeSuffix(result.Code), err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, keepAliveDrainLimit+1))

	result.Status = resp.StatusCode
	if resp.StatusCode >= http.StatusBadRequest {
		result.Category = KeepAliveTargetFailure
		result.Err = fmt.Errorf("http status %d", resp.StatusCode)
		log.Printf("KeepAlive: target failure target=%s routed=%s status=%d", target.URL, result.Routing, resp.StatusCode)
		return result
	}

	result.Category = KeepAliveOK
	if result.Routing == string(dial.RoutingDirect) {
		// The target answered, but not through the tunnel: this request does not
		// prove application activity and does not hold the session open. Say so
		// instead of reporting a silent success.
		log.Printf("KeepAlive: OK status=%d target=%s routed=direct: this request did not cross the tunnel "+
			"and does not hold the session; use an address inside the granted resources",
			resp.StatusCode, target.URL)
		return result
	}
	log.Printf("KeepAlive: OK status=%d target=%s routed=%s", resp.StatusCode, target.URL, result.Routing)
	return result
}

// KeepAliveRouter reports where a connection to an address would go without
// dialing it. It exists so a keep-alive log line can say whether the traffic that
// keeps the session alive really crossed the tunnel.
type KeepAliveRouter interface {
	TargetRouting(ctx context.Context, network string, addr string) (dial.Routing, error)
}

// KeepAliveRouting adapts a router to the KeepAliveOptions.Routing callback.
func KeepAliveRouting(router KeepAliveRouter) func(ctx context.Context, target string) (string, error) {
	return func(ctx context.Context, target string) (string, error) {
		parsed, err := url.Parse(target)
		if err != nil {
			return "", err
		}

		port := 80
		if parsed.Scheme == "https" {
			port = 443
		}
		if parsed.Port() != "" {
			port, err = strconv.Atoi(parsed.Port())
			if err != nil {
				return "", err
			}
		}

		routing, err := router.TargetRouting(ctx, "tcp", net.JoinHostPort(parsed.Hostname(), strconv.Itoa(port)))
		if err != nil {
			return "", err
		}
		return string(routing), nil
	}
}

// keepAliveSessionCodes are the answers that mean the tunnel is up but the
// session behind it is gone, so the caller has to recover the session.
var keepAliveSessionCodes = []string{"10000004", "10000030", "75500002", "75500001"}

var keepAliveSessionText = []string{
	"invalid sid",
	"session is invalid",
	"session timeout",
	"sig or deviceid verify failed",
}

// classifyKeepAliveError turns a failed attempt into the class of problem it is.
func classifyKeepAliveError(err error) (KeepAliveCategory, int) {
	if errors.Is(err, dial.ErrACLDenied) {
		// The address is not one this tunnel may carry: a configuration problem,
		// not a dead session.
		return KeepAliveTargetFailure, 0
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return KeepAliveTransport, 0
	}

	text := strings.ToLower(err.Error())
	for _, code := range keepAliveSessionCodes {
		if strings.Contains(text, code) {
			parsed, _ := strconv.Atoi(code)
			return KeepAliveSession, parsed
		}
	}
	for _, needle := range keepAliveSessionText {
		if strings.Contains(text, needle) {
			return KeepAliveSession, 0
		}
	}
	return KeepAliveTransport, 0
}

func keepAliveCodeSuffix(code int) string {
	if code == 0 {
		return ""
	}
	return fmt.Sprintf(" code=%d", code)
}

// moreSevere reports whether left describes a worse problem than right: a dead
// session outranks anything a single target can say.
func moreSevere(left, right KeepAliveCategory) bool {
	rank := func(category KeepAliveCategory) int {
		switch category {
		case KeepAliveSession:
			return 3
		case KeepAliveTransport:
			return 2
		case KeepAliveTargetFailure:
			return 1
		default:
			return 0
		}
	}
	return rank(left) > rank(right)
}

func sleepKeepAlive(ctx context.Context, interval time.Duration) bool {
	if interval <= 0 {
		interval = keepAliveMinimumInterval
	}
	jitter := time.Duration(float64(interval) * keepAliveJitter * (rand.Float64()*2 - 1))
	return sleep(ctx, interval+jitter)
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

	if interval <= 0 {
		interval = keepAliveMinimumInterval
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

		if !sleepKeepAlive(ctx, interval) {
			return
		}
	}
}
