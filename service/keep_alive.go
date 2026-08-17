package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

const (
	keepAliveRequestTimeout = 10 * time.Second
	keepAliveDrainLimit     = 32 << 10
)

func KeepAlive(ctx context.Context, resolver *resolve.Resolver, dialer *dial.Dialer, keepAliveURL string) {
	if keepAliveURL != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = dialer.Dial
		transport.ResponseHeaderTimeout = keepAliveRequestTimeout
		client := &http.Client{
			Transport: transport,
		}
		defer client.CloseIdleConnections()

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		runHTTPKeepAlive(ctx, client, keepAliveURL, ticker.C)
		return
	} else {
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

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

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

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

func runHTTPKeepAlive(ctx context.Context, client *http.Client, keepAliveURL string, ticks <-chan time.Time) {
	for {
		requestCtx, cancel := context.WithTimeout(ctx, keepAliveRequestTimeout)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, keepAliveURL, nil)
		if err != nil {
			log.Printf("KeepAlive: %s", err)
		} else {
			resp, err := client.Do(req)
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					log.Printf("KeepAlive: %s", err)
				}
			} else {
				log.Printf("KeepAlive: OK, status code %d", resp.StatusCode)
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, keepAliveDrainLimit+1))
				_ = resp.Body.Close()
			}
		}
		cancel()

		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}
