package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

func KeepAlive(ctx context.Context, resolver *resolve.Resolver, dialer *dial.Dialer, keepAliveURL string) {
	if keepAliveURL != "" {
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
					return dialer.Dial(ctx, net, addr)
				},
			},
		}

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, keepAliveURL, nil)
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
					_ = resp.Body.Close()
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
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

			if remoteUDPResolver != nil {
				_, err := remoteUDPResolver.LookupIP(ctx, "ip4", "www.baidu.com")
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
				_, err := remoteTCPResolver.LookupIP(ctx, "ip4", "www.baidu.com")
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						log.Printf("KeepAlive using TCP error: %s", err)
					}
				} else {
					log.Printf("KeepAlive using TCP: OK")
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}
