package service

import (
	"context"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"net"
	"net/http"
	"time"
)

func KeepAlive(resolver *resolve.Resolver, dialer *dial.Dialer, keepAliveURL string) {
	if keepAliveURL != "" {
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, net, addr string) (net.Conn, error) {
					return dialer.Dial(ctx, net, addr)
				},
			},
		}

		for {
			resp, err := client.Get(keepAliveURL)
			if err != nil {
				log.Printf("KeepAlive: %s", err)
			} else {
				log.Printf("KeepAlive: OK, status code %d", resp.StatusCode)
				_ = resp.Body.Close()
			}

			time.Sleep(60 * time.Second)
		}
	} else {
		remoteUDPResolver, err := resolver.RemoteUDPResolver()
		if err != nil {
			log.Printf("KeepAlive: %s", err)
			panic("KeepAlive: " + err.Error())
		}

		for {
			_, err := remoteUDPResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
			if err != nil {
				log.Printf("KeepAlive: %s", err)
			} else {
				log.Printf("KeepAlive: OK")
			}

			time.Sleep(60 * time.Second)
		}
	}
}
