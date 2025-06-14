package service

import (
	"context"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"time"
)

func KeepAlive(resolver *resolve.Resolver) {
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

		if remoteUDPResolver != nil {
			_, err := remoteUDPResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
			if err != nil {
				log.DebugPrintf("KeepAlive using UDP error: %s", err)
				useTCP = true
			} else {
				log.Printf("KeepAlive using UDP: OK")
			}
		}

		if useTCP && remoteTCPResolver != nil {
			_, err := remoteTCPResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
			if err != nil {
				log.Printf("KeepAlive using TCP error: %s", err)
			} else {
				log.Printf("KeepAlive using TCP: OK")
			}
		}

		time.Sleep(60 * time.Second)
	}
}
