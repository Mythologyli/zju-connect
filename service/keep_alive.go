package service

import (
	"context"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"net"
	"time"
)

func KeepAlive(resolver *resolve.Resolver) {
	var remoteTCPResolver *net.Resolver
	remoteUDPResolver, err := resolver.RemoteUDPResolver()
	if err != nil {
		log.DebugPrintf("KeepAlive: %s", err)

		remoteTCPResolver, err = resolver.RemoteTCPResolver()
		if err != nil {
			log.Printf("KeepAlive: %s", err)
			panic("KeepAlive: " + err.Error())
		}
	}

	for {
		_, err := remoteUDPResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
		if err != nil {
			log.DebugPrintf("KeepAlive using UDP error: %s", err)

			// Try using TCP resolver
			_, err = remoteTCPResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
			if err != nil {
				log.Printf("KeepAlive: %s", err)
			} else {
				log.Printf("KeepAlive: OK")
			}
		} else {
			log.Printf("KeepAlive: OK")
		}

		time.Sleep(60 * time.Second)
	}
}
