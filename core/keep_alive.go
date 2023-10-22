package core

import (
	"context"
	"log"
	"net"
	"time"
)

func KeepAlive(remoteResolver *net.Resolver) {
	for {
		_, err := remoteResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
		if err != nil {
			log.Printf("KeepAlive: %s", err)
		} else {
			log.Printf("KeepAlive: OK")
		}

		time.Sleep(60 * time.Second)
	}
}
