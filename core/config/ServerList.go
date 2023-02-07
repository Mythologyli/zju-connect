package config

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cloverstd/tcping/ping"
)

var ServerList []string

func AppendSingleServer(server string, debug bool) {
	if debug {
		log.Printf("AppendSingleServer: %s", server)
	}

	ServerList = append(ServerList, server)
}

func GetBestServer() string {
	bestServer := ""
	bestLatency := int64(0)

	var tcpingList []ping.TCPing
	var chList []<-chan struct{}

	for _, server := range ServerList {
		parts := strings.Split(server, ":")
		host := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}

		tcping := ping.NewTCPing()
		target := ping.Target{
			Protocol: ping.TCP,
			Host:     host,
			Port:     port,
			Counter:  1,
			Interval: time.Duration(0.5 * float64(time.Second)),
			Timeout:  time.Duration(1 * float64(time.Second)),
		}
		tcping.SetTarget(&target)

		tcpingList = append(tcpingList, *tcping)
		ch := tcping.Start()
		chList = append(chList, ch)
	}

	for _, ch := range chList {
		<-ch
	}

	for i, tcping := range tcpingList {
		result := tcping.Result()
		if result.SuccessCounter > 0 {
			latency := result.Avg().Milliseconds()

			if bestLatency == 0 || latency < bestLatency {
				bestServer = ServerList[i]
				bestLatency = latency
			}
		}
	}

	return bestServer
}

func IsServerListAvailable() bool {
	return ServerList != nil
}

func GetServerListLen() int {
	if IsServerListAvailable() {
		return len(ServerList)
	} else {
		return 0
	}
}
