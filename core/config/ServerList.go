package config

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/cloverstd/tcping/ping"
)

var serverList []string

const tcpPingNum = 3

func AppendSingleServer(server string, debug bool) {
	if debug {
		log.Printf("AppendSingleServer: %s", server)
	}

	serverList = append(serverList, server)
}

func GetBestServer() string {
	bestServer := ""
	bestLatency := int64(0)

	var tcpingList []ping.TCPing
	var chList []<-chan struct{}

	for _, server := range serverList {
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
			Counter:  tcpPingNum,
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
		if result.SuccessCounter == tcpPingNum {
			latency := result.Avg().Milliseconds()

			if bestLatency == 0 || latency < bestLatency {
				bestServer = serverList[i]
				bestLatency = latency
			}
		}
	}

	return bestServer
}

func IsServerListAvailable() bool {
	return serverList != nil
}

func GetServerListLen() int {
	if IsServerListAvailable() {
		return len(serverList)
	} else {
		return 0
	}
}
