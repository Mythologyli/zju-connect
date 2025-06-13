package easyconnect

import (
	"errors"
	"github.com/cloverstd/tcping/ping"
	"strconv"
	"strings"
	"time"
)

const pingNum = 3

func findBestLine(lineList []string) (string, error) {
	bestLine := ""
	bestLatency := int64(0)

	var pingList []ping.TCPing
	var chList []<-chan struct{}

	for _, server := range lineList {
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
			Counter:  pingNum,
			Interval: time.Duration(0.5 * float64(time.Second)),
			Timeout:  time.Duration(1 * float64(time.Second)),
		}
		tcping.SetTarget(&target)

		pingList = append(pingList, *tcping)
		ch := tcping.Start()
		chList = append(chList, ch)
	}

	for _, ch := range chList {
		<-ch
	}

	for i, tcping := range pingList {
		result := tcping.Result()
		if result.SuccessCounter == pingNum {
			latency := result.Avg().Milliseconds()

			if bestLatency == 0 || latency < bestLatency {
				bestLine = lineList[i]
				bestLatency = latency
			}
		}
	}

	if bestLine == "" {
		return "", errors.New("no available line")
	}

	return bestLine, nil
}
