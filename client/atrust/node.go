package atrust

import (
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/internal/ping"
	"github.com/mythologyli/zju-connect/log"
)

const pingNum = 3

func getBestNodes(nodeGroups map[string][]string) map[string]string {
	bestNodes := make(map[string]string)
	for group, nodes := range nodeGroups {
		if len(nodes) > 1 {
			var pingList []ping.TCPing
			var chList []<-chan struct{}

			for _, node := range nodes {
				parts := strings.Split(node, ":")
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

			bestLatency := int64(0)
			bestNode := ""
			for i, tcping := range pingList {
				result := tcping.Result()
				if result.SuccessCounter == pingNum {
					latency := result.Avg().Milliseconds()

					if bestLatency == 0 || latency < bestLatency {
						bestNode = nodes[i]
						bestLatency = latency
					}
				}
			}

			if bestNode != "" {
				bestNodes[group] = bestNode
				log.Printf("Best node in group %s: %s with latency %d ms", group, bestNode, bestLatency)
			} else {
				log.Printf("No reachable node in group %s, using the first node", group)
				bestNodes[group] = nodes[0]
			}
		} else if len(nodes) == 1 {
			bestNodes[group] = nodes[0]
		}
	}

	return bestNodes
}

func (c *Client) updateBestNodes(updateBestNodesInterval int) {
	for {
		time.Sleep(time.Duration(updateBestNodesInterval) * time.Second)

		bestNodes := getBestNodes(c.NodeGroups)
		c.BestNodesRWMutex.Lock()
		c.BestNodes = bestNodes
		c.BestNodesRWMutex.Unlock()
	}
}
