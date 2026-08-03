package atrust

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/internal/ping"
	"github.com/mythologyli/zju-connect/log"
)

const pingNum = 3

type NodeGroup struct {
	WAN []string
	LAN []string
}

type nodeGroupsProbeFunc func(map[string][]string) map[string]string

func getBestNodes(nodeGroups map[string]NodeGroup, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	return selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		return getBestReachableNodes(nodeGroups, dialContext)
	})
}

func selectBestNodes(nodeGroups map[string]NodeGroup, probe nodeGroupsProbeFunc) map[string]string {
	wanNodeGroups := make(map[string][]string, len(nodeGroups))
	for group, nodes := range nodeGroups {
		wanNodeGroups[group] = nodes.WAN
	}
	bestNodes := probe(wanNodeGroups)

	fallbackNodeGroups := make(map[string][]string)
	for group, nodes := range nodeGroups {
		if bestNodes[group] == "" && len(nodes.LAN) > 0 {
			fallbackNodeGroups[group] = nodes.LAN
		}
	}

	if len(fallbackNodeGroups) == 0 {
		return bestNodes
	}
	for group, node := range probe(fallbackNodeGroups) {
		bestNodes[group] = node
	}
	return bestNodes
}

func getBestReachableNodes(nodeGroups map[string][]string, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	bestNodes := make(map[string]string)
	for group, nodes := range nodeGroups {
		if len(nodes) > 0 {
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
				tcping.SetDialContext(dialContext)
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
			}
		}
	}

	return bestNodes
}

func (c *Client) updateBestNodes(ctx context.Context, updateBestNodesInterval int) {
	ticker := time.NewTicker(time.Duration(updateBestNodesInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		bestNodes := getBestNodes(c.NodeGroups, c.underlayDialer.DialContext)
		c.BestNodesRWMutex.Lock()
		c.BestNodes = bestNodes
		c.BestNodesRWMutex.Unlock()
	}
}
