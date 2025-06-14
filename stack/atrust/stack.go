package atrust

import (
	"github.com/cloverstd/tcping/ping"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Stack struct {
	username  string
	sid       string
	deviceID  string
	connectID string
	signKey   string

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource

	nodeGroups map[string][]string

	bestNodes        map[string]string
	bestNodesRWMutex sync.RWMutex

	resolve zcdns.LocalServer
}

func NewStack(aTrustClient *atrustclient.Client) *Stack {
	stack := Stack{
		username:  aTrustClient.Username,
		sid:       aTrustClient.SID,
		deviceID:  aTrustClient.DeviceID,
		connectID: aTrustClient.ConnectionID,
		signKey:   aTrustClient.SignKey,
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	stack.ipResources = ipResources

	domainResources, err := aTrustClient.DomainResources()
	if err != nil {
		domainResources = make(map[string]client.DomainResource)
	}
	stack.domainResources = domainResources

	stack.nodeGroups = aTrustClient.NodeGroups
	if stack.nodeGroups == nil {
		log.Fatalf("No node group list found")
	}

	stack.bestNodes = getBestNodes(stack.nodeGroups)

	return &stack
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

const pingNum = 3

func getBestNodes(nodeGroups map[string][]string) map[string]string {
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
		}
	}

	return bestNodes
}

func (s *Stack) Run() {
	for {
		time.Sleep(time.Second * 60)

		bestNodes := getBestNodes(s.nodeGroups)
		s.bestNodesRWMutex.Lock()
		s.bestNodes = bestNodes
		s.bestNodesRWMutex.Unlock()
	}
}
