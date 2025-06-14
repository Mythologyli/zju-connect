package atrust

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/cloverstd/tcping/ping"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Stack struct {
	username       string
	sid            string
	deviceID       string
	connectID      string
	signKey        string
	majorNodeGroup string

	ip net.IP

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource

	nodeGroups map[string][]string

	bestNodes        map[string]string
	bestNodesRWMutex sync.RWMutex

	resolve zcdns.LocalServer
}

func NewStack(aTrustClient *atrustclient.Client) *Stack {
	stack := Stack{
		username:       aTrustClient.Username,
		sid:            aTrustClient.SID,
		deviceID:       aTrustClient.DeviceID,
		connectID:      aTrustClient.ConnectionID,
		signKey:        aTrustClient.SignKey,
		majorNodeGroup: aTrustClient.MajorNodeGroup,
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

	err = stack.getIP()
	if err != nil {
		log.Fatalf("Failed to get IP: %v", err)
	}

	stack.bestNodes = getBestNodes(stack.nodeGroups)

	return &stack
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) getIP() error {
	conn, err := tls.Dial("tcp", s.nodeGroups[s.majorNodeGroup][0], &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	msg := []byte{0x05, 0x01, 0xd0, 0x53, 0x00, 0x00, 0x53}
	msg = append(msg, []byte(fmt.Sprintf(`{"sid":"%s"}`, s.sid))...)
	n, err := conn.Write(msg)
	if err != nil {
		panic(err)
	}
	log.DebugPrintf("Get IP: wrote %d bytes", n)
	log.DebugDumpHex(msg)

	msg = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	n, err = conn.Write(msg)
	if err != nil {
		panic(err)
	}
	log.DebugPrintf("Get IP: wrote %d bytes", n)
	log.DebugDumpHex(msg)

	for {
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			return err
		}

		header := make([]byte, 2)
		_, err = io.ReadFull(conn, header)
		if header[0] == 0x53 && header[1] == 0x00 {
			lengthBytes := make([]byte, 2)
			_, err = io.ReadFull(conn, lengthBytes)
			if err != nil {
				return err
			}
			length := binary.BigEndian.Uint16(lengthBytes)
			data := make([]byte, length)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return err
			}
			log.DebugPrint("Received protocol response:")
			log.DebugDumpHex(data)

			if !strings.Contains(string(data), "OK") {
				log.Printf("Failed to connect to the server: %s", string(data))
				return fmt.Errorf("failed to connect to the server: %s", string(data))
			}
		} else if header[0] == 0x05 && header[1] == 0x00 {
			data := make([]byte, 6)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return err
			}
			log.DebugPrint("Received protocol response:")
			log.DebugDumpHex(data)

			if data[0] != 0x00 || data[1] != 0x01 {
				log.Printf("Unexpected response: %s", string(data))
				return fmt.Errorf("unexpected response: %s", string(data))
			}

			s.ip = net.IPv4(data[2], data[3], data[4], data[5])
			log.Printf("Received IP: %s", s.ip.String())
			return nil
		}
	}
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
