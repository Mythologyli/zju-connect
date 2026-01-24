package atrustl3

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloverstd/tcping/ping"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
)

type Stack struct {
	client     *atrustclient.Client
	username   string
	sid        string
	deviceID   string
	connectID  string
	signKey    string
	majorGroup string

	ip net.IP

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource

	nodeGroups map[string][]string

	bestNodes        map[string]string
	bestNodesRWMutex sync.RWMutex

	resolve zcdns.LocalServer

	endpoint *Endpoint
	conns    map[string]*l3Conn
	connsMu  sync.Mutex

	vipMu   sync.Mutex
	vipList []net.IP
}

func newStack(aTrustClient *atrustclient.Client) (*Stack, error) {
	s := &Stack{
		client:     aTrustClient,
		username:   aTrustClient.Username,
		sid:        aTrustClient.SID,
		deviceID:   aTrustClient.DeviceID,
		connectID:  buildConnectionID(aTrustClient.DeviceID),
		signKey:    aTrustClient.SignKey,
		majorGroup: aTrustClient.MajorNodeGroup,
		conns:      make(map[string]*l3Conn),
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	s.ipResources = ipResources

	domainResources, err := aTrustClient.DomainResources()
	if err != nil {
		domainResources = make(map[string]client.DomainResource)
	}
	s.domainResources = domainResources

	s.nodeGroups = aTrustClient.NodeGroups
	if s.nodeGroups == nil {
		return nil, fmt.Errorf("no node group list found")
	}

	s.bestNodes = getBestNodes(s.nodeGroups)

	if err := s.getIP(); err != nil {
		return nil, err
	}

	return s, nil
}

func buildConnectionID(deviceID string) string {
	sum := md5.Sum([]byte(deviceID))
	return fmt.Sprintf("%X-%d", sum, time.Now().UnixMicro())
}

func (s *Stack) SetupResolve(r zcdns.LocalServer) {
	s.resolve = r
}

func (s *Stack) updateVIP(ips []net.IP) {
	s.vipMu.Lock()
	defer s.vipMu.Unlock()
	s.vipList = ips
}

func (s *Stack) getConn(nodeGroupID string) (*l3Conn, error) {
	s.connsMu.Lock()
	if conn := s.conns[nodeGroupID]; conn != nil {
		s.connsMu.Unlock()
		return conn, nil
	}
	s.connsMu.Unlock()

	s.bestNodesRWMutex.RLock()
	addr := s.bestNodes[nodeGroupID]
	if addr == "" {
		addr = s.bestNodes[s.majorGroup]
	}
	s.bestNodesRWMutex.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("no available node for group %s", nodeGroupID)
	}

	info := clientInfo{
		sid:          s.sid,
		deviceID:     s.deviceID,
		connectionID: s.connectID,
		username:     s.username,
	}
	conn, err := newL3Conn(addr, info, s.signKey, s.updateVIP)
	if err != nil {
		return nil, err
	}

	s.connsMu.Lock()
	s.conns[nodeGroupID] = conn
	s.connsMu.Unlock()

	go s.forwardFromConn(conn)

	return conn, nil
}

func (s *Stack) forwardFromConn(conn *l3Conn) {
	for {
		pkt, err := conn.ReadPacket()
		if err != nil {
			return
		}
		logPacket("recv", pkt)
		if err := s.endpoint.Write(pkt); err != nil {
			log.Printf("atrust-l3: write to tun failed: %v", err)
			return
		}
	}
}

func (s *Stack) getIP() error {
	addr := s.bestNodes[s.majorGroup]
	if addr == "" {
		for _, node := range s.bestNodes {
			addr = node
			break
		}
	}
	if addr == "" {
		return fmt.Errorf("no reachable node for ip request")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	msg := []byte{0x05, 0x01, 0xd0, 0x53, 0x00, 0x00, 0x53}
	msg = append(msg, []byte(fmt.Sprintf(`{"sid":"%s"}`, s.sid))...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	msg = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	for {
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			return err
		}

		header := make([]byte, 2)
		_, err = io.ReadFull(conn, header)
		if err != nil {
			return err
		}
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

			if !strings.Contains(string(data), "OK") {
				return fmt.Errorf("failed to connect to the server: %s", string(data))
			}
		} else if header[0] == 0x05 && header[1] == 0x00 {
			data := make([]byte, 6)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return err
			}
			if data[0] != 0x00 || data[1] != 0x01 {
				return fmt.Errorf("unexpected response: %x", data)
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
