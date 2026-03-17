package atrust

import (
	"fmt"
	"net"
	"sync"

	"github.com/mythologyli/zju-connect/client"
)

type L3Tunnel struct {
	client *Client

	ip net.IP

	ipResources []client.IPResource

	conns   map[string]*l3TunnelConn
	connsMu sync.Mutex

	vipMu   sync.Mutex
	vipList []net.IP

	dataChan chan []byte
}

func NewL3Tunnel(aTrustClient *Client) (*L3Tunnel, error) {
	t := &L3Tunnel{
		client:   aTrustClient,
		conns:    make(map[string]*l3TunnelConn),
		dataChan: make(chan []byte, 4096),
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	t.ipResources = ipResources

	ip, err := aTrustClient.IP()
	if err != nil {
		return nil, fmt.Errorf("failed to get client IP: %v", err)
	}
	t.ip = ip

	return t, nil
}

func (t *L3Tunnel) updateVIP(ips []net.IP) {
	t.vipMu.Lock()
	defer t.vipMu.Unlock()
	t.vipList = ips
}

func (t *L3Tunnel) getConn(nodeGroupID string) (*l3TunnelConn, error) {
	t.connsMu.Lock()
	if conn := t.conns[nodeGroupID]; conn != nil {
		t.connsMu.Unlock()
		return conn, nil
	}
	t.connsMu.Unlock()

	t.client.BestNodesRWMutex.RLock()
	addr := t.client.BestNodes[nodeGroupID]
	if addr == "" {
		addr = t.client.BestNodes[t.client.MajorNodeGroup]
	}
	t.client.BestNodesRWMutex.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("no available node for group %s", nodeGroupID)
	}

	info := clientInfo{
		sid:          t.client.SID,
		deviceID:     t.client.DeviceID,
		connectionID: t.client.ConnectionID,
		username:     t.client.Username,
	}
	conn, err := newL3TunnelConn(addr, info, t.client.SignKey, t.updateVIP)
	if err != nil {
		return nil, err
	}

	t.connsMu.Lock()
	t.conns[nodeGroupID] = conn
	t.connsMu.Unlock()

	go t.forwardFromConn(nodeGroupID, conn)

	return conn, nil
}

func (t *L3Tunnel) evictConn(nodeGroupID string, conn *l3TunnelConn) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	if existing := t.conns[nodeGroupID]; existing == conn {
		delete(t.conns, nodeGroupID)
	}
}

func (t *L3Tunnel) forwardFromConn(nodeGroupID string, conn *l3TunnelConn) {
	for {
		pkt, err := conn.ReadPacket()
		if err != nil {
			t.evictConn(nodeGroupID, conn)
			return
		}
		logPacket("recv", pkt)
		t.dataChan <- pkt
	}
}
