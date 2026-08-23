package atrust

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/log"
)

type L3Tunnel struct {
	client *Client

	ip net.IP

	resourceIndex *ipresource.Index

	conns             map[string]*l3TunnelConn
	connsMu           sync.Mutex
	connecting        map[string]*l3TunnelConnectCall
	conntrackMgrs     map[string]*conntrackMgr
	connect           func(context.Context, string, *conntrackMgr) (*l3TunnelConn, error)
	reconnectInterval time.Duration

	vipMu   sync.Mutex
	vipList []net.IP

	dataChan  chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
}

type l3TunnelConnectCall struct {
	done chan struct{}
	conn *l3TunnelConn
	err  error
}

const (
	defaultReconnectInterval = 5 * time.Second
)

func NewL3Tunnel(aTrustClient *Client) (*L3Tunnel, error) {
	t := &L3Tunnel{
		client:            aTrustClient,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		conntrackMgrs:     make(map[string]*conntrackMgr),
		reconnectInterval: defaultReconnectInterval,
		dataChan:          make(chan []byte, 4096),
		closeCh:           make(chan struct{}),
	}
	t.connect = func(ctx context.Context, addr string, conntrackMgr *conntrackMgr) (*l3TunnelConn, error) {
		info := clientInfo{
			sid:          aTrustClient.SID,
			deviceID:     aTrustClient.DeviceID,
			connectionID: aTrustClient.ConnectionID,
			username:     aTrustClient.Username,
		}
		dialTLS := func(ctx context.Context, network, address string, config *tls.Config) (*tls.Conn, error) {
			return dialTLSContext(ctx, aTrustClient.underlayDialer, network, address, tlsConfig(config, aTrustClient.tlsKeyLogWriter))
		}
		return newL3TunnelConn(ctx, dialTLS, addr, info, aTrustClient.SignKey, conntrackMgr, t.updateVIP)
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	t.resourceIndex = ipresource.New(ipResources)

	ip, err := aTrustClient.IP()
	if err != nil {
		return nil, fmt.Errorf("failed to get client IP: %v", err)
	}
	t.ip = ip

	return t, nil
}

func (t *L3Tunnel) updateVIP(ips []net.IP) {
	updated := make([]net.IP, 0, len(ips))
	var ipv4 net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copyOfIP := append(net.IP(nil), ip...)
		updated = append(updated, copyOfIP)
		if ipv4 == nil && ip.To4() != nil {
			ipv4 = append(net.IP(nil), ip.To4()...)
		}
	}
	t.vipMu.Lock()
	changed := ipv4 != nil && !t.ip.Equal(ipv4)
	t.vipList = updated
	t.vipMu.Unlock()
	if changed && t.client != nil {
		if err := t.client.applyIPUpdate(ipv4); err != nil {
			log.Printf("Failed to apply updated l3-tunnel virtual IP %s: %v", ipv4, err)
			return
		}
		t.vipMu.Lock()
		t.ip = append(net.IP(nil), ipv4...)
		t.vipMu.Unlock()
		t.client.setIP(ipv4)
		if t.client.underlayDialer != nil {
			t.client.underlayDialer.ExcludeIP(ipv4)
		}
		log.Printf("Updated l3-tunnel virtual IP: %s", ipv4)
	}
}

func (t *L3Tunnel) Close() {
	t.closeOnce.Do(func() {
		if t.closeCh != nil {
			close(t.closeCh)
		}
		t.connsMu.Lock()
		conns := make([]*l3TunnelConn, 0, len(t.conns))
		for _, conn := range t.conns {
			conns = append(conns, conn)
		}
		conntrackMgrs := make([]*conntrackMgr, 0, len(t.conntrackMgrs))
		for _, conntrackMgr := range t.conntrackMgrs {
			conntrackMgrs = append(conntrackMgrs, conntrackMgr)
		}
		t.conns = make(map[string]*l3TunnelConn)
		t.conntrackMgrs = make(map[string]*conntrackMgr)
		t.connsMu.Unlock()

		for _, conn := range conns {
			_ = conn.Close()
		}
		for _, conntrackMgr := range conntrackMgrs {
			conntrackMgr.close()
		}
	})
}

func (t *L3Tunnel) getConn(nodeGroupID string) (*l3TunnelConn, error) {
	t.connsMu.Lock()
	if conn := t.conns[nodeGroupID]; conn != nil {
		t.connsMu.Unlock()
		return conn, nil
	}
	if call := t.connecting[nodeGroupID]; call != nil {
		t.connsMu.Unlock()
		return t.waitConnectCall(call)
	}
	call := &l3TunnelConnectCall{done: make(chan struct{})}
	if t.connecting == nil {
		t.connecting = make(map[string]*l3TunnelConnectCall)
	}
	t.connecting[nodeGroupID] = call
	t.connsMu.Unlock()
	go t.connectWithRetry(nodeGroupID, call, true)
	return t.waitConnectCall(call)
}

func (t *L3Tunnel) waitConnectCall(call *l3TunnelConnectCall) (*l3TunnelConn, error) {
	select {
	case <-call.done:
		return call.conn, call.err
	case <-t.closeCh:
		return nil, net.ErrClosed
	}
}

func (t *L3Tunnel) connectConn(nodeGroupID string) (*l3TunnelConn, error) {
	t.client.BestNodesRWMutex.RLock()
	addr := t.client.BestNodes[nodeGroupID]
	if addr == "" {
		addr = t.client.BestNodes[t.client.MajorNodeGroup]
	}
	t.client.BestNodesRWMutex.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("no available node for group %s", nodeGroupID)
	}

	ctx, cancel := context.WithTimeout(t.client.lifecycleCtx, 10*time.Second)
	defer cancel()
	conntrackMgr, err := t.getConntrackMgr(nodeGroupID)
	if err != nil {
		return nil, err
	}
	return t.connect(ctx, addr, conntrackMgr)
}

func (t *L3Tunnel) getConntrackMgr(nodeGroupID string) (*conntrackMgr, error) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()
	select {
	case <-t.closeCh:
		return nil, net.ErrClosed
	default:
	}
	if t.conntrackMgrs == nil {
		t.conntrackMgrs = make(map[string]*conntrackMgr)
	}
	if manager := t.conntrackMgrs[nodeGroupID]; manager != nil {
		return manager, nil
	}
	manager := newConntrackMgr()
	t.conntrackMgrs[nodeGroupID] = manager
	return manager, nil
}

func (t *L3Tunnel) evictConn(nodeGroupID string, conn *l3TunnelConn) {
	t.connsMu.Lock()
	removed := false
	if existing := t.conns[nodeGroupID]; existing == conn {
		delete(t.conns, nodeGroupID)
		removed = true
	}
	t.connsMu.Unlock()
	if removed {
		_ = conn.Close()
	}
}

func (t *L3Tunnel) evictStaleConns(bestNodes map[string]string, majorNodeGroup string) {
	t.connsMu.Lock()
	stale := make([]*l3TunnelConn, 0)
	for group, conn := range t.conns {
		addr := bestNodes[group]
		if addr == "" {
			addr = bestNodes[majorNodeGroup]
		}
		if addr != "" && conn.addr != addr {
			delete(t.conns, group)
			stale = append(stale, conn)
		}
	}
	t.connsMu.Unlock()

	for _, conn := range stale {
		log.DebugPrintf("l3-tunnel best node changed, closing stale connection to %s", conn.addr)
		_ = conn.Close()
	}
}

func (t *L3Tunnel) forwardFromConn(nodeGroupID string, conn *l3TunnelConn) {
	for {
		pkt, err := conn.ReadPacket()
		if err != nil {
			t.evictConn(nodeGroupID, conn)
			t.startReconnect(nodeGroupID)
			return
		}
		logPacket("recv", pkt)
		select {
		case t.dataChan <- pkt:
		case <-t.closeCh:
			return
		case <-conn.closeCh:
			return
		}
	}
}

func (t *L3Tunnel) startReconnect(nodeGroupID string) {
	if t.client == nil || t.connect == nil {
		return
	}
	select {
	case <-t.closeCh:
		return
	default:
	}
	t.connsMu.Lock()
	if t.conns[nodeGroupID] != nil || t.connecting[nodeGroupID] != nil {
		t.connsMu.Unlock()
		return
	}
	if t.connecting == nil {
		t.connecting = make(map[string]*l3TunnelConnectCall)
	}
	call := &l3TunnelConnectCall{done: make(chan struct{})}
	t.connecting[nodeGroupID] = call
	t.connsMu.Unlock()
	go t.connectWithRetry(nodeGroupID, call, false)
}

func (t *L3Tunnel) connectWithRetry(nodeGroupID string, call *l3TunnelConnectCall, immediate bool) {
	interval := t.reconnectInterval
	if interval <= 0 {
		interval = defaultReconnectInterval
	}
	for attempt := 0; ; attempt++ {
		if !immediate || attempt > 0 {
			timer := time.NewTimer(interval)
			select {
			case <-timer.C:
			case <-t.closeCh:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				t.finishConnect(nodeGroupID, call, nil, net.ErrClosed)
				return
			}
		}
		conn, err := t.connectConn(nodeGroupID)
		if err == nil {
			t.finishConnect(nodeGroupID, call, conn, nil)
			return
		}
		log.DebugPrintf("l3-tunnel connect attempt %d failed for group %s: %v", attempt+1, nodeGroupID, err)
	}
}

func (t *L3Tunnel) finishConnect(nodeGroupID string, call *l3TunnelConnectCall, conn *l3TunnelConn, err error) {
	t.connsMu.Lock()
	if t.connecting[nodeGroupID] != call {
		t.connsMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	delete(t.connecting, nodeGroupID)
	if err == nil {
		select {
		case <-t.closeCh:
			err = net.ErrClosed
		default:
			t.conns[nodeGroupID] = conn
		}
	}
	call.conn = conn
	call.err = err
	close(call.done)
	t.connsMu.Unlock()
	if err != nil && conn != nil {
		_ = conn.Close()
	} else if err == nil {
		go t.forwardFromConn(nodeGroupID, conn)
	}
}
