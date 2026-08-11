package atrust

import (
	"context"
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
	reconnecting      map[string]*l3TunnelConnectCall
	connect           func(context.Context, string) (*l3TunnelConn, error)
	reconnectDelay    time.Duration
	reconnectAttempts int

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
	defaultReconnectDelay    = time.Second
	defaultReconnectAttempts = 5
)

func NewL3Tunnel(aTrustClient *Client) (*L3Tunnel, error) {
	t := &L3Tunnel{
		client:            aTrustClient,
		conns:             make(map[string]*l3TunnelConn),
		connecting:        make(map[string]*l3TunnelConnectCall),
		reconnecting:      make(map[string]*l3TunnelConnectCall),
		reconnectDelay:    defaultReconnectDelay,
		reconnectAttempts: defaultReconnectAttempts,
		dataChan:          make(chan []byte, 4096),
		closeCh:           make(chan struct{}),
	}
	t.connect = func(ctx context.Context, addr string) (*l3TunnelConn, error) {
		info := clientInfo{
			sid:          aTrustClient.SID,
			deviceID:     aTrustClient.DeviceID,
			connectionID: aTrustClient.ConnectionID,
			username:     aTrustClient.Username,
		}
		return newL3TunnelConn(ctx, aTrustClient.underlayDialer.DialTLSContext, addr, info, aTrustClient.SignKey, t.updateVIP)
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
	t.vipMu.Lock()
	defer t.vipMu.Unlock()
	t.vipList = ips
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
		t.conns = make(map[string]*l3TunnelConn)
		t.connsMu.Unlock()

		for _, conn := range conns {
			_ = conn.Close()
		}
	})
}

func (t *L3Tunnel) getConn(nodeGroupID string) (*l3TunnelConn, error) {
	t.connsMu.Lock()
	if conn := t.conns[nodeGroupID]; conn != nil {
		t.connsMu.Unlock()
		return conn, nil
	}
	if call := t.reconnecting[nodeGroupID]; call != nil {
		t.connsMu.Unlock()
		return t.waitConnectCall(call)
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

	conn, err := t.connectConn(nodeGroupID)

	t.connsMu.Lock()
	delete(t.connecting, nodeGroupID)
	closed := false
	select {
	case <-t.closeCh:
		closed = true
	default:
	}
	if err == nil && !closed {
		t.conns[nodeGroupID] = conn
	} else if err == nil {
		err = net.ErrClosed
	}
	call.conn = conn
	call.err = err
	close(call.done)
	t.connsMu.Unlock()

	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	go t.forwardFromConn(nodeGroupID, conn)
	return conn, nil
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
	return t.connect(ctx, addr)
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
	if t.conns[nodeGroupID] != nil || t.reconnecting[nodeGroupID] != nil {
		t.connsMu.Unlock()
		return
	}
	if t.reconnecting == nil {
		t.reconnecting = make(map[string]*l3TunnelConnectCall)
	}
	call := &l3TunnelConnectCall{done: make(chan struct{})}
	t.reconnecting[nodeGroupID] = call
	t.connsMu.Unlock()
	go t.reconnect(nodeGroupID, call)
}

func (t *L3Tunnel) reconnect(nodeGroupID string, call *l3TunnelConnectCall) {
	delay := t.reconnectDelay
	if delay <= 0 {
		delay = defaultReconnectDelay
	}
	attempts := t.reconnectAttempts
	if attempts <= 0 {
		attempts = defaultReconnectAttempts
	}
	var conn *l3TunnelConn
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		timer := time.NewTimer(delay << attempt)
		select {
		case <-timer.C:
		case <-t.closeCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			err = net.ErrClosed
			t.finishReconnect(nodeGroupID, call, nil, err)
			return
		}
		conn, err = t.connectConn(nodeGroupID)
		if err == nil {
			t.finishReconnect(nodeGroupID, call, conn, nil)
			go t.forwardFromConn(nodeGroupID, conn)
			return
		}
		log.DebugPrintf("l3-tunnel reconnect attempt %d/%d failed for group %s: %v", attempt+1, attempts, nodeGroupID, err)
	}
	t.finishReconnect(nodeGroupID, call, nil, err)
}

func (t *L3Tunnel) finishReconnect(nodeGroupID string, call *l3TunnelConnectCall, conn *l3TunnelConn, err error) {
	t.connsMu.Lock()
	if t.reconnecting[nodeGroupID] != call {
		t.connsMu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	delete(t.reconnecting, nodeGroupID)
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
	}
}
