package atrust

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	defaultTCPTunnelMaxIdle     = 6
	defaultTCPTunnelIdleTTL     = 5 * time.Minute
	defaultTCPTunnelMinAlive    = 10 * time.Millisecond
	defaultTCPTunnelPreConn     = 1
	defaultTCPTunnelConnTimeout = 3 * time.Second
	tcpTunnelAliveProbeTimeout  = 15 * time.Microsecond
	tcpTunnelPoolTickInterval   = 15 * time.Second
)

type tcpTunnelTransport struct {
	conn     net.Conn
	reader   *bufio.Reader
	nodeAddr string
	reusedAt time.Time
	managed  bool
}

func (t *tcpTunnelTransport) checkAlive(now time.Time) bool {
	if t == nil || t.reader.Buffered() != 0 {
		return false
	}
	if now.Sub(t.reusedAt) < defaultTCPTunnelMinAlive {
		return true
	}
	if err := t.conn.SetReadDeadline(now.Add(tcpTunnelAliveProbeTimeout)); err != nil {
		return false
	}
	_, readErr := t.reader.Peek(1)
	clearErr := t.conn.SetReadDeadline(time.Time{})
	if clearErr != nil {
		return false
	}
	var netErr net.Error
	return errors.As(readErr, &netErr) && netErr.Timeout()
}

type tcpTunnelPool struct {
	mu      sync.Mutex
	idle    map[string][]*tcpTunnelTransport
	enabled bool
	maxIdle int
	minIdle int
	preConn int
	idleTTL time.Duration
	closed  bool

	active     map[string]int
	connecting map[string]int
	idleSince  map[string]time.Time
	stop       chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

func newTCPTunnelPool() *tcpTunnelPool {
	p := &tcpTunnelPool{
		idle:       make(map[string][]*tcpTunnelTransport),
		active:     make(map[string]int),
		connecting: make(map[string]int),
		idleSince:  make(map[string]time.Time),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go p.runAging()
	return p
}

func (p *tcpTunnelPool) configure(enabled bool, maxIdle, minIdle, preConn int, idleTTL time.Duration) {
	if maxIdle == 0 {
		maxIdle = defaultTCPTunnelMaxIdle
	}
	if idleTTL <= 0 {
		idleTTL = defaultTCPTunnelIdleTTL
	}
	if preConn <= 0 {
		preConn = defaultTCPTunnelPreConn
	}

	p.mu.Lock()
	p.enabled = enabled
	p.maxIdle = maxIdle
	if minIdle > 0 {
		p.minIdle = minIdle
	} else {
		p.minIdle = 0
	}
	p.preConn = preConn
	p.idleTTL = idleTTL
	var discarded []*tcpTunnelTransport
	if !p.enabled {
		for key, transports := range p.idle {
			discarded = append(discarded, transports...)
			delete(p.idle, key)
		}
	} else {
		for key, transports := range p.idle {
			if maxIdle < 0 {
				discarded = append(discarded, transports...)
				delete(p.idle, key)
			} else if len(transports) > maxIdle {
				discarded = append(discarded, transports[:len(transports)-maxIdle]...)
				p.idle[key] = transports[len(transports)-maxIdle:]
			}
		}
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
}

type tcpTunnelPreconnectDial func(context.Context, string) (net.Conn, error)

func (p *tcpTunnelPool) preconnect(ctx context.Context, nodeAddr string, dial tcpTunnelPreconnectDial) {
	p.mu.Lock()
	if p.closed || !p.enabled || p.preConn <= 0 {
		p.mu.Unlock()
		return
	}

	now := time.Now()
	transports := p.idle[nodeAddr]
	var discarded []*tcpTunnelTransport
	healthy := transports[:0]
	for _, transport := range transports {
		if transport.checkAlive(now) {
			healthy = append(healthy, transport)
		} else {
			discarded = append(discarded, transport)
		}
	}
	if len(healthy) == 0 {
		delete(p.idle, nodeAddr)
	} else {
		p.idle[nodeAddr] = healthy
	}
	if len(healthy) >= p.preConn || p.connecting[nodeAddr] >= p.preConn {
		p.mu.Unlock()
		closeTCPTunnelTransports(discarded)
		return
	}

	toStart := p.preConn - p.connecting[nodeAddr]
	p.connecting[nodeAddr] = p.preConn
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)

	var wg sync.WaitGroup
	wg.Add(toStart)
	for range toStart {
		go func() {
			defer wg.Done()
			conn, err := dial(ctx, nodeAddr)
			if err != nil {
				p.finishPreconnect(nodeAddr, nil)
				return
			}
			p.finishPreconnect(nodeAddr, &tcpTunnelTransport{
				conn: conn, reader: bufio.NewReader(conn), nodeAddr: nodeAddr, reusedAt: time.Now(),
			})
		}()
	}
	wg.Wait()
}

func (p *tcpTunnelPool) finishPreconnect(nodeAddr string, transport *tcpTunnelTransport) {
	p.mu.Lock()
	if p.connecting[nodeAddr] > 1 {
		p.connecting[nodeAddr]--
	} else {
		delete(p.connecting, nodeAddr)
	}
	if transport == nil {
		p.mu.Unlock()
		return
	}
	if p.closed || !p.enabled || p.maxIdle < 0 {
		p.mu.Unlock()
		_ = transport.conn.Close()
		return
	}

	transports := append(p.idle[nodeAddr], transport)
	if _, ok := p.idleSince[nodeAddr]; !ok {
		p.idleSince[nodeAddr] = time.Now()
	}
	var discarded []*tcpTunnelTransport
	if len(transports) > p.maxIdle {
		overflow := len(transports) - p.maxIdle
		discarded = transports[:overflow]
		transports = transports[overflow:]
	}
	if len(transports) == 0 {
		delete(p.idle, nodeAddr)
	} else {
		p.idle[nodeAddr] = transports
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
}

func (p *tcpTunnelPool) acquire(nodeAddr string, now time.Time) *tcpTunnelTransport {
	p.mu.Lock()
	if p.closed || !p.enabled {
		p.mu.Unlock()
		return nil
	}

	transports := p.idle[nodeAddr]
	var discarded []*tcpTunnelTransport
	for len(transports) > 0 {
		transport := transports[0]
		transports = transports[1:]
		if !transport.checkAlive(now) {
			discarded = append(discarded, transport)
			continue
		}
		transport.reusedAt = now
		transport.managed = true
		p.active[nodeAddr]++
		if len(transports) == 0 {
			delete(p.idle, nodeAddr)
		} else {
			p.idle[nodeAddr] = transports
		}
		p.mu.Unlock()
		closeTCPTunnelTransports(discarded)
		return transport
	}
	delete(p.idle, nodeAddr)
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
	return nil
}

func (p *tcpTunnelPool) release(transport *tcpTunnelTransport, now time.Time) bool {
	alive := transport.checkAlive(now)

	p.mu.Lock()
	p.finishLeaseLocked(transport, now)
	if !alive || p.closed || !p.enabled {
		p.mu.Unlock()
		return false
	}
	transports := p.idle[transport.nodeAddr]
	if p.active[transport.nodeAddr] == 0 {
		if _, ok := p.idleSince[transport.nodeAddr]; !ok {
			p.idleSince[transport.nodeAddr] = now
		}
	}
	transports = append(transports, transport)
	var discarded []*tcpTunnelTransport
	if p.maxIdle < 0 {
		discarded = transports
		delete(p.idle, transport.nodeAddr)
	} else if len(transports) > p.maxIdle {
		overflow := len(transports) - p.maxIdle
		discarded = transports[:overflow]
		p.idle[transport.nodeAddr] = transports[overflow:]
	} else {
		p.idle[transport.nodeAddr] = transports
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
	return true
}

func (p *tcpTunnelPool) beginLease(transport *tcpTunnelTransport, now time.Time) bool {
	if transport == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.enabled {
		return false
	}
	transport.managed = true
	transport.reusedAt = now
	p.active[transport.nodeAddr]++
	if _, ok := p.idleSince[transport.nodeAddr]; !ok {
		p.idleSince[transport.nodeAddr] = now
	}
	return true
}

func (p *tcpTunnelPool) endLease(transport *tcpTunnelTransport, now time.Time) {
	p.mu.Lock()
	p.finishLeaseLocked(transport, now)
	p.mu.Unlock()
}

func (p *tcpTunnelPool) finishLeaseLocked(transport *tcpTunnelTransport, now time.Time) {
	if transport == nil || !transport.managed {
		return
	}
	transport.managed = false
	if p.active[transport.nodeAddr] > 0 {
		p.active[transport.nodeAddr]--
	}
	if p.active[transport.nodeAddr] == 0 {
		p.idleSince[transport.nodeAddr] = now
	}
}

func (p *tcpTunnelPool) runAging() {
	ticker := time.NewTicker(tcpTunnelPoolTickInterval)
	defer func() {
		ticker.Stop()
		close(p.done)
	}()
	for {
		select {
		case now := <-ticker.C:
			p.age(now)
		case <-p.stop:
			return
		}
	}
}

func (p *tcpTunnelPool) age(now time.Time) {
	p.mu.Lock()
	var discarded []*tcpTunnelTransport
	if p.enabled && !p.closed {
		for nodeAddr, transports := range p.idle {
			if p.active[nodeAddr] > 0 || len(transports) == 0 || now.Sub(p.idleSince[nodeAddr]) <= p.idleTTL {
				continue
			}
			keep := min(p.minIdle, len(transports))
			overflow := len(transports) - keep
			discarded = append(discarded, transports[:overflow]...)
			if keep == 0 {
				delete(p.idle, nodeAddr)
			} else {
				p.idle[nodeAddr] = transports[overflow:]
			}
		}
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
}

func (p *tcpTunnelPool) close() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		var discarded []*tcpTunnelTransport
		for key, transports := range p.idle {
			discarded = append(discarded, transports...)
			delete(p.idle, key)
		}
		p.mu.Unlock()
		close(p.stop)
		closeTCPTunnelTransports(discarded)
		<-p.done
	})
}

func (p *tcpTunnelPool) retainNodes(bestNodes map[string]string) {
	valid := make(map[string]struct{}, len(bestNodes))
	for _, nodeAddr := range bestNodes {
		if nodeAddr != "" {
			valid[nodeAddr] = struct{}{}
		}
	}

	p.mu.Lock()
	var discarded []*tcpTunnelTransport
	for nodeAddr, transports := range p.idle {
		if _, ok := valid[nodeAddr]; ok {
			continue
		}
		discarded = append(discarded, transports...)
		delete(p.idle, nodeAddr)
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
}

func closeTCPTunnelTransports(transports []*tcpTunnelTransport) {
	for _, transport := range transports {
		_ = transport.conn.Close()
	}
}
