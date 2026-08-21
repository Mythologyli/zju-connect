package atrust

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	defaultTCPTunnelMaxIdle    = 6
	defaultTCPTunnelIdleTTL    = 5 * time.Minute
	defaultTCPTunnelMinAlive   = 10 * time.Millisecond
	tcpTunnelAliveProbeTimeout = 15 * time.Microsecond
)

type tcpTunnelTransport struct {
	conn     net.Conn
	reader   *bufio.Reader
	nodeAddr string
	idleAt   time.Time
	reusedAt time.Time
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
	idleTTL time.Duration
	closed  bool
}

func newTCPTunnelPool() *tcpTunnelPool {
	return &tcpTunnelPool{idle: make(map[string][]*tcpTunnelTransport)}
}

func (p *tcpTunnelPool) configure(enabled bool, maxIdle int, idleTTL time.Duration) {
	if maxIdle == 0 {
		maxIdle = defaultTCPTunnelMaxIdle
	}
	if idleTTL <= 0 {
		idleTTL = defaultTCPTunnelIdleTTL
	}

	p.mu.Lock()
	p.enabled = enabled
	p.maxIdle = maxIdle
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
		if p.idleTTL > 0 && now.Sub(transport.idleAt) >= p.idleTTL {
			discarded = append(discarded, transport)
			continue
		}
		if !transport.checkAlive(now) {
			discarded = append(discarded, transport)
			continue
		}
		transport.reusedAt = now
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
	if !transport.checkAlive(now) {
		return false
	}

	p.mu.Lock()
	if p.closed || !p.enabled {
		p.mu.Unlock()
		return false
	}
	transports := p.idle[transport.nodeAddr]
	transport.idleAt = now
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

func (p *tcpTunnelPool) close() {
	p.mu.Lock()
	p.closed = true
	var discarded []*tcpTunnelTransport
	for key, transports := range p.idle {
		discarded = append(discarded, transports...)
		delete(p.idle, key)
	}
	p.mu.Unlock()
	closeTCPTunnelTransports(discarded)
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
