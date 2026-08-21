package atrust

import (
	"bufio"
	"net"
	"sync"
	"time"
)

type tcpTunnelTransport struct {
	conn     net.Conn
	reader   *bufio.Reader
	nodeAddr string
	idleAt   time.Time
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
	p.mu.Lock()
	p.enabled = enabled && maxIdle > 0
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
			if len(transports) > maxIdle {
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
		last := len(transports) - 1
		transport := transports[last]
		transports = transports[:last]
		if p.idleTTL > 0 && now.Sub(transport.idleAt) >= p.idleTTL {
			discarded = append(discarded, transport)
			continue
		}
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
	if transport == nil || transport.reader.Buffered() != 0 {
		return false
	}

	p.mu.Lock()
	if p.closed || !p.enabled {
		p.mu.Unlock()
		return false
	}
	transports := p.idle[transport.nodeAddr]
	if len(transports) >= p.maxIdle {
		p.mu.Unlock()
		return false
	}
	transport.idleAt = now
	p.idle[transport.nodeAddr] = append(transports, transport)
	p.mu.Unlock()
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
