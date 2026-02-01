package ippool

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

type entry[T any] struct {
	ipUint   uint32
	domain   string
	resource T
}

type IPPool[T any] struct {
	mu         sync.RWMutex
	domainToIP map[string]*entry[T]
	ipToDomain map[uint32]*entry[T]
	minIP      uint32
	maxIP      uint32
	currentIP  uint32
}

func NewIPPool[T any](cidr string) (*IPPool[T], error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()
	numIPs := uint32(1 << (bits - ones))
	minIP := binary.BigEndian.Uint32(ipNet.IP)

	return &IPPool[T]{
		domainToIP: make(map[string]*entry[T]),
		ipToDomain: make(map[uint32]*entry[T]),
		minIP:      minIP,
		maxIP:      minIP + numIPs - 1,
		currentIP:  minIP + 2,
	}, nil
}

func (p *IPPool[T]) SetIPDomain(ip net.IP, domain string, res T) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return errors.New("only IPv4 is supported")
	}
	ipUint := binary.BigEndian.Uint32(ip4)

	p.mu.Lock()
	defer p.mu.Unlock()

	newEntry := &entry[T]{
		ipUint:   ipUint,
		domain:   domain,
		resource: res,
	}

	p.domainToIP[domain] = newEntry
	p.ipToDomain[ipUint] = newEntry

	return nil
}

func (p *IPPool[T]) GenerateIP(domain string, res T) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.domainToIP[domain]; ok {
		return uint32ToIP(e.ipUint)
	}

	if p.currentIP > p.maxIP {
		panic("Fake IP range exhausted")
	}

	newIP := p.currentIP
	newEntry := &entry[T]{
		ipUint:   newIP,
		domain:   domain,
		resource: res,
	}

	p.domainToIP[domain] = newEntry
	p.ipToDomain[newIP] = newEntry
	p.currentIP++

	return uint32ToIP(newIP)
}

func (p *IPPool[T]) GetDomain(ip net.IP) (string, T, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		var zero T
		return "", zero, false
	}
	ipUint := binary.BigEndian.Uint32(ip4)

	p.mu.RLock()
	defer p.mu.RUnlock()

	if e, ok := p.ipToDomain[ipUint]; ok {
		return e.domain, e.resource, true
	}

	var zero T
	return "", zero, false
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
