package atrust

import (
	"container/list"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/internal/zctcpip"
)

const (
	defaultConntrackMaxEntries = 16384
	defaultPendingPacketLimit  = 64
	defaultPendingByteLimit    = 256 * 1024
	tcpOutboundSynTTL          = 60 * time.Second
	tcpInboundSynTTL           = 120 * time.Second
	tcpSynAckTTL               = 60 * time.Second
	tcpResetTTL                = 90 * time.Second
	tcpInboundFirstClosedTTL   = 120 * time.Second
	tcpOutboundFirstClosedTTL  = 30 * time.Second
	tcpEstablishedTTL          = 6 * time.Hour
	udpConntrackTTL            = 120 * time.Second
	icmpConntrackTTL           = 30 * time.Second
	defaultConntrackTTL        = 60 * time.Second
)

const (
	tcpStateReset               = 0
	tcpStateInboundSyn          = 1
	tcpStateOutboundSyn         = 2
	tcpStateSynAck              = 3
	tcpStateEstablished         = 4
	tcpStateInboundFin          = 5
	tcpStateInboundFirstClosed  = 7
	tcpStateOutboundFin         = 9
	tcpStateOutboundFirstClosed = 10
)

var errConntrackEvicted = errors.New("l3-tunnel conntrack evicted")
var errPendingPacketCacheFull = errors.New("l3-tunnel pending packet cache full")

type conntrackAuthJob struct {
	conntrack *conntrack
	meta      packetMeta
}

type conntrack struct {
	key          string
	authID       uint64
	connectToken string
	appID        string
	nodeGroupID  string
	authCh       chan struct{}
	authErr      error
	authStarted  uint32
	authAttempts int
	authMeta     packetMeta
	authDeadline time.Time
	authRetryAt  time.Time
	sendMu       sync.Mutex
	pending      [][]byte
	pendingBytes int
	lastSeen     time.Time
	expiresAt    time.Time
	tcpState     uint8
	tcpSeq       uint32
	tcpTTL       time.Duration
	lruElement   *list.Element
}

type conntrackMgr struct {
	mu         sync.Mutex
	nextAuthID uint64
	byKey      map[string]*conntrack
	byID       map[uint64]*conntrack
	lru        list.List
	ttl        time.Duration
	maxEntries int
	now        func() time.Time
	closed     bool
}

func newConntrackMgr() *conntrackMgr {
	return &conntrackMgr{
		byKey:      make(map[string]*conntrack),
		byID:       make(map[uint64]*conntrack),
		maxEntries: defaultConntrackMaxEntries,
		now:        time.Now,
	}
}

func (m *conntrackMgr) getByKey(key string) *conntrack {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byKey[key]
}

func (m *conntrackMgr) getByID(authID uint64) *conntrack {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.byID[authID]
}

func (m *conntrackMgr) getOrCreate(key, appID, nodeGroupID string) *conntrack {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.removeExpiredLocked(now)
	if ct := m.byKey[key]; ct != nil {
		ct.lastSeen = now
		m.lru.MoveToBack(ct.lruElement)
		return ct
	}
	m.nextAuthID++
	ct := &conntrack{
		key:         key,
		authID:      m.nextAuthID,
		appID:       appID,
		nodeGroupID: nodeGroupID,
		authCh:      make(chan struct{}),
		lastSeen:    now,
		expiresAt:   now.Add(defaultConntrackTTL),
	}
	if m.closed {
		ct.authErr = net.ErrClosed
		close(ct.authCh)
		return ct
	}
	if len(m.byKey) >= m.maxEntries {
		m.removeOldestLocked()
	}
	ct.lruElement = m.lru.PushBack(ct)
	m.byKey[key] = ct
	m.byID[ct.authID] = ct
	return ct
}

func (m *conntrackMgr) observePacket(key string, packet []byte, incoming bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ct := m.byKey[key]
	if ct == nil {
		return false
	}
	now := m.now()
	ct.lastSeen = now
	m.lru.MoveToBack(ct.lruElement)
	ipPacket := zctcpip.IPv4Packet(packet)
	if !ipPacket.Valid() {
		ct.expiresAt = now.Add(defaultConntrackTTL)
		return true
	}
	ct.authMeta.proto = int(ipPacket.Protocol())
	switch ipPacket.Protocol() {
	case zctcpip.TCP:
		tcpPacket := zctcpip.TCPPacket(ipPacket.Payload())
		if !tcpPacket.Valid() {
			ct.expiresAt = now.Add(defaultConntrackTTL)
			return true
		}
		direction := 0
		if incoming {
			direction = 1
		}
		ct.observeTCP(tcpPacket, direction)
		ct.expiresAt = now.Add(ct.tcpTTL)
	case zctcpip.UDP:
		ct.expiresAt = now.Add(udpConntrackTTL)
	case zctcpip.ICMP:
		ct.expiresAt = now.Add(icmpConntrackTTL)
	default:
		ct.expiresAt = now.Add(defaultConntrackTTL)
	}
	return true
}

func (ct *conntrack) observeTCP(packet zctcpip.TCPPacket, direction int) {
	flags := packet.Flags()
	if flags&zctcpip.TCPRst != 0 {
		ct.tcpState = tcpStateReset
		ct.tcpTTL = tcpResetTTL
		return
	}
	if ct.tcpTTL == 0 {
		ct.tcpTTL = defaultConntrackTTL
	}
	sequence := binary.BigEndian.Uint32(packet[4:8])
	acknowledgment := binary.BigEndian.Uint32(packet[8:12])

	switch ct.tcpState {
	case tcpStateReset:
		if flags&zctcpip.TCPSyn == 0 {
			return
		}
		ct.tcpSeq = sequence
		if direction == 1 {
			ct.tcpState = tcpStateInboundSyn
			ct.tcpTTL = tcpInboundSynTTL
		} else {
			ct.tcpState = tcpStateOutboundSyn
			ct.tcpTTL = tcpOutboundSynTTL
		}
	case tcpStateInboundSyn:
		if direction != 0 || flags&zctcpip.TCPSyn == 0 {
			return
		}
		if flags&zctcpip.TCPAck != 0 && acknowledgment == ct.tcpSeq+1 {
			ct.tcpState = tcpStateEstablished
			ct.tcpTTL = tcpEstablishedTTL
			return
		}
		ct.tcpState = tcpStateSynAck
		ct.tcpSeq = sequence
		ct.tcpTTL = tcpSynAckTTL
	case tcpStateOutboundSyn:
		if direction == 1 && flags&(zctcpip.TCPSyn|zctcpip.TCPAck) == zctcpip.TCPSyn|zctcpip.TCPAck && acknowledgment == ct.tcpSeq+1 {
			ct.tcpState = tcpStateSynAck
			ct.tcpSeq = sequence
			ct.tcpTTL = tcpSynAckTTL
		}
	case tcpStateSynAck:
		if direction == 0 && flags&zctcpip.TCPAck != 0 && acknowledgment == ct.tcpSeq+1 {
			ct.tcpState = tcpStateEstablished
			ct.tcpTTL = tcpEstablishedTTL
			return
		}
		ct.observeTCPFin(flags, direction)
	case tcpStateEstablished:
		ct.observeTCPFin(flags, direction)
	case tcpStateInboundFin:
		if direction == 0 && flags&zctcpip.TCPFin != 0 {
			ct.tcpState = tcpStateInboundFirstClosed
			ct.tcpTTL = tcpInboundFirstClosedTTL
		}
	case tcpStateOutboundFin:
		if direction == 1 && flags&zctcpip.TCPFin != 0 {
			ct.tcpState = tcpStateOutboundFirstClosed
			ct.tcpTTL = tcpOutboundFirstClosedTTL
		}
	}
}

func (ct *conntrack) observeTCPFin(flags uint16, direction int) {
	if flags&zctcpip.TCPFin == 0 {
		return
	}
	if direction == 1 {
		ct.tcpState = tcpStateInboundFin
	} else {
		ct.tcpState = tcpStateOutboundFin
	}
}

func (m *conntrackMgr) markAuth(authID uint64, token string, err error) {
	m.completeAuth(authID, token, err)
}

func (m *conntrackMgr) completeAuth(authID uint64, token string, err error) (*conntrack, [][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ct := m.byID[authID]
	if ct == nil {
		return nil, nil
	}
	select {
	case <-ct.authCh:
		return nil, nil
	default:
	}
	packets := ct.pending
	ct.pending = nil
	ct.pendingBytes = 0
	if token != "" {
		ct.connectToken = token
	}
	ct.authErr = err
	close(ct.authCh)
	if err != nil {
		m.removeIndexesLocked(ct)
		return ct, nil
	}
	return ct, packets
}

func (m *conntrackMgr) cachePacket(ct *conntrack, meta packetMeta, packet []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byKey[ct.key] != ct {
		select {
		case <-ct.authCh:
			return false, ct.authErr
		default:
			return false, errConntrackEvicted
		}
	}
	select {
	case <-ct.authCh:
		return false, ct.authErr
	default:
	}
	if len(ct.pending) >= defaultPendingPacketLimit || ct.pendingBytes+len(packet) > defaultPendingByteLimit {
		return false, errPendingPacketCacheFull
	}
	ct.authMeta = meta
	copyOfPacket := append([]byte(nil), packet...)
	ct.pending = append(ct.pending, copyOfPacket)
	ct.pendingBytes += len(copyOfPacket)
	return true, nil
}

func (m *conntrackMgr) authResult(ct *conntrack) (string, error, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-ct.authCh:
		return ct.connectToken, ct.authErr, true
	default:
		return "", nil, false
	}
}

func (m *conntrackMgr) nextAuthBatch(limit int) ([]conntrackAuthJob, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs := make([]conntrackAuthJob, 0, limit)
	more := false
	for element := m.lru.Front(); element != nil; element = element.Next() {
		ct := element.Value.(*conntrack)
		if ct.authStarted != 0 || len(ct.pending) == 0 || m.now().Before(ct.authRetryAt) {
			continue
		}
		if len(jobs) >= limit {
			more = true
			break
		}
		ct.authStarted = 1
		jobs = append(jobs, conntrackAuthJob{conntrack: ct, meta: ct.authMeta})
	}
	return jobs, more
}

func (m *conntrackMgr) markAuthSent(authID uint64, deadline time.Time) {
	m.mu.Lock()
	if ct := m.byID[authID]; ct != nil {
		select {
		case <-ct.authCh:
		default:
			ct.authDeadline = deadline
			ct.authAttempts++
		}
	}
	m.mu.Unlock()
}

func (m *conntrackMgr) expireAuth(now time.Time, err error) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	expired := 0
	for element := m.lru.Front(); element != nil; {
		next := element.Next()
		ct := element.Value.(*conntrack)
		if !ct.authDeadline.IsZero() && !now.Before(ct.authDeadline) {
			if ct.authAttempts < defaultAuthMaxAttempts {
				ct.authStarted = 0
				ct.authDeadline = time.Time{}
				ct.authRetryAt = now
			} else {
				m.removeLocked(ct, err)
				expired++
			}
		}
		element = next
	}
	return expired
}

func (m *conntrackMgr) retryAuth(authID uint64, delay time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ct := m.byID[authID]
	if ct == nil || ct.authAttempts >= defaultAuthMaxAttempts {
		return false
	}
	select {
	case <-ct.authCh:
		return false
	default:
	}
	ct.authStarted = 0
	ct.authDeadline = time.Time{}
	ct.authRetryAt = m.now().Add(delay)
	return true
}

func (m *conntrackMgr) remove(key string) {
	m.mu.Lock()
	if ct := m.byKey[key]; ct != nil {
		m.removeLocked(ct, errConntrackEvicted)
	}
	m.mu.Unlock()
}

func (m *conntrackMgr) removeExpired() {
	m.mu.Lock()
	m.removeExpiredLocked(m.now())
	m.mu.Unlock()
}

func (m *conntrackMgr) removeExpiredLocked(now time.Time) {
	for element := m.lru.Front(); element != nil; {
		next := element.Next()
		ct := element.Value.(*conntrack)
		expiresAt := ct.expiresAt
		if m.ttl > 0 {
			expiresAt = ct.lastSeen.Add(m.ttl)
		}
		if !now.Before(expiresAt) {
			m.removeLocked(ct, errConntrackEvicted)
		}
		element = next
	}
}

func (m *conntrackMgr) removeOldestLocked() {
	if element := m.lru.Front(); element != nil {
		m.removeLocked(element.Value.(*conntrack), errConntrackEvicted)
	}
}

func (m *conntrackMgr) removeLocked(ct *conntrack, err error) {
	m.removeIndexesLocked(ct)
	ct.pending = nil
	ct.pendingBytes = 0
	select {
	case <-ct.authCh:
	default:
		ct.authErr = err
		close(ct.authCh)
	}
}

func (m *conntrackMgr) removeIndexesLocked(ct *conntrack) {
	if m.byKey[ct.key] == ct {
		delete(m.byKey, ct.key)
	}
	if m.byID[ct.authID] == ct {
		delete(m.byID, ct.authID)
	}
	if ct.lruElement != nil {
		m.lru.Remove(ct.lruElement)
		ct.lruElement = nil
	}
}

func (m *conntrackMgr) close() {
	m.mu.Lock()
	m.closed = true
	for _, ct := range m.byKey {
		m.removeLocked(ct, net.ErrClosed)
	}
	m.mu.Unlock()
}
