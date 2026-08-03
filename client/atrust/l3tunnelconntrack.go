package atrust

import (
	"container/list"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	defaultConntrackTTL        = 10 * time.Minute
	defaultConntrackMaxEntries = 16384
)

var errConntrackEvicted = errors.New("l3-tunnel conntrack evicted")

type conntrack struct {
	key          string
	authID       uint64
	connectToken string
	appID        string
	nodeGroupID  string
	authCh       chan struct{}
	authErr      error
	authStarted  uint32
	lastSeen     time.Time
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
		ttl:        defaultConntrackTTL,
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

func (m *conntrackMgr) markAuth(authID uint64, token string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ct := m.byID[authID]
	if ct == nil {
		return
	}
	select {
	case <-ct.authCh:
		return
	default:
	}
	if token != "" {
		ct.connectToken = token
	}
	ct.authErr = err
	close(ct.authCh)
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
	if m.ttl <= 0 {
		return
	}
	cutoff := now.Add(-m.ttl)
	for element := m.lru.Front(); element != nil; element = m.lru.Front() {
		ct := element.Value.(*conntrack)
		if ct.lastSeen.After(cutoff) {
			return
		}
		m.removeLocked(ct, errConntrackEvicted)
	}
}

func (m *conntrackMgr) removeOldestLocked() {
	if element := m.lru.Front(); element != nil {
		m.removeLocked(element.Value.(*conntrack), errConntrackEvicted)
	}
}

func (m *conntrackMgr) removeLocked(ct *conntrack, err error) {
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
	select {
	case <-ct.authCh:
	default:
		ct.authErr = err
		close(ct.authCh)
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
