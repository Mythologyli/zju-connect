package atrustl3

import (
	"sync"
	"sync/atomic"
)

type conntrack struct {
	key          string
	authID       uint64
	connectToken string
	appID        string
	nodeGroupID  string
	authCh       chan struct{}
	authErr      error
	authStarted  uint32
}

type conntrackMgr struct {
	mu         sync.Mutex
	nextAuthID uint64
	byKey      map[string]*conntrack
	byID       map[uint64]*conntrack
}

func newConntrackMgr() *conntrackMgr {
	return &conntrackMgr{
		byKey: make(map[string]*conntrack),
		byID:  make(map[uint64]*conntrack),
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
	if ct := m.byKey[key]; ct != nil {
		return ct
	}
	authID := atomic.AddUint64(&m.nextAuthID, 1)
	ct := &conntrack{
		key:         key,
		authID:      authID,
		appID:       appID,
		nodeGroupID: nodeGroupID,
		authCh:      make(chan struct{}),
	}
	m.byKey[key] = ct
	m.byID[authID] = ct
	return ct
}

func (m *conntrackMgr) markAuth(authID uint64, token string, err error) {
	m.mu.Lock()
	ct := m.byID[authID]
	if ct != nil && token != "" {
		ct.connectToken = token
	}
	m.mu.Unlock()
	if ct == nil {
		return
	}
	ct.authErr = err
	select {
	case <-ct.authCh:
		return
	default:
		close(ct.authCh)
	}
}
