//go:build !android

package tun

import "sync"

const resourceDecisionCacheSize = 4096

type resourceDecisionKey struct {
	ip       uint32
	port     int
	protocol string
}

type resourceDecisionCache struct {
	mu     sync.RWMutex
	values map[resourceDecisionKey]bool
	keys   []resourceDecisionKey
	next   int
}

func newResourceDecisionCache() *resourceDecisionCache {
	return &resourceDecisionCache{
		values: make(map[resourceDecisionKey]bool, resourceDecisionCacheSize),
		keys:   make([]resourceDecisionKey, 0, resourceDecisionCacheSize),
	}
}

func (c *resourceDecisionCache) get(key resourceDecisionKey) (bool, bool) {
	c.mu.RLock()
	value, ok := c.values[key]
	c.mu.RUnlock()
	return value, ok
}

func (c *resourceDecisionCache) set(key resourceDecisionKey, value bool) {
	c.mu.Lock()
	if _, ok := c.values[key]; ok {
		c.values[key] = value
		c.mu.Unlock()
		return
	}
	if len(c.keys) < resourceDecisionCacheSize {
		c.keys = append(c.keys, key)
	} else {
		delete(c.values, c.keys[c.next])
		c.keys[c.next] = key
		c.next = (c.next + 1) % resourceDecisionCacheSize
	}
	c.values[key] = value
	c.mu.Unlock()
}
