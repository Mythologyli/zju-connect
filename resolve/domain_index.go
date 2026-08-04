package resolve

import "github.com/mythologyli/zju-connect/client"

type domainResourceEntry struct {
	domain   string
	resource client.DomainResource
	order    int
}

type domainResourceNode struct {
	children map[byte]*domainResourceNode
	entry    *domainResourceEntry
}

type domainResourceIndex struct {
	root *domainResourceNode
}

func newDomainResourceIndex(resources map[string]client.DomainResource) *domainResourceIndex {
	index := &domainResourceIndex{root: &domainResourceNode{}}
	order := 0
	for domain, resource := range resources {
		normalized := normalizeHostname(domain)
		if normalized == "" {
			continue
		}
		node := index.root
		for pos := len(normalized) - 1; pos >= 0; pos-- {
			if node.children == nil {
				node.children = make(map[byte]*domainResourceNode)
			}
			child := node.children[normalized[pos]]
			if child == nil {
				child = &domainResourceNode{}
				node.children[normalized[pos]] = child
			}
			node = child
		}
		if node.entry == nil {
			node.entry = &domainResourceEntry{domain: domain, resource: resource, order: order}
		}
		order++
	}
	return index
}

func (i *domainResourceIndex) Match(host string) (string, client.DomainResource, bool) {
	if i == nil || i.root == nil {
		return "", client.DomainResource{}, false
	}
	node := i.root
	var best *domainResourceEntry
	for pos := len(host) - 1; pos >= 0; pos-- {
		node = node.children[host[pos]]
		if node == nil {
			break
		}
		if node.entry != nil && (best == nil || node.entry.order < best.order) {
			best = node.entry
		}
	}
	if best == nil {
		return "", client.DomainResource{}, false
	}
	return best.domain, best.resource, true
}
