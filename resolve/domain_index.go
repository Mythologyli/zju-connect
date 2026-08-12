package resolve

import (
	"strings"

	"github.com/mythologyli/zju-connect/client"
)

type domainResourceEntry struct {
	domain    string
	resources []client.DomainResource
}

type domainResourceNode struct {
	children map[byte]*domainResourceNode
	entry    *domainResourceEntry
}

type domainResourceIndex struct {
	root *domainResourceNode
}

func newDomainResourceIndex(resources client.DomainResources) *domainResourceIndex {
	index := &domainResourceIndex{root: &domainResourceNode{}}
	for domain, domainResources := range resources {
		normalized := normalizeHostname(domain)
		if strings.HasPrefix(normalized, "*.") {
			normalized = normalized[1:]
		}
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
			node.entry = &domainResourceEntry{domain: domain}
		}
		node.entry.resources = append(node.entry.resources, domainResources...)
	}
	return index
}

func (i *domainResourceIndex) Match(host string) (string, []client.DomainResource, bool) {
	if i == nil || i.root == nil {
		return "", nil, false
	}
	node := i.root
	var matches []*domainResourceEntry
	for pos := len(host) - 1; pos >= 0; pos-- {
		node = node.children[host[pos]]
		if node == nil {
			break
		}
		boundary := pos == 0 || host[pos] == '.' || host[pos-1] == '.'
		if node.entry != nil && boundary {
			matches = append(matches, node.entry)
		}
	}
	if len(matches) == 0 {
		return "", nil, false
	}
	mostSpecific := matches[len(matches)-1]
	resources := make([]client.DomainResource, 0)
	for pos := len(matches) - 1; pos >= 0; pos-- {
		resources = append(resources, matches[pos].resources...)
	}
	return mostSpecific.domain, resources, true
}
