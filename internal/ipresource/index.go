package ipresource

import (
	"encoding/binary"
	"net"
	"sort"

	"github.com/mythologyli/zju-connect/client"
)

type indexedResource struct {
	resource client.IPResource
	start    uint32
	end      uint32
	order    int
}

type node struct {
	resource indexedResource
	maxEnd   uint32
	left     *node
	right    *node
}

type Index struct {
	root *node
}

func New(resources []client.IPResource) *Index {
	indexed := make([]indexedResource, 0, len(resources))
	for order, resource := range resources {
		start, startOK := IPv4Uint32(resource.IPMin)
		end, endOK := IPv4Uint32(resource.IPMax)
		if !startOK || !endOK || start > end {
			continue
		}
		indexed = append(indexed, indexedResource{resource: resource, start: start, end: end, order: order})
	}
	sort.SliceStable(indexed, func(i, j int) bool { return indexed[i].start < indexed[j].start })
	return &Index{root: build(indexed)}
}

func build(resources []indexedResource) *node {
	if len(resources) == 0 {
		return nil
	}
	middle := len(resources) / 2
	n := &node{resource: resources[middle]}
	n.left = build(resources[:middle])
	n.right = build(resources[middle+1:])
	n.maxEnd = n.resource.end
	if n.left != nil && n.left.maxEnd > n.maxEnd {
		n.maxEnd = n.left.maxEnd
	}
	if n.right != nil && n.right.maxEnd > n.maxEnd {
		n.maxEnd = n.right.maxEnd
	}
	return n
}

func (i *Index) Match(destination net.IP, protocol string, port int) (client.IPResource, bool) {
	return i.match(destination, protocol, port, false)
}

func (i *Index) MatchLast(destination net.IP, protocol string, port int) (client.IPResource, bool) {
	return i.match(destination, protocol, port, true)
}

func (i *Index) match(destination net.IP, protocol string, port int, preferLast bool) (client.IPResource, bool) {
	ip, ok := IPv4Uint32(destination)
	if !ok || i == nil || i.root == nil {
		return client.IPResource{}, false
	}
	var best *indexedResource
	i.root.match(ip, protocol, port, preferLast, &best)
	if best == nil {
		return client.IPResource{}, false
	}
	return best.resource, true
}

func (n *node) match(ip uint32, protocol string, port int, preferLast bool, best **indexedResource) {
	if n.maxEnd < ip {
		return
	}
	if n.left != nil && n.left.maxEnd >= ip {
		n.left.match(ip, protocol, port, preferLast, best)
	}
	resource := &n.resource
	if resource.start <= ip && ip <= resource.end &&
		(resource.resource.Protocol == protocol || resource.resource.Protocol == "all") &&
		(protocol == "icmp" || resource.resource.PortMin <= port && port <= resource.resource.PortMax) &&
		(*best == nil || (!preferLast && resource.order < (*best).order) || (preferLast && resource.order > (*best).order)) {
		*best = resource
	}
	if resource.start <= ip && n.right != nil && n.right.maxEnd >= ip {
		n.right.match(ip, protocol, port, preferLast, best)
	}
}

func IPv4Uint32(ip net.IP) (uint32, bool) {
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(ip), true
}
