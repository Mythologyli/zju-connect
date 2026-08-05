package ipresource

import (
	"bytes"
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
	v6   []ipv6Resource
}

type ipv6Resource struct {
	resource client.IPResource
	start    [16]byte
	end      [16]byte
	order    int
}

func New(resources []client.IPResource) *Index {
	indexed := make([]indexedResource, 0, len(resources))
	v6 := make([]ipv6Resource, 0)
	for order, resource := range resources {
		start, startOK := IPv4Uint32(resource.IPMin)
		end, endOK := IPv4Uint32(resource.IPMax)
		if startOK && endOK && start <= end {
			indexed = append(indexed, indexedResource{resource: resource, start: start, end: end, order: order})
			continue
		}
		start16, startOK := ipv6Bytes(resource.IPMin)
		end16, endOK := ipv6Bytes(resource.IPMax)
		if startOK && endOK && bytes.Compare(start16[:], end16[:]) <= 0 {
			v6 = append(v6, ipv6Resource{resource: resource, start: start16, end: end16, order: order})
		}
	}
	sort.SliceStable(indexed, func(i, j int) bool { return indexed[i].start < indexed[j].start })
	return &Index{root: build(indexed), v6: v6}
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
	if ok && i != nil && i.root != nil {
		var best *indexedResource
		i.root.match(ip, protocol, port, preferLast, &best)
		if best != nil {
			return best.resource, true
		}
	}
	if i == nil {
		return client.IPResource{}, false
	}
	ip6, ok := ipv6Bytes(destination)
	if !ok {
		return client.IPResource{}, false
	}
	best := -1
	for n := range i.v6 {
		resource := &i.v6[n]
		if bytes.Compare(resource.start[:], ip6[:]) <= 0 && bytes.Compare(ip6[:], resource.end[:]) <= 0 &&
			(resource.resource.Protocol == protocol || resource.resource.Protocol == "all") &&
			(protocol == "icmp" || resource.resource.PortMin <= port && port <= resource.resource.PortMax) &&
			(best == -1 || (!preferLast && resource.order < i.v6[best].order) || (preferLast && resource.order > i.v6[best].order)) {
			best = n
		}
	}
	if best == -1 {
		return client.IPResource{}, false
	}
	return i.v6[best].resource, true
}

func ipv6Bytes(ip net.IP) ([16]byte, bool) {
	var value [16]byte
	if ip == nil || ip.To4() != nil {
		return value, false
	}
	ip = ip.To16()
	if ip == nil {
		return value, false
	}
	copy(value[:], ip)
	return value, true
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
