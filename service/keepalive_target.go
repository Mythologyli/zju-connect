package service

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/mythologyli/zju-connect/client"
)

const (
	// maxDerivedCandidates bounds one discovery round. A derived candidate is a
	// guess, so it is probed on a short leash and only a handful of them.
	maxDerivedCandidates = 4
	// derivedHTTPPort is the port a granted resource has to cover to be probed
	// as a plain HTTP application address.
	derivedHTTPPort = 80
)

// NamedKeepAliveTargets validates the values of -keep-alive-url. A named target
// is what a human chose, so it is probed with a generous timeout and a retry
// budget instead of a single short-leash attempt.
func NamedKeepAliveTargets(urls []string) ([]KeepAliveTarget, []string) {
	var targets []KeepAliveTarget
	var warnings []string
	seen := make(map[string]bool)

	for _, raw := range urls {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}

		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			warnings = append(warnings, fmt.Sprintf(
				"-keep-alive-url %q is not a http:// or https:// URL and is ignored", raw))
			continue
		}
		if parsed.Scheme == "https" {
			warnings = append(warnings, fmt.Sprintf(
				"-keep-alive-url %s: an https target is reached with CONNECT, which is not application "+
					"traffic and does not hold the session open; use a plain http:// address inside the VPN",
				value))
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		targets = append(targets, KeepAliveTarget{URL: value, Named: true})
	}

	return targets, warnings
}

// DeriveKeepAliveTargets turns the destinations the tunnel carries into
// candidate HTTP URLs. The tunnel's own route table comes first: a route is an
// address the datapath carries right now, while a granted resource only says the
// account may use that address. The granted resources are the fallback, so a
// tunnel that installed no route (no -add-route, or another mode than TUN)
// derives exactly what it derived before. It never invents an address: every
// candidate comes from one of the two, and one that answers is an application
// the user has.
func DeriveKeepAliveTargets(
	routes []netip.Prefix,
	ipResources []client.IPResource,
) ([]KeepAliveTarget, []string) {
	var targets []KeepAliveTarget
	var notes []string
	seen := make(map[string]bool)

	routed := hostRouteAddresses(routes)
	routedTargets := 0
	for _, address := range routed {
		if len(targets) >= maxDerivedCandidates {
			break
		}

		resource, ok := resourceCarryingAddress(ipResources, address)
		if !ok {
			notes = append(notes, fmt.Sprintf(
				"route %s is not among the granted resources, the tunnel refuses it", address))
			continue
		}
		port, allowed := resourceHTTPPort(resource)
		if !allowed {
			notes = append(notes, fmt.Sprintf(
				"route %s is granted without a plain HTTP port, not probing it", address))
			continue
		}

		value := httpTargetURL(address, port)
		if seen[value] {
			continue
		}
		seen[value] = true
		targets = append(targets, KeepAliveTarget{URL: value})
		routedTargets++
	}

	switch {
	case routedTargets > 0:
		notes = append(notes, fmt.Sprintf(
			"probing %d address(es) the tunnel routes itself", routedTargets))
	case len(routes) > 0:
		notes = append(notes, "the tunnel's routes yield no plain HTTP target, probing the granted resources")
	}

	for _, resource := range ipResources {
		if len(targets) >= maxDerivedCandidates {
			break
		}
		if !resourceForwardsProtocol(resource) {
			continue
		}
		address, ok := resourceAddress(resource)
		if !ok {
			// IPv6 destinations are dialed directly, so they prove nothing.
			continue
		}
		if maximum, ok := resourceMaximumAddress(resource); ok && maximum != address {
			notes = append(notes, fmt.Sprintf(
				"resource %s-%s covers a range, probing %s only", address, maximum, address))
		}

		port, ok := resourceHTTPPort(resource)
		if !ok {
			continue
		}

		value := httpTargetURL(address, port)
		if seen[value] {
			continue
		}
		seen[value] = true
		targets = append(targets, KeepAliveTarget{URL: value})
	}

	if len(targets) == 0 {
		notes = append(notes, "no HTTP application target could be derived from the tunnel's routes "+
			"or the granted resources")
	}

	return targets, notes
}

// hostRouteAddresses returns the single-address routes of a route table, in
// order. A wider prefix says the tunnel carries a range, not which address in it
// answers a probe.
func hostRouteAddresses(routes []netip.Prefix) []netip.Addr {
	addresses := make([]netip.Addr, 0, len(routes))
	for _, route := range routes {
		if !route.IsValid() {
			continue
		}
		address := route.Addr()
		if address.Is6() || route.Bits() != address.BitLen() {
			continue
		}
		addresses = append(addresses, address)
	}
	return addresses
}

// resourceForwardsProtocol reports whether the tunnel forwards a resource's
// protocol at all.
func resourceForwardsProtocol(resource client.IPResource) bool {
	return resource.Protocol == "tcp" || resource.Protocol == "all"
}

// resourceAddress returns the address a resource is probed at.
func resourceAddress(resource client.IPResource) (netip.Addr, bool) {
	address, ok := netip.AddrFromSlice(resource.IPMin)
	if !ok {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if address.Is6() || !address.Is4() {
		return netip.Addr{}, false
	}
	return address, true
}

// resourceMaximumAddress returns the last address of a resource, which is the
// first one again for a single address.
func resourceMaximumAddress(resource client.IPResource) (netip.Addr, bool) {
	maximum := resource.IPMax
	if maximum == nil {
		maximum = resource.IPMin
	}
	address, ok := netip.AddrFromSlice(maximum)
	if !ok {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

// resourceHTTPPort returns the port a resource allows for a plain HTTP probe: 80
// when it covers 80, otherwise the single port it grants.
func resourceHTTPPort(resource client.IPResource) (int, bool) {
	switch {
	case resource.PortMin <= derivedHTTPPort && resource.PortMax >= derivedHTTPPort:
		return derivedHTTPPort, true
	case resource.PortMin == resource.PortMax && resource.PortMin > 0:
		return resource.PortMin, true
	}
	return 0, false
}

// resourceCarryingAddress returns the first resource that covers an address, so a
// route can be probed at the port that address is actually granted for.
func resourceCarryingAddress(
	resources []client.IPResource,
	address netip.Addr,
) (client.IPResource, bool) {
	for _, resource := range resources {
		if !resourceForwardsProtocol(resource) {
			continue
		}
		minimum, ok := resourceAddress(resource)
		if !ok {
			continue
		}
		maximum, ok := resourceMaximumAddress(resource)
		if !ok {
			continue
		}
		if address.Compare(minimum) < 0 || address.Compare(maximum) > 0 {
			continue
		}
		return resource, true
	}
	return client.IPResource{}, false
}

// httpTargetURL builds the probe URL for an address and a port.
func httpTargetURL(address netip.Addr, port int) string {
	if port == derivedHTTPPort {
		return fmt.Sprintf("http://%s/", address)
	}
	return fmt.Sprintf("http://%s:%d/", address, port)
}

// keepAliveOrder puts the last target that answered first, then the named
// targets in the order the user gave them, then the derived candidates.
func keepAliveOrder(targets []KeepAliveTarget, active string) []KeepAliveTarget {
	ordered := make([]KeepAliveTarget, 0, len(targets))
	if active != "" {
		for _, target := range targets {
			if target.URL == active {
				ordered = append(ordered, target)
			}
		}
	}
	for _, named := range []bool{true, false} {
		for _, target := range targets {
			if target.Named != named || target.URL == active {
				continue
			}
			ordered = append(ordered, target)
		}
	}
	return ordered
}
