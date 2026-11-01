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
	// derivedHTTPPort is the only port a granted resource is probed on. A grant
	// for 22 or 443 is not an HTTP service, and probing it with plain HTTP both
	// fails and consumes a candidate slot that a real port-80 resource needs.
	derivedHTTPPort = 80
)

// NamedKeepAliveTargets validates the comma-separated value of -keep-alive-url.
// A named target is what a human chose, so it is probed with a generous timeout.
func NamedKeepAliveTargets(value string) ([]KeepAliveTarget, []string) {
	var targets []KeepAliveTarget
	var warnings []string
	seen := make(map[string]bool)

	for _, raw := range strings.Split(value, ",") {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}

		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			warnings = append(warnings, fmt.Sprintf(
				"-keep-alive-url %q is not a http:// or https:// URL and is ignored", raw))
			continue
		}
		if parsed.Scheme == "https" {
			warnings = append(warnings, fmt.Sprintf(
				"-keep-alive-url %s: an https target is reached with CONNECT, which is not application "+
					"traffic and does not hold the session open; use a plain http:// address inside the VPN",
				target))
		}
		if seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, KeepAliveTarget{URL: target, Named: true})
	}

	return targets, warnings
}

// DeriveKeepAliveTargets turns the granted resources into candidate HTTP URLs.
// It never invents an address, and only a grant that covers port 80 is a
// candidate: other ports and https:// are the job of -keep-alive-url.
func DeriveKeepAliveTargets(ipResources []client.IPResource) ([]KeepAliveTarget, []string) {
	var targets []KeepAliveTarget
	var notes []string
	seen := make(map[string]bool)

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
		notes = append(notes, "no HTTP application target could be derived from the granted resources")
	}

	return targets, notes
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

// resourceHTTPPort returns the port a resource allows for a plain HTTP probe.
// Only port 80 qualifies: a single port such as 22 or 443 is not an HTTP
// service, and probing it would waste a candidate slot.
func resourceHTTPPort(resource client.IPResource) (int, bool) {
	if resource.PortMin <= derivedHTTPPort && resource.PortMax >= derivedHTTPPort {
		return derivedHTTPPort, true
	}
	return 0, false
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
