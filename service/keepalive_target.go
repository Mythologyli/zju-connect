package service

import (
	"fmt"
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

// DeriveKeepAliveTargets turns the granted resources into candidate HTTP URLs.
// It never invents an address: every candidate is a resource the gateway already
// granted this account, so the one that answers is an application the user has.
func DeriveKeepAliveTargets(ipResources []client.IPResource) ([]KeepAliveTarget, []string) {
	var targets []KeepAliveTarget
	var notes []string
	seen := make(map[string]bool)

	for _, resource := range ipResources {
		if len(targets) >= maxDerivedCandidates {
			break
		}
		if resource.Protocol != "tcp" && resource.Protocol != "all" {
			continue
		}
		if resource.IPMin == nil || strings.Contains(resource.IPMin.String(), ":") {
			// IPv6 destinations are dialed directly, so they prove nothing.
			continue
		}
		if resource.IPMax != nil && !resource.IPMin.Equal(resource.IPMax) {
			notes = append(notes, fmt.Sprintf(
				"resource %s-%s covers a range, probing %s only",
				resource.IPMin, resource.IPMax, resource.IPMin))
		}

		var port int
		switch {
		case resource.PortMin <= derivedHTTPPort && resource.PortMax >= derivedHTTPPort:
			port = derivedHTTPPort
		case resource.PortMin == resource.PortMax:
			port = resource.PortMin
		default:
			continue
		}

		value := fmt.Sprintf("http://%s/", resource.IPMin)
		if port != derivedHTTPPort {
			value = fmt.Sprintf("http://%s:%d/", resource.IPMin, port)
		}
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
