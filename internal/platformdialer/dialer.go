package platformdialer

import (
	"context"
	"fmt"
	"net"
)

// Dialer creates network connections bound to a specific platform interface.
// It contains no interface selection or retry policy.
type Dialer struct {
	InterfaceName string
	Resolver      *net.Resolver
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	netDialer := &net.Dialer{}
	if d != nil {
		netDialer.Resolver = d.Resolver
		if d.InterfaceName != "" {
			if err := bindInterface(netDialer, d.InterfaceName); err != nil {
				return nil, fmt.Errorf("bind interface %q: %w", d.InterfaceName, err)
			}
		}
	}
	return netDialer.DialContext(ctx, network, address)
}
