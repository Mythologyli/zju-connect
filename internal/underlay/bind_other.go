//go:build !linux && !darwin && !windows

package underlay

import "net"

func bindInterface(_ *net.Dialer, _ string) error {
	return nil
}
