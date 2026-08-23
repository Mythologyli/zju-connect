//go:build !linux && !darwin && !windows

package platformdialer

import "net"

func bindInterface(_ *net.Dialer, _ string) error {
	return nil
}
