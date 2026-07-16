//go:build linux

package underlay

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindInterface(dialer *net.Dialer, interfaceName string) error {
	dialer.ControlContext = func(_ context.Context, _, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			bindErr = unix.BindToDevice(int(fd), interfaceName)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}
