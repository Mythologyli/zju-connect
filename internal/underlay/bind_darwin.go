//go:build darwin

package underlay

import (
	"context"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func bindInterface(dialer *net.Dialer, interfaceName string) error {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return err
	}
	dialer.ControlContext = func(_ context.Context, network, _ string, conn syscall.RawConn) error {
		var bindErr error
		err := conn.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, iface.Index)
			} else {
				bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
			}
		})
		if err != nil {
			return err
		}
		return bindErr
	}
	return nil
}
